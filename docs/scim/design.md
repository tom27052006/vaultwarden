# SCIM v2 for Vaultwarden — Design & Security Notes

This document records the architecture and the security decisions behind Vaultwarden's
SCIM 2.0 provisioning support. It is meant to be read together with
[`README.md`](README.md), which is the operator-facing documentation.

## 0. Provenance / clean-room statement

This implementation was written from:

* [RFC 7643](https://www.rfc-editor.org/rfc/rfc7643) — SCIM Core Schema
* [RFC 7644](https://www.rfc-editor.org/rfc/rfc7644) — SCIM Protocol
* Microsoft's public documentation of the SCIM dialect Entra ID emits
* Vaultwarden's own existing organization/membership/group code
  (`src/api/core/organizations.rs`, `src/api/core/public.rs`, `src/db/models/*`)

No code, data model or wire format was taken from Bitwarden's `bitwarden_license`
directories, from Bitwarden's C# SCIM server, from Bitwarden's proprietary SCIM web-vault
UI, or from the previously closed Vaultwarden PR #7443. The resource mapping below is
derived from Vaultwarden's own data model, not from Bitwarden's.

## 1. Goals and non-goals

### Goals

* A standards-based SCIM 2.0 `/Users` and `/Groups` provider.
* Microsoft Entra ID as the first real-world interoperability target.
* Strict per-organization tenant isolation.
* Reuse of Vaultwarden's existing invitation / revoke / restore / group business logic
  rather than a parallel implementation.
* Management entirely inside Vaultwarden's own `/admin` panel.

### Explicit non-goals for V1

Staged members, `/Bulk`, sorting, ETags, password operations, the `EnterpriseUser`
extension, SSO, claimed domains, automatic organization confirmation, role provisioning,
collection-permission provisioning and custom-role provisioning are all out of scope.
`ServiceProviderConfig` advertises them as unsupported rather than lying about them.

## 2. Where SCIM lives

```
src/api/scim/
    mod.rs           route table, tenant context, shared helpers
    auth.rs          bearer token model, request guard, rate limiting
    error.rs         SCIM error type + Rocket responder (application/scim+json)
    json.rs          SCIM-aware request/response body handling and size limits
    filter.rs        RFC 7644 3.4.2.2 filter tokenizer / parser / evaluator
    patch.rs         RFC 7644 3.5.2 PatchOp parsing and change-set construction
    resource.rs      SCIM <-> Vaultwarden resource mapping
    settings.rs      the CONFIG values this module reads, behind one indirection
    discovery.rs     ServiceProviderConfig / ResourceTypes / Schemas
    users.rs         /Users endpoints
    groups.rs        /Groups endpoints
    e2e.rs           end-to-end tests through a Rocket local client (test builds only)
```

`settings.rs` exists for testability. In a release build its functions are plain reads of `CONFIG`
and the shared rate limiter, and nothing test-specific is compiled in. In a test build they are
backed by atomics the suite can set, which is what lets the tests drive the real request path with
SCIM disabled, groups disabled, or the rate limiter exhausted. The alternatives were not available:
`std::env::set_var` is `unsafe` and this crate sets `unsafe_code = "forbid"`, and
`Config::update_config` persists a `config.json` into the operator's data folder.

Mounted at `<basepath>/scim/v2`, so the public base URL of an organization is:

```
https://vault.example.com/scim/v2/<organization_uuid>
```

The organization UUID is part of every path. There is no "current organization" inferred
from the token alone; the token and the path organization must agree (section 5).

Shared business logic that SCIM and the Directory Connector both need was extracted into
`src/api/core/organizations.rs` (`provision_org_member`, `try_revoke_member`,
`try_restore_member`) and is called from both `src/api/core/public.rs` and the SCIM code.
The Directory Connector's observable behaviour is unchanged: where it previously logged a
warning and carried on, it now maps the shared function's `Err` to the same warning.

## 3. Configuration

| Setting | Default | Meaning |
| --- | --- | --- |
| `SCIM_ENABLED` | `false` | Master switch. When false the SCIM routes return `404` and the `/admin` token controls are unavailable. |
| `SCIM_RATELIMIT_SECONDS` | `60` | Average seconds between SCIM requests from one IP before limiting. |
| `SCIM_RATELIMIT_MAX_BURST` | `100` | Burst allowance for the above. |

SCIM is disabled by default because it is a network surface that grants
organization-membership mutation rights to whoever holds a bearer token.

The routes are always mounted, and the request guard checks `SCIM_ENABLED` at request time.
This is deliberate: Vaultwarden's config is editable at runtime from `/admin`, and a
mount-time decision would require a restart to take effect. When disabled the guard returns
`404` before any token parsing or database access happens.

Enabling SCIM while `ORG_EVENTS_ENABLED` is false produces a config-validation warning:
SCIM performs unattended membership changes and an operator almost always wants those in
the organization event log. It is only a warning — SCIM does not silently turn on event
logging, and it does not turn on `ORG_GROUPS_ENABLED` either.

## 4. Database

One new table, `organization_scim_key`:

| column | SQLite | MySQL / PostgreSQL | notes |
| --- | --- | --- | --- |
| `uuid` | `TEXT` | `CHAR(36)` | primary key, also the public key id embedded in the token |
| `org_uuid` | `TEXT` | `VARCHAR(40)` | `UNIQUE`, FK to `organizations(uuid)` |
| `key_hash` | `TEXT` | `VARCHAR(255)` | hex SHA-256 of the token secret; never the secret |
| `created_at` | `DATETIME` | `DATETIME`/`TIMESTAMP` | |
| `updated_at` | `DATETIME` | `DATETIME`/`TIMESTAMP` | bumped on rotation |
| `last_used_at` | nullable | nullable | best-effort, refreshed at most every five minutes |

`org_uuid` is `VARCHAR(40)` rather than `CHAR(36)` on MySQL and PostgreSQL specifically so it
matches the type of `organizations.uuid`: InnoDB refuses a foreign key between a `CHAR` and a
`VARCHAR` column, so the "obvious" `CHAR(36)` would make the migration fail on MySQL.

`UNIQUE(org_uuid)` means an organization has at most one active SCIM token. Rotation
overwrites the row, so the previous secret stops working immediately, and deletion removes
the row, so that secret stops working immediately. No extra revocation bookkeeping is
needed and there is no window in which two secrets are valid.

Migrations exist for SQLite, MySQL/MariaDB and PostgreSQL, with `down.sql` for each.
MySQL needs a table-level `FOREIGN KEY` clause (an inline `REFERENCES` on a column is
parsed and then ignored by InnoDB) and a bounded key length on the unique column, so the
MySQL variant uses `CHAR(36)`/`VARCHAR` types rather than `TEXT`. The three schemas are
semantically equivalent.

`Organization::delete()` deletes the organization's SCIM key alongside its other children;
SQLite does not run with `PRAGMA foreign_keys=ON` in Vaultwarden, so cleanup is explicit
rather than relying on the constraint.

**No SCIM-specific user or group mapping table was added.** SCIM identifiers are existing
Vaultwarden identifiers:

* SCIM `User.id` maps to `users_organizations.uuid` (`MembershipId`)
* SCIM `Group.id` maps to `groups.uuid` (`GroupId`)
* SCIM `externalId` maps to `users_organizations.external_id` / `groups.external_id`

This is what makes tenant isolation cheap: both underlying tables already carry the
organization id, so every lookup can bind resource id and organization id together.

## 5. Authentication

### Token format

```
scim_v1.<key-uuid>.<secret>
```

* `scim_v1` — a version tag, so the format can change later without ambiguity.
* `<key-uuid>` — the `organization_scim_key.uuid`. A **non-secret lookup handle**; it makes
  verification an indexed single-row fetch instead of a scan over every organization's key.
* `<secret>` — 32 bytes from `crypto::get_random_bytes`, base64url-encoded without padding
  (256 bits of entropy).

Security does not depend on any property of the untrusted parts. The key id only selects a
candidate row; authorization comes entirely from the constant-time secret comparison and
from the fact that the row is fetched with the path organization id already bound.

### Verification

1. Rate-limit the request by client IP (fail closed on limiter error).
2. Reject unless `SCIM_ENABLED` (returns `404`).
3. Read `Authorization: Bearer <token>`. Missing or non-Bearer gives `401`.
4. Split into exactly three `.`-separated parts; part 0 must equal `scim_v1`.
5. Fetch the row `WHERE uuid = <part 1> AND org_uuid = <organization from the URL>`.
6. Compare `sha256_hex(part 2)` against the stored hash with `crypto::ct_eq`.

Every failure in steps 3-6 returns the *same* SCIM `401` body with no detail that
distinguishes "no such organization" from "no such key" from "wrong secret". When no row is
found, the SHA-256 and the constant-time comparison are still performed against a fixed
dummy hash so the secret-comparison path costs the same either way.

The remaining measurable difference is the database lookup itself (indexed hit vs. miss).
That is not a practical oracle against a 256-bit secret and it is additionally covered by
the IP rate limiter; it is recorded here rather than papered over.

Handlers additionally re-assert `token.org_id == <organization from the URL>` as
defence-in-depth, so a mistake in the guard's path-parameter extraction cannot become a
cross-tenant bug.

### Why SHA-256 and not Argon2/PBKDF2

The secret is 256 bits of CSPRNG output, not a human-chosen password, so there is no
dictionary or brute-force attack for a slow KDF to defend against. A per-request KDF would
add tens of milliseconds to every one of the many requests an Entra sync cycle makes.
Hashing at rest is still done so that a database leak does not yield usable tokens.

### `/admin` token management

Token create/rotate/delete live behind the same `AdminToken` guard as every other sensitive
`/admin` operation, i.e. the admin cookie/JWT issued after `ADMIN_TOKEN` login. The
plaintext token is returned exactly once, in the JSON response to the create/rotate call,
and is never persisted, never logged and never re-derivable.

## 6. Resource mapping

### User (`urn:ietf:params:scim:schemas:core:2.0:User`)

| SCIM | Vaultwarden | Writable |
| --- | --- | --- |
| `id` | `Membership.uuid` | no |
| `externalId` | `Membership.external_id` | yes |
| `userName` | `User.email` (lower-cased) | **no — see section 7** |
| `emails[0].value` | `User.email` | no |
| `displayName` | `User.name` | **no — see section 7** |
| `active` | `Membership.status > Revoked` | yes |
| `meta.resourceType` / `meta.location` | derived | n/a |

`meta.created` / `meta.lastModified` are **not** emitted for users. `users_organizations`
has no timestamp columns, and emitting the *account's* timestamps would be actively
misleading. Both sub-attributes are optional in RFC 7643 section 3.1, ETags and sorting are
out of scope, and Entra does not require them. Groups do have
`creation_date`/`revision_date`, so group `meta` is complete.

### Group (`urn:ietf:params:scim:schemas:core:2.0:Group`)

| SCIM | Vaultwarden | Writable |
| --- | --- | --- |
| `id` | `Group.uuid` | no |
| `externalId` | `Group.external_id` | yes |
| `displayName` | `Group.name` | yes |
| `members[].value` | `GroupUser.users_organizations_uuid` | yes |
| `meta.created` / `meta.lastModified` | `creation_date` / `revision_date` | n/a |

`members[].display` is omitted. It is optional in RFC 7643, Entra does not consume it, and
producing it would mean an extra user lookup per member on every group read.

Group endpoints require `ORG_GROUPS_ENABLED`. When groups are disabled the `/Groups`
endpoints return `501` and the `Group` resource type and schema are omitted from
`/ResourceTypes` and `/Schemas`, so discovery stays truthful.

## 7. User lifecycle semantics

### Provisioning (`POST /Users`)

1. Validate `userName` as an email address (`util::is_valid_email`) and normalize to
   lower case.
2. Look up an existing Vaultwarden account by normalized email.
3. If none exists, create the same shell/invited account
   (`User::new` plus an `Invitation` row when mail is disabled) that the Directory
   Connector creates.
4. Create a `Membership` with `atype = MembershipType::User` and `access_all = false`.
5. Set `external_id`.
6. Status follows Vaultwarden's existing invitation rules: `Invited` when mail is enabled or
   the account has no password yet, otherwise `Accepted`.
7. Send the invitation mail through `mail::send_invite` when mail is enabled, rolling back
   the membership (and the account, if this call created it) if sending fails.

This is `provision_org_member`, the function the Directory Connector now also calls.

Step 3 creates a **global** Vaultwarden account, so before reaching it the SCIM layer applies the
same two server policies the interactive invite endpoint applies at exactly the same point:
`INVITATIONS_ALLOWED` and `SIGNUPS_DOMAINS_WHITELIST`. Without that, an identity provider could
create accounts on domains the operator excluded, or while invitations were switched off
entirely — a quiet bypass of a stated server policy. The checks live in `users.rs` rather than in
the shared `provision_org_member` because the Directory Connector has never performed them and its
behaviour must not change. They apply only when the address has no account yet: adding a
membership for someone who already has an account is not a signup.

SCIM **never** confirms a membership. Confirmation requires the organization key to be
wrapped for the member's public key, which is a client-side cryptographic operation an
IdP cannot perform. Provisioned members therefore appear as invited/accepted and an
organization admin completes confirmation, exactly as for any other invite.

### Privileged memberships

SCIM refuses **every mutating operation** (`PUT`, `PATCH`, `DELETE`) on a membership whose
`atype` is not `User` — that is, on Owners, Admins and Managers/Custom. The response is
`403` with `scimType: "mutability"` and a detail explaining that the member must be demoted
in the web vault first.

This single rule is what makes the privilege-escalation requirements hold, and it holds by
construction rather than by a checklist of special cases:

* SCIM cannot create an Owner or Admin — `POST` hard-codes `MembershipType::User` and there
  is no request field that maps to membership type at all.
* SCIM cannot demote or overwrite a privileged membership — it cannot write to one.
* SCIM cannot remove the last Owner — it cannot remove any Owner.
* A stale or compromised SCIM token cannot restore privileged access, because a revoked
  Owner/Admin membership is equally untouchable.

Privileged memberships remain **visible** on `GET` and list. Hiding them would make Entra
believe the user is absent and create a duplicate, which is worse.

### Deactivation and reactivation

* `active: false` calls `Membership::revoke()`. The row, its `external_id`, its
  `akey` (the organization key wrapped for that user) and every collection/group assignment
  are preserved. Effective access is removed immediately because every access path checks
  the membership status.
* `active: true` calls `Membership::restore()` followed by
  `OrgPolicy::check_user_allowed(..., "restore")`, the same check the normal restore
  endpoint and the Directory Connector run. If the policy check fails the membership is
  re-revoked and the request fails.

Restore returns the membership to its exact pre-revocation status (Vaultwarden encodes the
previous status as `status - 128`), so a member who was Confirmed before is Confirmed
again. This is deliberate and matches both the admin restore endpoint and the Directory
Connector; it is not an escalation because the state being restored is the state the
organization itself previously granted. It is bounded by the privileged-membership rule
above: only `MembershipType::User` memberships can be restored through SCIM at all.

A membership that a Vaultwarden administrator revoked by hand *can* be reactivated by
SCIM if it is an unprivileged membership. That is the documented meaning of handing an
IdP authority over a directory: the IdP is the source of truth for who is in scope. An
operator who does not want that should remove the member instead of revoking them, or
delete the SCIM token.

### `DELETE /Users/<id>`

Removes the **membership**, via the same safe path as the admin "remove member" action.
The Vaultwarden account, its personal vault and its memberships in other organizations are
untouched. Organization cryptographic state is untouched (Vaultwarden does not rotate
organization keys on member removal).

The membership row is genuinely removed rather than merely revoked because RFC 7644
section 3.6 requires a subsequent `GET` to return `404`. A "soft delete" that keeps
returning the resource makes IdPs retry forever. Operators who want the reversible
behaviour should configure their IdP to deprovision with `active: false`, which is Entra's
default.

### Why `userName` and `displayName` are not writable

`User.email` is Vaultwarden's global account identity: it is the login identifier, the
invitation target and the key that every other organization's membership resolves through.
Letting organization A's SCIM token rewrite it would mean:

* an account-takeover primitive — repoint an existing account at an attacker-controlled
  address and drive a password reset;
* silent cross-tenant mutation — organization B's member identity changes because
  organization A's IdP said so;
* collisions with an existing account's email, with no safe resolution.

So a `PUT`/`PATCH` that presents a `userName` which normalizes to something *different*
from the stored email is rejected with `400` and `scimType: "mutability"`. A `userName`
that matches is accepted as a no-op, which is what Entra sends on every update. The
documented remedy for a genuine rename is deprovision-and-reprovision.

`User.name` (`displayName`) is not an authorization attribute, but it is equally global: it is
shown in every organization the account belongs to. SCIM therefore does not write it on an
account that already exists. Unlike `userName`, an inbound change is **accepted and ignored**
rather than rejected — the response returns the stored value, which RFC 7644 section 3.5.1
explicitly permits ("the service provider MAY return the resource with modified values") —
because rejecting it would break provisioning outright for a purely cosmetic attribute.

There is one exception, and it is not really an exception to the rule above: when provisioning
*creates* a brand-new shell account, `displayName` (or `name.formatted`, or `givenName` plus
`familyName`) is used as that account's name. Nobody else has a claim on an account that did not
exist a moment ago, and the alternative is an organization full of members displayed by email
address. `provision_org_member` takes the name as a parameter and uses it only on the create path,
so the Directory Connector — which passes `None` — behaves exactly as before.

## 8. Groups

Group membership entries must resolve to a membership **in the same organization**. This is
not incidental: `GroupUser::save()` in the existing codebase does not validate that the
group and the membership share an organization, so SCIM validates it itself, before any
mutation, by resolving every `members[].value` through
`Membership::find_by_uuid_and_org(id, org_id)`. An unresolvable member id fails the whole
request with `400`/`invalidValue`; nothing is written.

### `PUT` and omitted `members`

A strict reading of RFC 7644 section 3.5.1 says `PUT` replaces the resource and omitted
modifiable attributes are cleared. Applied literally to `members`, a sparse IdP payload
silently empties a group — a mass-deprovisioning event triggered by a client bug.

Vaultwarden therefore distinguishes *absent* from *empty*:

* `members` key absent means membership unchanged
* `"members": []` means all members removed

The same rule applies to `active` and `externalId` on `PUT /Users`. This is a deliberate,
documented deviation, chosen for blast-radius reasons; an IdP that wants to clear a
collection can always say so explicitly. Entra does not `PUT` group members at all — it
uses `PATCH` — so this costs nothing in practice.

### Atomicity

Vaultwarden's database layer runs one `conn.run(...)` per query and its model methods are
`async`, so a transaction cannot span several model calls. The strategy is therefore
**validate everything, then apply**:

1. Parse the whole `PatchOp` document.
2. Resolve it into a typed change-set (`UserChanges` / `GroupChanges`).
3. Validate the complete change-set — resource exists and is in this organization, every
   member id resolves inside this organization, the membership is not privileged, no
   uniqueness violation, no unsupported path.
4. Only then write.

The change-sets use a `FieldChange` enum rather than `Option<Option<String>>`, because SCIM needs
three states an `Option` cannot express: the request did not mention the attribute (leave it
alone), the request set it, and the request asked for it to be removed. Collapsing the first two
is exactly the bug that turns a sparse payload into a silent deletion.

For the one genuinely destructive multi-statement operation — replacing a group's whole
member set — a real transaction is used: `GroupUser::replace_all_for_group` performs the
delete and the inserts inside a single `conn.transaction(...)` on all three backends, so a
failure mid-way cannot leave a group with a partially applied membership list.

## 9. Filtering

`filter.rs` is a hand-written tokenizer plus recursive-descent parser producing an AST,
which is then evaluated in Rust against candidate resources. **A filter never becomes a SQL
fragment.** The only values that reach the database are bound parameters extracted from
recognized fast-path shapes.

Supported: `eq ne co sw ew pr gt ge lt le`, `and`, `or`, `not`, parentheses, and
`attr[subfilter]` value paths. Attribute names are matched case-insensitively per RFC 7644
section 3.4.2.2 and unknown attributes are rejected with `400`/`invalidFilter` rather than
silently matching nothing.

Bounds, to keep evaluation cheap and to prevent recursive blow-up:

* filter string at most 2048 bytes
* AST depth at most 16
* AST nodes at most 128

Fast paths that become an indexed single-row database lookup instead of a scan:

* Users — `id eq`, `userName eq`, `externalId eq`
* Groups — `id eq`, `displayName eq`, `externalId eq`

These are the only shapes Entra actually emits. Anything else falls back to loading the
organization's members or groups and evaluating in memory, which is bounded by the size of
one organization and by the page-size cap. The parser deliberately supports more than the
fast paths so that adding new indexed shapes later is a change to the optimizer, not to the
grammar.

## 10. Pagination

SCIM is 1-based (RFC 7644 section 3.4.2.4).

* `startIndex` — default `1`; values below `1` are clamped to `1`.
* `count` — default `100`, hard maximum `500`. `count = 0` is legal and returns
  `Resources: []` with a correct `totalResults`, which is the standard way to ask for a
  count.
* Responses always carry `schemas`, `totalResults`, `startIndex`, `itemsPerPage` and
  `Resources`.

The hard cap exists so a client cannot ask for an unbounded response.

`attributes` and `excludedAttributes` are honoured for top-level attributes. This matters
in practice: Entra requests groups with `excludedAttributes=members`, and honouring it lets
Vaultwarden skip the member lookup entirely.

## 11. Errors and content types

All SCIM responses — success and failure — use `application/scim+json`. Requests are
accepted with `application/scim+json`, `application/json`, or no `Content-Type` at all;
some IdPs are careless about this and it costs nothing to be liberal on input.

The normal Vaultwarden `Error` responder emits the Bitwarden error envelope with
`Content-Type: application/json`, which SCIM clients cannot parse, so SCIM has its own
`ScimError` type with its own `Responder`. Every failure path in the SCIM module returns
`ScimError`; the module never leaks a Vaultwarden-internal error to the client. Internal
detail is written to the server log instead, and the client gets a generic message.

Error bodies follow `urn:ietf:params:scim:api:messages:2.0:Error` with `status`,
`scimType` where the RFC defines one, and a human-readable `detail`:

| Situation | HTTP | `scimType` |
| --- | --- | --- |
| malformed JSON / not an object | 400 | `invalidSyntax` |
| unparseable or unknown-attribute filter | 400 | `invalidFilter` |
| unsupported PATCH path | 400 | `invalidPath` |
| bad value for a known attribute | 400 | `invalidValue` |
| immutable attribute written | 400 | `mutability` |
| bad or absent credentials | 401 | — |
| privileged membership | 403 | `mutability` |
| unknown resource, or resource in another organization | 404 | — |
| duplicate user/group | 409 | `uniqueness` |
| body over the limit | 413 | — |
| rate limited | 429 | — |
| groups disabled server-side | 501 | — |

## 12. Uniqueness and races

Organization-scoped uniqueness is enforced for:

* **userName** — at most one membership per (organization, account). Backed by a
  pre-check plus the natural key: `Membership::find_by_email_and_org` resolves the account
  and then the membership, and duplicate creation returns `409`/`uniqueness`.
* **`externalId`** — `Membership.external_id` and `Group.external_id` are checked against
  the organization before assignment; a collision returns `409`/`uniqueness`.
* **Group `displayName`** — not required to be unique by RFC 7643 and not unique in
  Vaultwarden today, so it is not enforced on update. `POST /Groups` with an existing
  `displayName` is still rejected with `409` because Entra treats `displayName` as the
  group's natural key and would otherwise create duplicates on every sync.

**Known limitation, recorded rather than hidden:** these are pre-checks, not database
constraints. Two concurrent `POST /Users` for the same address can both pass the check and
create two memberships. Adding `UNIQUE(org_uuid, user_uuid)` and
`UNIQUE(org_uuid, external_id)` to `users_organizations` would be the real fix, but that
table is written by many existing code paths that do not expect a constraint violation, and
existing deployments may already contain rows that violate it — so retrofitting it belongs
in its own change, not in the SCIM PR. In practice IdPs including Entra drive a single
sync worker per tenant and serialize writes per resource, so the window is narrow. The
consequences are also mild: a duplicate membership is visible in the admin UI and grants no
access beyond what one membership would.

## 13. Tenant isolation

The rule the code follows without exception: **never fetch a resource by UUID alone and
then check its organization.** Every lookup binds resource id *and* organization id in the
same query:

* `Membership::find_by_uuid_and_org`
* `Group::find_by_uuid_and_org`
* `Membership::find_by_external_id_and_org`
* `Group::find_by_external_id_and_org`
* `organization_scim_key` fetched by `(uuid, org_uuid)`

A miss is a `404` that is indistinguishable from "does not exist anywhere", so ids cannot
be enumerated across tenants. Group member resolution goes through the same
organization-bound helper, which is what prevents an organization B membership from being
injected into an organization A group.

## 14. Event logging

SCIM actions are written to Vaultwarden's existing organization event log via `log_event`,
with a synthetic actor rather than a real user id:

```rust
const ACTING_SCIM_USER: &str = "vaultwarden-scim-000000-000000000000";
```

This mirrors the existing `ACTING_ADMIN_USER` pattern in `src/api/admin.rs`, so the event
log never claims a human performed an automated change. `device_type` is `14`
(`UnknownBrowser`), the value `/admin` already uses for non-interactive actions.

| Action | `EventType` |
| --- | --- |
| member provisioned | `OrganizationUserInvited` |
| member deactivated | `OrganizationUserRevoked` |
| member reactivated | `OrganizationUserRestored` |
| member deprovisioned (`DELETE`) | `OrganizationUserRemoved` |
| group created | `GroupCreated` |
| group updated | `GroupUpdated` |
| group deleted | `GroupDeleted` |
| group membership changed | `OrganizationUserUpdatedGroups` |
| SCIM token created / rotated / deleted | `OrganizationUpdated` |

Token lifecycle events reuse `OrganizationUpdated` rather than inventing new numeric event
types: Vaultwarden's `EventType` values are Bitwarden's, and a made-up value could collide
with a future upstream one and would render as "Unknown" in clients. The server log
additionally records which action it was. **No event, log line or error message ever
contains the token secret.**

## 15. Abuse protection

* Every SCIM request passes the dedicated IP rate limiter before any parsing or database
  access, so authentication attempts, listing and writes are all covered.
* SCIM request bodies are capped at **1 MiB**, independently of Rocket's 20 MB global JSON
  limit, and over-sized bodies return `413`.
* `members` arrays are capped at **5000** entries per request.
* `PatchOp.Operations` is capped at **1000** operations per request.
* Filter complexity is bounded (section 9) and page size is capped (section 10).

## 16. `useScim` and the official clients

`Organization::to_json` continues to report `"useScim": false`, and membership permissions
continue to report `"manageScim": false`.

The web vault's SCIM configuration page is part of Bitwarden's `bitwarden_license` code. It
is built for Bitwarden's own endpoint layout and its own key-management API, neither of
which Vaultwarden implements — Vaultwarden's endpoint is `/scim/v2/<org_id>` and its tokens
are issued from `/admin`. Setting `useScim: true` would light up a page in the official
client that cannot talk to this server and would hand operators a broken workflow.

The backend does not need the organization to pretend to be a Bitwarden Enterprise tenant.
SCIM is configured in Vaultwarden's `/admin` panel, which shows the endpoint URL, the
token controls and the setup instructions. This should be revisited only if a future
web-vault version ships a SCIM page that can be pointed at an arbitrary endpoint.

## 17. Testing strategy

The module is deliberately layered so that the security-critical logic is testable without
a running server:

* **Pure unit tests**, alongside the code they cover, exercise the filter tokenizer/parser/
  evaluator, the PATCH path parser and change-set builder, pagination arithmetic, token
  formatting/parsing and hash comparison, resource serialization, email normalization, media-type
  negotiation and the SCIM error envelope. These need neither a database nor `CONFIG`.
* **End-to-end tests** in `e2e.rs` drive the *real* request path — routing, the bearer-token
  request guard, the body guard, the handlers and the SCIM catchers — through a Rocket local
  client backed by a throwaway SQLite database built from an explicit URL under `target/`. They
  never touch the developer's configured database. These cover what only means something against
  real data and a real request: authentication and its failure modes, tenant isolation,
  privileged-membership refusal, revoke/restore semantics, uniqueness, group membership
  operations, and the protocol-level behaviour of every error path.

Vaultwarden has no `src/lib.rs`, so there is no library target for a `tests/` directory to link
against; tests live in `#[cfg(test)]` modules, which is the existing convention throughout the
codebase.

The suite runs on SQLite. The MySQL and PostgreSQL paths are covered by the fact that the SCIM code
contains no backend-specific branches beyond the `db_run!` arms in
`db/models/scim.rs`, which follow the same shape as every other model, and by CI building and
testing all three feature combinations.

## 18. Security audit

A dedicated pass over the finished implementation, checking each item against the code rather
than against intent. Everything below is covered by a test unless noted.

| Checked for | Result |
| --- | --- |
| IDOR / BOLA, tenant isolation | Every resource lookup binds resource id and organization id in one query. The only non-organization-bound calls are `User::find_by_mail` and `User::find_by_uuid`, both of which are funnelled straight through an organization-bound membership lookup, so neither can return anything from another tenant. |
| Privilege escalation | `POST` hard-codes `MembershipType::User`; the inbound structs have no role field at all; every mutating path calls `ensure_manageable` first. |
| Account takeover by email mutation | `ensure_user_name_unchanged` refuses any real change to `userName`. |
| Unsafe member restoration | Restores go through `try_restore_member`, which enforces the same organization policies as the interactive endpoint and re-revokes on refusal; privileged memberships are unreachable. |
| Last-owner removal | Owners cannot be touched at all through SCIM. |
| Stale-token acceptance | Rotation deletes the row, so both the previous key id and the previous secret stop resolving. |
| Authentication timing | Constant-time secret comparison, and the same hash plus comparison on a miss. The residual signal is the indexed row lookup itself, recorded in section 5. |
| Mass assignment | Typed request structs with no privileged fields; unknown attributes are dropped. |
| Incomplete `PATCH` rollback | Plan-then-apply, plus a real transaction for group member replacement. |
| `externalId` collisions, duplicate memberships | Organization-scoped pre-checks. The pre-check-versus-constraint limitation is recorded in section 12. |
| Cross-tenant group membership injection | Every `members[].value` is resolved organization-bound before any write. |
| Unbounded resource consumption | Body, page size, filter length/depth/nodes, member array and operation count are all capped; group listing only loads membership when a filter actually references it. |
| Secret logging, plaintext storage | Only a SHA-256 hash is stored; no log line, event or error contains the secret. |
| Behaviour across database backends | No backend-specific branches beyond the standard `db_run!` arms. |

Two findings came out of this pass and were fixed:

1. **Signup policy bypass.** Provisioning an unknown address creates a global Vaultwarden account,
   but the Directory Connector code this was extracted from never checked `INVITATIONS_ALLOWED` or
   `SIGNUPS_DOMAINS_WHITELIST`, so neither did SCIM. An identity provider could therefore create
   accounts on excluded domains, or while invitations were switched off. The checks now run in the
   SCIM layer before provisioning, only when the address has no account yet, leaving the Directory
   Connector's behaviour untouched (section 7).
2. **A policy refusal reported as a server error.** When an organization policy refuses a
   reactivation — two-step login enforcement, for example — the underlying error was converted to
   a generic `500`. That is a normal outcome an operator has to act on, so it is now a `403`
   carrying the policy's own message.

## 19. Known deviations and limitations

1. `meta.created` / `meta.lastModified` are absent on `User` resources (section 6).
2. `userName` is never writable, and `displayName` is only ever applied to an account this
   request creates (section 7).
3. `PUT` treats an omitted multi-valued attribute as "unchanged", not "clear" (section 8).
4. Uniqueness is enforced by pre-check, not by a database constraint (section 12).
5. `Group.displayName` uniqueness is enforced on create only, for Entra's benefit
   (section 12).
6. SCIM token lifecycle events reuse `OrganizationUpdated` (section 14).
7. Discovery endpoints require authentication, although RFC 7644 section 4 permits them to
   be anonymous; they are tenant-scoped and Entra always sends the bearer token.
8. `PATCH` atomicity is validate-then-apply rather than a single transaction, except for
   group member replacement which is genuinely transactional (section 8).
9. `useScim` stays `false` (section 16).
