# SCIM provisioning

Vaultwarden can act as a SCIM 2.0 service provider, so an identity provider such as Microsoft
Entra ID can create, update and deprovision organization members and groups automatically.

This is Vaultwarden's own implementation, configured from Vaultwarden's own `/admin` panel. It is
not related to, and does not use, Bitwarden's licensed SCIM server or the SCIM page in the
official web vault. See [`design.md`](design.md) for the architecture and the security decisions.

- [Enabling SCIM](#enabling-scim)
- [Generating a token](#generating-a-token)
- [Endpoint URL](#endpoint-url)
- [Microsoft Entra ID setup](#microsoft-entra-id-setup)
- [Attribute mappings](#attribute-mappings)
- [User lifecycle](#user-lifecycle)
- [Group lifecycle](#group-lifecycle)
- [Token rotation and revocation](#token-rotation-and-revocation)
- [Security considerations](#security-considerations)
- [What is not supported](#what-is-not-supported)
- [Known deviations](#known-deviations)
- [Troubleshooting](#troubleshooting)

## Enabling SCIM

SCIM is off by default. Turn it on with:

```
SCIM_ENABLED=true
```

While it is off, the SCIM endpoints return `404` and the token controls in `/admin` are
unavailable, so enabling the setting on its own does not expose any organization: a
per-organization token has to be generated first.

Two related settings matter:

| Setting | Effect on SCIM |
| --- | --- |
| `ORG_GROUPS_ENABLED` | Required for group provisioning. While it is off, `/Groups` returns `501` and the `Group` resource type is left out of discovery. User provisioning works either way. |
| `ORG_EVENTS_ENABLED` | Required for SCIM's changes to appear in the organization event log. Strongly recommended: SCIM changes membership unattended. Vaultwarden warns at startup if SCIM is on and this is off. |

Two optional settings tune the rate limiter:

```
SCIM_RATELIMIT_PER_SECOND=20     # sustained requests per second, per IP
SCIM_RATELIMIT_MAX_BURST=1000    # burst allowance on top of that
```

The defaults suit a normal Entra ID sync cycle. Raise the burst if you provision a large directory
and see `429` responses in the identity provider's logs.

## Generating a token

1. Open `/admin` and sign in with your `ADMIN_TOKEN`.
2. Go to **Organizations**.
3. In the **SCIM** column for the organization, choose **Generate token**.
4. Copy the token from the dialog that appears.

**The token is shown once.** Vaultwarden stores only a SHA-256 hash of it; there is no way to see
it again. If you lose it, generate a new one — that invalidates the old one.

Token creation, rotation and revocation are behind the same admin authentication as every other
sensitive `/admin` operation.

## Endpoint URL

```
https://vault.example.com/scim/v2/<organization_uuid>
```

The organization UUID is shown next to the organization name in `/admin`, and the full URL is on
the **Show endpoint** button. Every SCIM request is scoped to that organization: a token issued
for one organization does not work against another organization's URL.

Authentication is a bearer token:

```
Authorization: Bearer scim_v1.<key-id>.<secret>
```

## Microsoft Entra ID setup

1. In the Microsoft Entra admin center, open **Enterprise applications** and either create a new
   non-gallery application or open your existing one.
2. Open **Provisioning** and set **Provisioning Mode** to **Automatic**.
3. Under **Admin Credentials**:
   - **Tenant URL**: the endpoint URL above.
   - **Secret Token**: the token from `/admin`.
4. Choose **Test Connection**. Entra performs a `GET /ServiceProviderConfig` and a filtered
   `GET /Users`; both should succeed.
5. Save, then assign the users and groups you want provisioned to the application.
6. Under **Mappings**, review the attribute mappings — see the next section for which ones
   Vaultwarden actually uses.
7. Set **Provisioning Status** to **On**.

Entra performs an initial full sync and then incremental syncs roughly every 40 minutes.

Other SCIM 2.0 clients work too; Entra is simply the one this implementation was verified against.

## Attribute mappings

Only these attributes affect Vaultwarden. Anything else an identity provider sends is accepted and
ignored, so an over-broad default mapping does not fail provisioning.

### User

| SCIM attribute | Vaultwarden | Direction |
| --- | --- | --- |
| `id` | organization membership UUID | read-only, server generated |
| `userName` | account email address | required on create; **cannot be changed afterwards** |
| `externalId` | membership external id | read/write |
| `active` | membership revoked / not revoked | read/write |
| `emails[primary].value` | account email address | read-only (mirrors `userName`) |
| `displayName` | account name | used **only** when Vaultwarden creates a brand-new account |
| `name.formatted`, `name.givenName`, `name.familyName` | account name | fallback for `displayName`, same rule |

For Entra, the important mappings are `userName` → `userPrincipalName` (or `mail`) and
`active` → `Not([IsSoftDeleted])`. Remove mappings for attributes Vaultwarden does not store if you
prefer a tidy configuration; leaving them in is harmless.

### Group

| SCIM attribute | Vaultwarden | Direction |
| --- | --- | --- |
| `id` | group UUID | read-only, server generated |
| `displayName` | group name | read/write, required |
| `externalId` | group external id | read/write |
| `members[].value` | membership UUIDs in the same organization | read/write |

## User lifecycle

### Provisioning

When the identity provider creates a user, Vaultwarden:

1. validates `userName` as an email address and lower-cases it;
2. reuses the existing Vaultwarden account with that address, or creates the same shell account an
   organization invitation creates;
3. adds an organization membership with the ordinary **User** role and no collection access;
4. records `externalId`;
5. sends the normal organization invitation email, if mail is configured.

Provisioning an address that has no Vaultwarden account creates one, so the server's own signup
policy applies at that point — the same policy an organization admin's invite is subject to:

* `INVITATIONS_ALLOWED=false` makes SCIM refuse to create accounts for new addresses (`403`).
  Addresses that already have an account are still provisioned normally.
* `SIGNUPS_DOMAINS_WHITELIST`, if set, restricts which email domains SCIM can create accounts for
  (`400`).

**Provisioned members are invited, not confirmed.** Confirming a member requires wrapping the
organization key for that member's public key, which is a client-side cryptographic operation that
no identity provider can perform. An organization admin confirms provisioned members in the web
vault, exactly as for a manual invite. Until then the member has no access to organization data.

Members are also created with no collection assignments. Grant access through groups or through the
web vault.

### Provisioning somebody who is already inactive

`POST /Users` with `"active": false` creates the membership **already revoked** and skips the
invitation entirely — no invitation email, and no invitation record. Sending an invitation to
somebody the identity provider marked as out of scope would contradict the state it asked for, and
neither an email nor an invitation record can be taken back once created.

A later `active: true` is the point at which the invitation becomes wanted, so reactivating an
account that has never registered issues it then.

### Deactivation

`active: false` **revokes** the membership. Organization access stops immediately, and the
membership row, its `externalId`, its collection assignments and its wrapped organization key are
all kept, so a later reactivation restores the member exactly as they were. The Vaultwarden account
and its personal vault are untouched.

This is Entra's default deprovisioning action ("soft delete"), and the mode we recommend.

### Reactivation

`active: true` restores the membership to the status it had before it was revoked, subject to the
same organization policy checks as the web vault's restore button (two-step login enforcement,
single-organization policy, and so on). If a policy refuses the restore, the request fails and the
membership stays revoked.

Note that this means an identity provider can reactivate a member an administrator revoked by
hand. That is the meaning of delegating directory authority: the identity provider is the source
of truth for who is in scope. If you do not want that for a particular person, remove them from the
organization rather than revoking them.

### Deprovisioning with DELETE

`DELETE /Users/<id>` **removes the organization membership**. The Vaultwarden account, its personal
vault and its memberships in other organizations are untouched.

The membership row is genuinely removed rather than merely revoked, because RFC 7644 requires a
later `GET` on a deleted resource to return `404`; a "soft delete" that keeps returning the
resource makes identity providers retry forever. If you want the reversible behaviour, configure
your identity provider to deprovision with `active: false`.

### Privileged members

SCIM **cannot modify the `User` resource of a member whose role is Owner, Admin or Manager**. Such
memberships are visible on `GET` (so the identity provider does not create a duplicate) but every
`PUT`, `PATCH` and `DELETE` against `/Users/<id>` is refused with `403`.

This protection covers the membership itself — its role, its active state and its existence. It
does **not** cover group association: SCIM may add a privileged member to a group and remove them
from one, exactly as it does for anyone else. That is a deliberate choice. Blocking it would fail
an entire group synchronisation because one member happens to be an Owner, and an identity
provider has no way to recover from that. The consequence is that group synchronisation can change
a privileged member's group-derived collection access; see the security notes above.

This is deliberate and is what makes the following true by construction:

* SCIM cannot create an Owner or an Admin — provisioning always creates an ordinary User, and there
  is no request field that maps to a role at all.
* SCIM cannot demote or promote anyone.
* SCIM cannot remove or disable the last Owner.
* A stolen SCIM token cannot restore privileged access that an administrator took away.

To bring a privileged member under SCIM management, change their role to **User** in the web vault
first.

### Email changes

SCIM **never changes an account's email address**. A `PUT` or `PATCH` that presents a different
`userName` is rejected with `400` and `scimType: "mutability"`; one that presents the same address
is accepted as a no-op, which is what identity providers send on every update.

The account email is Vaultwarden's global identity: it is the login identifier and how every other
organization resolves the same person. Letting one organization's identity provider rewrite it
would be an account-takeover primitive. To move someone to a new address, deprovision the old user
and provision the new one.

Similarly, an account's display name is only ever set when Vaultwarden creates the account. An
existing account keeps its own name, because that name is visible in every organization it belongs
to.

## Group lifecycle

Groups require `ORG_GROUPS_ENABLED=true`.

* **Create** adds a Vaultwarden group with no collection access of its own. Collection-to-group
  assignments are made in the web vault and SCIM never creates or edits them.

  That is **not** the same as "SCIM cannot grant access to secrets". Once a group has collection
  assignments, adding a member to that group grants them the group's access, and removing them
  revokes it. Since SCIM manages membership of every group in the organization — including groups
  that existed before provisioning was switched on — group synchronisation genuinely changes who
  can read organization secrets.
* **Rename** and **externalId** updates work through `PUT` and `PATCH`.
* **Membership** changes work through `PATCH` with `add`, `remove` and `replace` on `members`,
  including the `members[value eq "..."]` form older Azure AD connectors use.
* **Delete** removes the group and its collection and membership assignments. The members keep
  their organization membership.

Every member reference must resolve to a membership **in the same organization**. A request naming
even one unknown or foreign membership fails with `400` and writes nothing at all.

A group's `displayName` must be unique within the organization when creating it, because identity
providers treat it as the group's natural key. Existing duplicates created by other means keep
working.

## Token rotation and revocation

Each organization has at most one SCIM token.

* **Rotate**: `/admin` → Organizations → **Rotate token**. The new token is shown once; the
  previous one stops working immediately. Update the identity provider straight away, or
  provisioning will start failing with `401`.
* **Revoke**: **Revoke token** deletes it. Provisioning stops immediately.
* Deleting an organization also deletes its SCIM token.

## Security considerations

* **Serve SCIM over HTTPS only.** The token is a bearer credential; anyone who observes it can
  provision and deprovision members of that organization until it is rotated.
* **A SCIM token can change who has access to organization secrets.** SCIM never creates or edits
  collection assignments, but adding somebody to a group that *already* has collection
  assignments — or full access — grants them that access, and removing them takes it away. Group
  synchronisation is therefore an access-control operation, not just directory bookkeeping. Treat
  the token as an organization-level provisioning credential accordingly.
* **SCIM can operate on groups it did not create.** It manages every group in the organization,
  matched by `displayName` or `externalId`, not only ones a previous SCIM sync made. That is
  deliberate — an operator usually wants the identity provider to take over the groups that
  already exist — but it does mean an existing, highly privileged group can come under identity
  provider control. Check which groups hold collection assignments before enabling provisioning.
* **The token does not expire.** See [Known deviations](#known-deviations).
* **The token is organization-scoped.** It cannot read or change anything outside its own
  organization, and it cannot touch privileged members even inside it.
* **Only a hash is stored.** A database compromise does not yield usable tokens. The secret is 256
  bits of cryptographically secure randomness.
* **Failed authentication is uniform.** Wrong secret, unknown key, and unknown organization all
  produce the same `401` with the same body, so SCIM cannot be used to discover which
  organizations exist.
* **Requests are rate limited** by client IP before any parsing or database work.
* **Bodies are capped** at 1 MiB, member lists at 5000 entries per request, `PATCH` documents at
  1000 operations, and page size at 500 resources.
* **Enable `ORG_EVENTS_ENABLED`** so that provisioning actions are recorded. SCIM events are logged
  against a synthetic `vaultwarden-scim-...` actor, never against a real user.
* A SCIM token is *not* a substitute for the organization API key used by the Directory Connector,
  and vice versa; the two are separate credentials with separate endpoints.

## What is not supported

Advertised as unsupported in `/ServiceProviderConfig`, so a well-behaved client will not attempt
them:

* `/Bulk` operations
* Sorting
* ETags / conditional requests
* Password operations (`changePassword`)
* The `EnterpriseUser` schema extension
* Filtering on attributes other than the ones listed above

Also out of scope, and not advertised:

* Staged members
* Provisioning of roles, collection permissions or custom roles
* Automatic confirmation of provisioned members
* SSO and claimed domains
* The SCIM page in the official Bitwarden web vault (see below)

## Known deviations

These are deliberate. Each is explained in [`design.md`](design.md).

1. **`useScim` stays `false`** in the organization API response. The web vault's SCIM page is part
   of Bitwarden's licensed code, targets a different endpoint layout and key-management API, and
   cannot work against Vaultwarden. Enabling the flag would surface a broken page. SCIM is
   configured in `/admin` instead.
2. **`meta.created` and `meta.lastModified` are omitted on `User` resources.** Vaultwarden's
   membership table has no timestamps, and reporting the account's timestamps instead would be
   misleading. Both are optional in RFC 7643. Group resources do carry them.
3. **`userName` and `displayName` are not writable** on an existing account (see above).
4. **An omitted multi-valued attribute in a `PUT` means "unchanged", not "clear".** A strict
   reading of RFC 7644 would empty a group whose `members` a client forgot to send; Vaultwarden
   requires an explicit `"members": []` to do that.
5. **Uniqueness is enforced by pre-check, not by a database constraint**, so two simultaneous
   creates of the same user could both succeed. Identity providers serialise writes per resource,
   so the window is narrow, and a duplicate membership grants no extra access.
6. **SCIM token lifecycle events are recorded as `OrganizationUpdated`**, because Vaultwarden's
   event type numbers mirror Bitwarden's and inventing a new one could collide with a future
   upstream value. The server log records which action it was.
7. **Discovery endpoints require the bearer token**, although RFC 7644 permits them to be
   anonymous.
8. **The SCIM token does not expire.** RFC 7644's security considerations say a bearer token
   should have a lifetime the service provider can determine. Vaultwarden's is valid until an
   administrator rotates or revokes it.

   This is a deliberate deviation, not an oversight. A short-lived token would have to be replaced
   by hand in the identity provider every time it expired — Microsoft Entra ID cannot fetch a new
   one on its own — so a short expiry would either be switched off immediately or leave
   provisioning silently broken at 3am. The mitigations actually in place are that the token is
   organization-scoped, cannot touch a privileged member's role or existence, is stored only as a
   hash, is rate limited, shows a `Last used` timestamp in `/admin` so a forgotten token is
   visible, and can be revoked instantly.

   Rotate it on whatever schedule you use for other long-lived integration credentials, and revoke
   it as soon as an organization stops using SCIM.
9. **`PATCH` is atomic per request, not serialisable against concurrent requests.** Two
   simultaneous group updates each apply completely or not at all, but a client sending both at
   once is not guaranteed a particular order.

## Troubleshooting

**Entra's "Test Connection" fails with 401**
The token or the tenant URL is wrong, or the token belongs to a different organization. Note that
the organization UUID in the URL and the token must match. Generate a fresh token and paste both
values again.

**Everything returns 404**
`SCIM_ENABLED` is not set, or the URL is missing the organization UUID. The correct shape is
`https://vault.example.com/scim/v2/<organization_uuid>` with no trailing slash.

**Group operations return 501**
`ORG_GROUPS_ENABLED` is not set.

**Users are provisioned but cannot see anything**
That is expected. Provisioned members are invited and must be confirmed by an organization admin,
and they need collection access — through a group or directly — before they see any items.

**Provisioning fails with 403 for some users**
Those members hold an Owner, Admin or Manager role. Change the role to User in the web vault if you
want SCIM to manage them.

**Provisioning fails with 400 and `mutability` on `userName`**
The identity provider is trying to change an existing account's email address. Deprovision and
reprovision instead.

**Provisioning new users fails with 403 mentioning `INVITATIONS_ALLOWED`**
The server has invitations switched off, so SCIM will not create accounts for addresses that do
not already have one. Set `INVITATIONS_ALLOWED=true`.

**Provisioning fails with 400 about an email domain**
`SIGNUPS_DOMAINS_WHITELIST` excludes the directory's domain. Add it, or clear the whitelist.

**Requests fail with 429**
Raise `SCIM_RATELIMIT_MAX_BURST`, or `SCIM_RATELIMIT_PER_SECOND`, to suit the size of your
directory. Requests carrying no bearer token, or a malformed one, are charged to
`UNAUTHENTICATED_RATELIMIT_*` instead, so junk traffic cannot exhaust a real sync's allowance.

**Nothing appears in the organization's event log**
Set `ORG_EVENTS_ENABLED=true`.
