# Rolling back the Custom-role change

The Custom-role change removes the membership `access_all` column and adds nine permission columns.
A Vaultwarden version from before that change cannot start against the new schema, because its
`schema.rs` still expects `access_all` to exist.

Vaultwarden only ever applies *pending* migrations — it never reverts one on its own — so putting
the old image back is not enough. Run the script for your backend once and the old version starts
again.

## What is lost

The old schema has nowhere to store the nine permissions, so they are dropped. Which role a Custom
member comes back as depends on whether it was a Manager *before* the upgrade — recorded per
membership in `__vw_custom_role_legacy_manager` by migration `2026-06-30-120000`, at the only moment
that is still knowable, because the upgrade reuses `atype = 3` for the Custom role:

| Before the rollback | After |
|---|---|
| Owner / Admin | Owner / Admin with `access_all = TRUE` |
| **Recorded** legacy Manager, with all three collection permissions | Manager with `access_all = TRUE` |
| **Recorded** legacy Manager, with only some collection permissions | Manager with `access_all = FALSE` |
| Custom member created after the upgrade | plain User with `access_all = FALSE` |
| plain User | plain User with `access_all = FALSE` |

The mapping is asymmetric on purpose, because the two roles are not ordered. The old Manager role is
**not** a subset of what a Custom member holds: it manages — and deletes — every collection reachable
through `users_collections.manage`, `collections_groups.manage` or `groups.access_all`, and it reads
member and collection ACL details through `ManagerHeadersLoose`. None of that needs a permission flag
in the old schema. So mapping every Custom member to Manager would *grant* authority during a
downgrade: a member with `deleteAnyCollection = false` but a direct or group-based manage grant would
come back able to delete those collections, and a member with no permissions at all would come back
able to read the org's member list.

A membership that really was a Manager becomes one again — that is the role it held before the
upgrade, so the round trip preserves its authority exactly. Everything else becomes a plain User.
Per-collection assignments (`users_collections`, `collections_groups`) and `groups.access_all` are
untouched by the rollback, so those members keep every grant those carry and lose only the
organization-wide powers the old schema cannot express. Only `users_organizations` changes.

Two rows do not come back byte-identical to what the database held before the *upgrade*, because the
information no longer exists to reconstruct it:

- **Owner/Admin always come back with `access_all = TRUE`**, even if the flag was `FALSE` for them
  before. The upgrade dropped the column precisely because Owners and Admins reach every collection
  through their role, so the original value is unknown afterwards. It grants them nothing they did
  not already have as Owner/Admin; the visible difference is that unassigned collections show up in
  their personal vault view again.
- **A recorded legacy Manager whose permissions an owner has changed since the upgrade** comes back
  as a Manager regardless. The record says where the membership came from, not what it holds today.
  If an owner has deliberately reduced such a member, delete its row from
  `__vw_custom_role_legacy_manager` before rolling back and it becomes a plain User instead.

A plain User carrying `access_all` cannot reach this point at all: the upgrade refuses to start on such
a database and asks an owner to resolve it first, precisely so that no rollback has to guess what the
bit meant.

Edit-any-collection deliberately does **not** become `access_all` on its own: in the old schema that
flag also carried the legacy "manage all collections" authority including deletion, so a member who
only held Edit must not come back with delete rights.

### One-time conversion of group-derived Manager authority

A legacy Manager who managed every collection through an organization-local group with `access_all`
had that authority for as long as the group relationship lasted. The upgrade writes it out as
`editAnyCollection` / `deleteAnyCollection` on the membership itself, so it no longer lapses when the
group is removed or its `accessAll` is switched off.

That is deliberate. Deriving the authority from the group at request time — which an earlier revision
did — cannot work, because "Custom member, no collection permissions, member of an `access_all` group"
is also the shape of every newly created flagless Custom member: assigning one to an ordinary
`access_all` group would have handed out organization-wide collection edit and delete. Making it an
explicit permission is the trade: it is visible in the member's permission list and an owner can
revoke it by clearing a checkbox, which the group-derived version never was.

Review those memberships once after upgrading:

```sql
SELECT uo.uuid, uo.org_uuid, uo.edit_any_collection, uo.delete_any_collection
FROM users_organizations uo
INNER JOIN __vw_custom_role_legacy_manager lm ON lm.users_organizations_uuid = uo.uuid
INNER JOIN groups_users gu ON gu.users_organizations_uuid = uo.uuid
INNER JOIN groups g ON g.uuid = gu.groups_uuid AND g.organizations_uuid = uo.org_uuid
WHERE g.access_all = TRUE;
```

## How to run it

Stop every Vaultwarden instance and take a backup first. Then:

```bash
# SQLite
sqlite3 -bail /path/to/data/db.sqlite3 < tools/custom_role_rollback/sqlite.sql

# MySQL / MariaDB
mysql -u <user> -p <database> < tools/custom_role_rollback/mysql.sql

# PostgreSQL
psql -U <user> -d <database> -v ON_ERROR_STOP=1 -f tools/custom_role_rollback/postgresql.sql
```

Every script begins with a **read-only precondition** that inspects the schema and the migration
ledger before it touches anything, and refuses unless all of these hold:

- membership `access_all` is gone (so the upgrade did run, and this script has not),
- all nine permission columns exist,
- all eight migrations are recorded in `__diesel_schema_migrations`,
- **no migration newer than `20260809120000` is recorded** — this script does not know what a later
  migration changed, and removing only the eight Custom-role versions would leave the ledger claiming
  a migration whose schema objects may have been undone,
- **`__vw_custom_role_legacy_manager` exists**, so the role mapping above has something to go on,
- SQLite only: **`users_organizations` has exactly the eighteen expected columns and no user-defined
  index or trigger.** The SQLite script rebuilds the table from a fixed column list, so anything it
  does not know about would be dropped along with its data — it refuses instead.

A second run, or a half-finished upgrade, is therefore refused with a message that names the reason
and leaves the database exactly as it was. This matters most on MySQL/MariaDB, where nothing can be
rolled back: without the check, a database whose `access_all` was already dropped but whose
access-permission columns were never added would get through the first `ADD COLUMN`, the value
rewrites, the type change and six `DROP COLUMN`s before failing on the seventh — ending up less
consistent than before.

The PostgreSQL script resolves `users_organizations`, `__diesel_schema_migrations` and
`__vw_custom_role_legacy_manager` once each, requires all three to live in the **same** schema, and
addresses that schema explicitly from then on. An unqualified name is otherwise resolved per
statement through `search_path`, so a session with `search_path = decoy, real` could have the table
rewrite land in one schema and the ledger delete in another.

The MySQL/MariaDB script ends with an explicit `COMMIT`. Everything before it is DDL and commits
implicitly, but the final ledger `DELETE` is plain DML: under `autocommit = 0` it would be rolled back
on disconnect, leaving the schema old while all eight migrations still count as applied — and a later
upgrade would then skip them and start new code against the old schema.

### Databases upgraded before the legacy-Manager record existed

`__vw_custom_role_legacy_manager` is written by `2026-06-30-120000`. A database upgraded by an
earlier revision of this feature branch carries that migration's version in its ledger without the
table, and Diesel never re-runs a recorded version — so Vaultwarden refuses to start and the rollback
scripts refuse to run, rather than guessing which memberships were Managers.

If you still have the backup from before the first upgrade, restoring it and upgrading again is
simplest. Otherwise decide once, with every instance stopped and a backup taken. List the Custom
members and record every one that held the Manager role before the upgrade:

```sql
CREATE TABLE __vw_custom_role_legacy_manager (users_organizations_uuid TEXT NOT NULL PRIMARY KEY);
INSERT INTO __vw_custom_role_legacy_manager (users_organizations_uuid) VALUES ('<MEMBERSHIP_UUID>');
```

Use `CHAR(36)` instead of `TEXT` on MySQL/MariaDB and PostgreSQL. Leaving the table empty is a valid
answer and means "no membership was a legacy Manager": nothing is granted, and a rollback maps every
Custom member to plain User. Creating the table is what lets the upgrade continue — it is the marker
that the decision was made.

Migration `2026-08-09-120000` performs the same check a second time, for the narrower case it acts on,
and stops with the list of memberships to review. Record the genuine legacy Managers as above, then
acknowledge once:

```sql
CREATE TABLE __vw_ack_legacy_group_collection_authority (acknowledged INTEGER NOT NULL PRIMARY KEY);
```

The acknowledgement only lifts the stop; it never grants anything by itself. That migration is always
driven by the record table, so an unrecorded membership keeps exactly the permissions it has. It is
dropped once the migration succeeds, so one decision covers one upgrade.

**Do not drop the `-bail` / `ON_ERROR_STOP=1` flags, do not pass `--force` to `mysql`, and do not run
these through a client that keeps going after a failed statement.** The sqlite3 shell continues after
errors by default; the script sets `.bail on` itself, but that is a shell command a different runner
will ignore. A runner that carries on past a failing statement would reach the `DROP TABLE` and commit
an empty `users_organizations`.

SQLite and PostgreSQL apply the script in a single transaction, so an aborted run leaves the
database untouched. On MySQL/MariaDB the statements cannot be wrapped in a transaction (DDL commits
implicitly there); the precondition is what keeps a mismatch from being mutated at all, but if the
script is interrupted *after* it passed, restore the backup and start over.

The SQLite script rebuilds `users_organizations` instead of using `ALTER TABLE ... DROP COLUMN`, which
only exists since SQLite 3.35 — the same reason the forward migration rebuilds the table. It therefore
also works against the older system SQLite that `sqlite_system` builds link.

Afterwards start the older Vaultwarden version. Upgrading again later re-applies the eight
migrations from a clean state.

## Reverting with the Diesel CLI instead

For development checkouts the down migrations do the same thing step by step. **Every one of them that
loses permission data refuses by default** — `2026-07-24-130000`, `2026-07-16-120000` and
`2026-06-30-120000` — and so does `2026-07-24-140000`, which loses nothing itself and exists to stop
the chain before the first destructive step. `2026-08-09-120000` is reverted first and is a no-op, so
it neither loses anything nor needs an acknowledgement. Acknowledge the downgrade once:

```sql
CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
```

Then `diesel migration revert` works as usual for the whole chain. The acknowledgement is deliberately
*not* consumed by the first guard it satisfies: it is dropped by the oldest lossy migration
(`2026-06-30-120000`), so one decision covers one downgrade and a revert that stops halfway is still
guarded when it resumes. Re-upgrading clears a leftover acknowledgement
(`2026-07-24-140000/up.sql`), so consent never carries over into a later, unrelated revert. The
rollback scripts above drop the table as well.

The down migrations use the same asymmetric role mapping as the scripts above: `2026-06-30-120000`
sends recorded legacy Managers back to Manager and every other Custom member to plain User. Unlike the
scripts they do not refuse when `__vw_custom_role_legacy_manager` is missing — they create it empty,
which means "no membership was a legacy Manager" and downgrades every Custom member. Populate it
first if that is not what you want.

On SQLite the down migrations do use `ALTER TABLE ... DROP COLUMN` and therefore need SQLite 3.35 or
newer. That is fine for a development checkout with a bundled SQLite; operators on an older system
SQLite should use `sqlite.sql` above, which rebuilds the table instead.

On MySQL/MariaDB each down migration removes its three permission columns in a single `ALTER TABLE`
rather than three. DDL commits implicitly there, so three statements would leave two intermediate
states that survive a failure while Diesel still considers the migration unapplied; one statement is
the closest this backend gets to all-or-nothing. The temporary guard tables are removed with
`DROP TEMPORARY TABLE`, which is one implicit commit fewer and cannot hit a permanent table of the
same name by accident.
