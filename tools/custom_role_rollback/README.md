# Rolling back the Custom-role change

The Custom-role change removes the membership `access_all` column and adds nine permission columns.
A Vaultwarden version from before that change cannot start against the new schema, because its
`schema.rs` still expects `access_all` to exist.

Vaultwarden only ever applies *pending* migrations — it never reverts one on its own — so putting
the old image back is not enough. Run the script for your backend once and the old version starts
again.

## What is lost

The old schema has nowhere to store the nine permissions, so they are dropped:

| Before the rollback | After |
|---|---|
| Owner / Admin | Owner / Admin with `access_all = TRUE` |
| Custom with **all three** collection permissions | Manager with `access_all = TRUE` |
| Custom with only some collection permissions | Manager with `access_all = FALSE` |
| Custom with `manageUsers` / `manageGroups` / `managePolicies` | Manager — those permissions are gone |
| Custom with `accessEventLogs` / `accessImportExport` / `accessReports` | Manager — those permissions are gone |
| plain User | plain User with `access_all = FALSE` |

Per-collection assignments (`users_collections`, `collections_groups`) and `groups.access_all` are
untouched. Only `users_organizations` changes.

One of those rows does not come back byte-identical to what the database held before the *upgrade*,
because the information no longer exists to reconstruct it:

- **Owner/Admin always come back with `access_all = TRUE`**, even if the flag was `FALSE` for them
  before. The upgrade dropped the column precisely because Owners and Admins reach every collection
  through their role, so the original value is unknown afterwards. It grants them nothing they did
  not already have as Owner/Admin; the visible difference is that unassigned collections show up in
  their personal vault view again.

A plain User carrying `access_all` cannot reach this point at all: the upgrade refuses to start on such
a database and asks an owner to resolve it first, precisely so that no rollback has to guess what the
bit meant.

Edit-any-collection deliberately does **not** become `access_all` on its own: in the old schema that
flag also carried the legacy "manage all collections" authority including deletion, so a member who
only held Edit must not come back with delete rights.

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
ledger before it touches anything, and refuses unless all three hold:

- membership `access_all` is gone (so the upgrade did run, and this script has not),
- all nine permission columns exist,
- all eight migrations are recorded in `__diesel_schema_migrations`.

A second run, or a half-finished upgrade, is therefore refused with a message that names the reason
and leaves the database exactly as it was. This matters most on MySQL/MariaDB, where nothing can be
rolled back: without the check, a database whose `access_all` was already dropped but whose
access-permission columns were never added would get through the first `ADD COLUMN`, the value
rewrites, the type change and six `DROP COLUMN`s before failing on the seventh — ending up less
consistent than before.

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

On SQLite the down migrations do use `ALTER TABLE ... DROP COLUMN` and therefore need SQLite 3.35 or
newer. That is fine for a development checkout with a bundled SQLite; operators on an older system
SQLite should use `sqlite.sql` above, which rebuilds the table instead.
