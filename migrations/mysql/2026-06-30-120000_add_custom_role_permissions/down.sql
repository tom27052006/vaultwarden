-- Lossy revert: this removes the three Custom management permissions and the Custom role itself,
-- which the legacy role/access_all schema cannot represent. The revert therefore
-- requires the same acknowledgement as 2026-07-24-140000/down.sql -- which only announces the loss,
-- it does not authorize it. Create the marker table while every Vaultwarden instance is stopped:
--
--     CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
CREATE TEMPORARY TABLE __vw_custom_role_downgrade_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_custom_role_downgrade_guard (blocked) VALUES (1);
-- The duplicate key aborts the revert. It is only inserted while the acknowledgement is absent.
INSERT INTO __vw_custom_role_downgrade_guard (blocked)
SELECT 1 FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = '__vw_allow_custom_role_downgrade'
);
-- `DROP TEMPORARY TABLE`, not `DROP TABLE`: the latter is one more statement that commits
-- implicitly on MySQL/MariaDB, and it would happily drop a permanent table of the same name.
DROP TEMPORARY TABLE __vw_custom_role_downgrade_guard;

-- Present on every database that ran the rewritten up migration; created empty for a ledger that
-- recorded an earlier revision of it. Empty means "no membership is on record as a legacy Manager",
-- which the mapping below resolves in the safe direction.
CREATE TABLE IF NOT EXISTS __vw_custom_role_legacy_manager (
    users_organizations_uuid CHAR(36) NOT NULL PRIMARY KEY
);

-- Convert Custom members back to a role the older server can load -- it cannot represent type 4 and
-- masquerades Manager as Custom in API responses. Which role depends on where the membership came
-- from, because the two directions are not symmetric.
--
-- A membership recorded as a legacy Manager becomes Manager again: that is exactly the role it held
-- before the upgrade, so the round trip preserves its authority.
UPDATE users_organizations SET atype = 3
WHERE atype = 4
  AND uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager);

-- Every other Custom member was created *after* the upgrade and never was a Manager. The legacy
-- Manager role is not a subset of what a Custom member holds: it manages -- and deletes -- every
-- collection reachable through `users_collections.manage`, `collections_groups.manage` or
-- `groups.access_all`, and reads member and collection ACL details through `ManagerHeadersLoose`,
-- none of which requires a permission flag in the old schema. Mapping such a member to Manager would
-- therefore *grant* authority during a downgrade, including collection deletion to a member whose
-- `delete_any_collection` is FALSE. Map to plain User instead: `users_collections` and
-- `collections_groups` are untouched, so the member keeps every per-collection grant and loses only
-- the organization-wide powers the old schema cannot express.
UPDATE users_organizations SET atype = 2 WHERE atype = 4;

-- One ALTER, not three. Each `ALTER TABLE` commits implicitly on MySQL/MariaDB, so three statements
-- mean two intermediate states that survive a failure while Diesel still considers the migration
-- unapplied; one statement is the closest this backend gets to all-or-nothing.
ALTER TABLE users_organizations
  DROP COLUMN manage_users,
  DROP COLUMN manage_groups,
  DROP COLUMN manage_policies;

-- Oldest lossy step of the chain: nothing below this can lose Custom-role data any more, so the
-- acknowledgement is consumed here. It authorized *this* downgrade, not every future one. The
-- legacy-Manager record has served its purpose too -- the roles it describes are back.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
DROP TABLE IF EXISTS __vw_custom_role_legacy_manager;
