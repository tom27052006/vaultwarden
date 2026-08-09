-- Roll a SQLite database back to the schema the Vaultwarden version *before* the Custom-role
-- change expects, so that older binary starts again. Read README.md in this directory first --
-- it lists exactly what is lost and how to run this safely.
--
-- `ALTER TABLE ... DROP COLUMN` is avoided on purpose: it only exists since SQLite 3.35, and this
-- script has to work on the same older system SQLite the forward migrations support. Rebuilding the
-- table also recreates `access_all` and drops all nine permission columns in one step.

-- Stop at the first error. Without this the sqlite3 shell keeps going after a failed statement,
-- and a second run -- where the SELECT below can no longer see the permission columns -- would
-- still reach DROP TABLE and commit an empty users_organizations. `.bail on` is a shell command;
-- a runner that is not the sqlite3 CLI has to abort on the first error and roll back by itself.
.bail on

PRAGMA foreign_keys = OFF;

BEGIN;

-- Refuse to start at all unless the database is in the exact state this script converts *from*. A
-- repeat run, or a half-finished upgrade, would otherwise only fail somewhere in the middle. Each
-- check is read-only, and the name of the failing CHECK constraint *is* the error message.
CREATE TEMPORARY TABLE __vw_rollback_precondition (
    ok INTEGER NOT NULL CONSTRAINT
        refused_membership_access_all_still_exists_so_this_database_was_not_upgraded_or_was_already_rolled_back
        CHECK (ok = 1)
);
INSERT INTO __vw_rollback_precondition (ok)
SELECT CASE
    WHEN NOT EXISTS (SELECT 1 FROM pragma_table_info('users_organizations') WHERE name = 'access_all')
    THEN 1
    ELSE 0
END;
DROP TABLE __vw_rollback_precondition;

CREATE TEMPORARY TABLE __vw_rollback_precondition_columns (
    ok INTEGER NOT NULL CONSTRAINT
        refused_all_nine_custom_role_permission_columns_must_exist_restore_the_pre_upgrade_backup
        CHECK (ok = 9)
);
INSERT INTO __vw_rollback_precondition_columns (ok)
SELECT COUNT(*)
FROM pragma_table_info('users_organizations')
WHERE name IN (
    'manage_users', 'manage_groups', 'manage_policies',
    'create_new_collections', 'edit_any_collection', 'delete_any_collection',
    'access_event_logs', 'access_import_export', 'access_reports'
);
DROP TABLE __vw_rollback_precondition_columns;

-- The rebuild below copies a fixed column list, so anything this script does not know about would be
-- silently dropped together with its data. Require the table to hold *exactly* the eighteen columns
-- the Custom-role upgrade leaves behind -- not merely to contain them. A newer migration that added a
-- column, or a local modification, therefore refuses here instead of being destroyed at COMMIT.
CREATE TEMPORARY TABLE __vw_rollback_precondition_exact_columns (
    ok INTEGER NOT NULL CONSTRAINT
        refused_users_organizations_has_unexpected_columns_this_script_is_older_than_the_database
        CHECK (ok = 1)
);
INSERT INTO __vw_rollback_precondition_exact_columns (ok)
SELECT CASE WHEN total = 18 AND known = 18 THEN 1 ELSE 0 END
FROM (
    SELECT
        COUNT(*) AS total,
        SUM(CASE WHEN name IN (
            'uuid', 'user_uuid', 'org_uuid', 'akey', 'status', 'atype',
            'reset_password_key', 'external_id', 'invited_by_email',
            'manage_users', 'manage_groups', 'manage_policies',
            'create_new_collections', 'edit_any_collection', 'delete_any_collection',
            'access_event_logs', 'access_import_export', 'access_reports'
        ) THEN 1 ELSE 0 END) AS known
    FROM pragma_table_info('users_organizations')
);
DROP TABLE __vw_rollback_precondition_exact_columns;

-- Same reasoning for schema objects attached to the table: `DROP TABLE` takes every index and trigger
-- that belongs to it with it, and the rebuild recreates none of them. The upgraded table has no
-- user-defined ones (its PRIMARY KEY and UNIQUE produce implicit indexes, which carry no SQL text),
-- so anything with SQL text here came from somewhere this script does not understand.
CREATE TEMPORARY TABLE __vw_rollback_precondition_objects (
    ok INTEGER NOT NULL CONSTRAINT
        refused_users_organizations_has_indexes_or_triggers_the_table_rebuild_would_destroy
        CHECK (ok = 0)
);
INSERT INTO __vw_rollback_precondition_objects (ok)
SELECT COUNT(*)
FROM sqlite_master
WHERE tbl_name = 'users_organizations'
  AND type IN ('index', 'trigger')
  AND sql IS NOT NULL;
DROP TABLE __vw_rollback_precondition_objects;

CREATE TEMPORARY TABLE __vw_rollback_precondition_ledger (
    ok INTEGER NOT NULL CONSTRAINT
        refused_all_eight_custom_role_migrations_must_be_recorded_schema_and_ledger_disagree
        CHECK (ok = 8)
);
INSERT INTO __vw_rollback_precondition_ledger (ok)
SELECT COUNT(*)
FROM __diesel_schema_migrations
WHERE version IN (
  '20260630120000',
  '20260715120000',
  '20260716120000',
  '20260723120000',
  '20260724120000',
  '20260724130000',
  '20260724140000',
  '20260809120000'
);
DROP TABLE __vw_rollback_precondition_ledger;

-- A migration newer than the last Custom-role one has run, so this script cannot know what it changed
-- or whether the rebuild below would undo it. Removing only the eight versions would also leave the
-- ledger claiming a migration whose schema objects are gone.
CREATE TEMPORARY TABLE __vw_rollback_precondition_future_ledger (
    ok INTEGER NOT NULL CONSTRAINT
        refused_migrations_newer_than_the_custom_role_change_are_recorded_use_a_newer_rollback_script
        CHECK (ok = 0)
);
INSERT INTO __vw_rollback_precondition_future_ledger (ok)
SELECT COUNT(*) FROM __diesel_schema_migrations WHERE version > '20260809120000';
DROP TABLE __vw_rollback_precondition_future_ledger;

-- Which memberships were legacy Managers before the upgrade is recorded by
-- 2026-06-30-120000. Without that record every Custom member would have to be mapped to plain User,
-- which is safe but demotes people who were Managers all along -- so refuse and let the operator
-- populate it (README.md explains how) rather than quietly downgrading them.
CREATE TEMPORARY TABLE __vw_rollback_precondition_provenance (
    ok INTEGER NOT NULL CONSTRAINT
        refused_legacy_manager_record_missing_see_readme_before_rolling_back_this_database
        CHECK (ok = 1)
);
INSERT INTO __vw_rollback_precondition_provenance (ok)
SELECT COUNT(*)
FROM sqlite_master
WHERE type = 'table' AND name = '__vw_custom_role_legacy_manager';
DROP TABLE __vw_rollback_precondition_provenance;

CREATE TABLE users_organizations_rollback (
  uuid       TEXT    NOT NULL PRIMARY KEY,
  user_uuid  TEXT    NOT NULL REFERENCES users (uuid),
  org_uuid   TEXT    NOT NULL REFERENCES organizations (uuid),
  access_all BOOLEAN NOT NULL DEFAULT 0,
  akey       TEXT    NOT NULL,
  status     INTEGER NOT NULL,
  atype      INTEGER NOT NULL,
  reset_password_key TEXT,
  external_id TEXT,
  invited_by_email TEXT DEFAULT NULL,

  UNIQUE (user_uuid, org_uuid)
);

-- Roles and the legacy flag are recomputed together, because in the old schema they are not
-- independent.
--
-- The role mapping is asymmetric on purpose. A membership recorded as a legacy Manager becomes
-- Manager again -- that is the role it held before the upgrade, so the round trip preserves its
-- authority. Every other Custom member was created *after* the upgrade and never was a Manager, and
-- the old Manager role is not a subset of what such a member holds: it manages -- and deletes --
-- every collection reachable through `users_collections.manage`, `collections_groups.manage` or
-- `groups.access_all`, and reads member and collection ACL details through `ManagerHeadersLoose`,
-- none of which requires a permission flag in the old schema. Mapping those to Manager would *grant*
-- authority during a downgrade, so they become plain User. Per-collection assignments are untouched,
-- so they keep every grant those carry.
--
-- `access_all` follows the same mapping the down migrations use: everyone who reached every
-- collection keeps that reach, and a Custom member has to hold all three collection permissions --
-- Edit-only must not silently turn into the legacy "manage all collections" authority, which in that
-- older schema also carried collection deletion.
INSERT INTO users_organizations_rollback (
  uuid, user_uuid, org_uuid, access_all, akey, status, atype,
  reset_password_key, external_id, invited_by_email
)
SELECT
  uo.uuid, uo.user_uuid, uo.org_uuid,
  CASE
    WHEN uo.atype IN (0, 1) THEN 1
    WHEN uo.atype = 4
         AND uo.uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager)
         AND uo.create_new_collections = 1
         AND uo.edit_any_collection = 1
         AND uo.delete_any_collection = 1 THEN 1
    ELSE 0
  END,
  uo.akey, uo.status,
  CASE
    WHEN uo.atype = 4
         AND uo.uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager)
    THEN 3
    WHEN uo.atype = 4 THEN 2
    ELSE uo.atype
  END,
  uo.reset_password_key, uo.external_id, uo.invited_by_email
FROM users_organizations AS uo;

DROP TABLE users_organizations;

ALTER TABLE users_organizations_rollback RENAME TO users_organizations;

-- Bookkeeping tables this feature may have left behind. The legacy-Manager record is dropped last
-- and on purpose: a later re-upgrade rebuilds it from the very `atype = 3` rows this script just
-- restored, so the round trip converges.
DROP TABLE IF EXISTS __vw_custom_role_same_run_0716;
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
DROP TABLE IF EXISTS __vw_ack_legacy_group_collection_authority;
DROP TABLE IF EXISTS __vw_custom_role_legacy_manager;

-- Finally forget the eight migrations, so the older binary does not see a ledger from the future
-- and a later upgrade applies them again from a clean state.
DELETE FROM __diesel_schema_migrations
WHERE version IN (
  '20260630120000',
  '20260715120000',
  '20260716120000',
  '20260723120000',
  '20260724120000',
  '20260724130000',
  '20260724140000',
  '20260809120000'
);

COMMIT;
