-- Roll a PostgreSQL database back to the schema the Vaultwarden version *before* the Custom-role
-- change expects, so that older binary starts again. Read README.md in this directory first --
-- it lists exactly what is lost and how to run this safely.
--
-- PostgreSQL DDL is transactional, so this whole script either applies or it does not.

BEGIN;

-- Precondition. Read-only: it inspects the catalog and the migration ledger and changes nothing, so a
-- database this script does not fit keeps its exact state. The transaction would roll back a mismatch
-- anyway; this turns a raw "column does not exist" into a message that says what to do, and it keeps
-- all three backends' scripts symmetrical.
--
-- The column checks resolve `users_organizations` through `to_regclass`, i.e. exactly the relation the
-- session's `search_path` points at, and read its attributes. Counting `information_schema.columns` by
-- `table_name` alone would also count same-named tables in *other* schemas and refuse a perfectly
-- valid target database.
DO $$
DECLARE
    memberships regclass := to_regclass('users_organizations');
    access_all_present int;
    permission_columns int;
    ledger_rows int;
BEGIN
    IF memberships IS NULL THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: no users_organizations table is '
                        'reachable through the current search_path. Connect to the database and schema '
                        'Vaultwarden uses.';
    END IF;

    SELECT count(*) INTO access_all_present
    FROM pg_attribute
    WHERE attrelid = memberships
      AND attnum > 0
      AND NOT attisdropped
      AND attname = 'access_all';

    SELECT count(*) INTO permission_columns
    FROM pg_attribute
    WHERE attrelid = memberships
      AND attnum > 0
      AND NOT attisdropped
      AND attname IN (
          'manage_users', 'manage_groups', 'manage_policies',
          'create_new_collections', 'edit_any_collection', 'delete_any_collection',
          'access_event_logs', 'access_import_export', 'access_reports'
      );

    SELECT count(*) INTO ledger_rows
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

    IF access_all_present <> 0 THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: users_organizations.access_all still '
                        'exists. This database was either never upgraded past the Custom-role '
                        'migrations, or this script already ran.';
    END IF;

    IF permission_columns <> 9 THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: expected all nine Custom-role '
                        'permission columns on users_organizations, found %. The upgrade is '
                        'incomplete, so restore the backup taken before it and start over.',
                        permission_columns;
    END IF;

    IF ledger_rows <> 8 THEN
        RAISE EXCEPTION 'Rollback refused, nothing was changed: expected all eight Custom-role '
                        'migrations in __diesel_schema_migrations, found %. Schema and ledger '
                        'disagree, so restore the backup taken before the upgrade and start over.',
                        ledger_rows;
    END IF;
END $$;

ALTER TABLE users_organizations ADD COLUMN access_all BOOLEAN NOT NULL DEFAULT FALSE;

-- The legacy flag is recomputed with the same mapping the down migrations use: everyone who
-- reached every collection keeps that reach, and a Custom member has to hold all three collection
-- permissions -- Edit-only must not silently turn into the legacy "manage all collections"
-- authority, which in that older schema also carried collection deletion.
UPDATE users_organizations SET access_all = TRUE WHERE atype IN (0, 1);
UPDATE users_organizations
SET access_all = TRUE
WHERE atype = 4
  AND create_new_collections = TRUE
  AND edit_any_collection = TRUE
  AND delete_any_collection = TRUE;

-- The old server cannot load type 4; Custom members were stored as Manager back then.
UPDATE users_organizations SET atype = 3 WHERE atype = 4;

ALTER TABLE users_organizations
  DROP COLUMN manage_users,
  DROP COLUMN manage_groups,
  DROP COLUMN manage_policies,
  DROP COLUMN create_new_collections,
  DROP COLUMN edit_any_collection,
  DROP COLUMN delete_any_collection,
  DROP COLUMN access_event_logs,
  DROP COLUMN access_import_export,
  DROP COLUMN access_reports;

-- Bookkeeping tables this feature may have left behind.
DROP TABLE IF EXISTS __vw_custom_role_same_run_0716;
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;

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
