-- Roll a MySQL/MariaDB database back to the schema the Vaultwarden version *before* the Custom-role
-- change expects, so that older binary starts again. Read README.md in this directory first --
-- it lists exactly what is lost and how to run this safely.
--
-- NOTE: MySQL/MariaDB commit every DDL statement implicitly, so this script cannot be wrapped in a
-- transaction. That is exactly why everything below the precondition has to be reached in a known
-- state: an ALTER that fails halfway leaves every earlier statement committed. Take a backup before
-- running it; if it is interrupted, restore and start over.

-- ---------------------------------------------------------------------------------------------
-- Precondition. Read-only and session-local: it reads `information_schema` and the migration ledger,
-- prints the reason when the database does not fit, and aborts on a duplicate key in a TEMPORARY
-- table. No permanent object is created, altered or dropped, so a database this script does not fit
-- keeps its exact state -- which matters here precisely because DDL cannot be rolled back.
--
-- Without it, a partially upgraded database -- for example one where `access_all` was already dropped
-- but the access-permission columns were never added, which DDL autocommit makes reachable -- would
-- get through the first ADD COLUMN, the value rewrites, the type change and six DROP COLUMNs before
-- failing on the seventh with error 1091, ending up *less* consistent than before.
--
-- Deliberately not a stored procedure with SIGNAL: MySQL caps `MESSAGE_TEXT` at 128 characters and
-- answers a longer one with "ERROR 1648 Data too long for condition item 'MESSAGE_TEXT'" instead of
-- the diagnosis (MariaDB accepts it, so the difference is easy to miss), and CREATE PROCEDURE is a
-- permanent object that would have to be written *before* the checks have run -- replacing any
-- same-named routine, surviving a refusal, and requiring routine privileges this script otherwise
-- does not need.
-- ---------------------------------------------------------------------------------------------
CREATE TEMPORARY TABLE __vw_rollback_precondition (
    ok INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_rollback_precondition (ok) VALUES (1);

-- 1) Membership `access_all` has to be gone already, i.e. the upgrade ran and this script did not.
SELECT CONCAT(
    'REFUSED, nothing was changed: users_organizations.access_all still exists. This database was ',
    'either never upgraded past the Custom-role migrations, or this script already ran.'
) AS rollback_precondition_failure
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'users_organizations'
  AND column_name = 'access_all';
INSERT INTO __vw_rollback_precondition (ok)
SELECT 1
FROM information_schema.columns
WHERE table_schema = DATABASE()
  AND table_name = 'users_organizations'
  AND column_name = 'access_all';

-- 2) All nine permission columns have to be present.
SELECT CONCAT(
    'REFUSED, nothing was changed: expected all nine Custom-role permission columns on ',
    'users_organizations, found ', c.n, '. The upgrade is incomplete, so restore the backup taken ',
    'before it and start over.'
) AS rollback_precondition_failure
FROM (
    SELECT COUNT(*) AS n
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users_organizations'
      AND column_name IN (
          'manage_users', 'manage_groups', 'manage_policies',
          'create_new_collections', 'edit_any_collection', 'delete_any_collection',
          'access_event_logs', 'access_import_export', 'access_reports'
      )
) AS c
WHERE c.n <> 9;
INSERT INTO __vw_rollback_precondition (ok)
SELECT 1
FROM (
    SELECT COUNT(*) AS n
    FROM information_schema.columns
    WHERE table_schema = DATABASE()
      AND table_name = 'users_organizations'
      AND column_name IN (
          'manage_users', 'manage_groups', 'manage_policies',
          'create_new_collections', 'edit_any_collection', 'delete_any_collection',
          'access_event_logs', 'access_import_export', 'access_reports'
      )
) AS c
WHERE c.n <> 9;

-- 3) All eight Custom-role migrations have to be recorded.
SELECT CONCAT(
    'REFUSED, nothing was changed: expected all eight Custom-role migrations in ',
    '__diesel_schema_migrations, found ', c.n, '. Schema and ledger disagree, so restore the backup ',
    'taken before the upgrade and start over.'
) AS rollback_precondition_failure
FROM (
    SELECT COUNT(*) AS n
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
    )
) AS c
WHERE c.n <> 8;
INSERT INTO __vw_rollback_precondition (ok)
SELECT 1
FROM (
    SELECT COUNT(*) AS n
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
    )
) AS c
WHERE c.n <> 8;

DROP TEMPORARY TABLE __vw_rollback_precondition;

-- ---------------------------------------------------------------------------------------------
-- From here on the database is known to be in the state this script converts *from*.
-- ---------------------------------------------------------------------------------------------

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

ALTER TABLE users_organizations DROP COLUMN manage_users;
ALTER TABLE users_organizations DROP COLUMN manage_groups;
ALTER TABLE users_organizations DROP COLUMN manage_policies;
ALTER TABLE users_organizations DROP COLUMN create_new_collections;
ALTER TABLE users_organizations DROP COLUMN edit_any_collection;
ALTER TABLE users_organizations DROP COLUMN delete_any_collection;
ALTER TABLE users_organizations DROP COLUMN access_event_logs;
ALTER TABLE users_organizations DROP COLUMN access_import_export;
ALTER TABLE users_organizations DROP COLUMN access_reports;

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
