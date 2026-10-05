-- A legacy role cannot express arbitrary Custom permissions. Demote Custom to User on rollback.
UPDATE users_organizations SET atype = 2 WHERE atype = 4;
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
