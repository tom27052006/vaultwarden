-- Add the Custom permission model while retaining historical membership access_all values.
ALTER TABLE users_organizations
    ADD COLUMN manage_users BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN manage_groups BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN manage_policies BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN create_new_collections BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN edit_any_collection BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN delete_any_collection BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN access_event_logs BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN access_import_export BOOLEAN NOT NULL DEFAULT FALSE,
    ADD COLUMN access_reports BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users_organizations
SET create_new_collections = access_all,
    edit_any_collection = access_all,
    delete_any_collection = access_all,
    atype = 4
WHERE atype = 3;
