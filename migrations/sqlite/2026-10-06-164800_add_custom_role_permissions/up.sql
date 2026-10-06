-- Add the Custom permission model without rebuilding the membership table or dropping access_all.
ALTER TABLE users_organizations ADD COLUMN manage_users BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN manage_groups BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN manage_policies BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN create_new_collections BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN edit_any_collection BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN delete_any_collection BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN access_event_logs BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN access_import_export BOOLEAN NOT NULL DEFAULT FALSE;
ALTER TABLE users_organizations ADD COLUMN access_reports BOOLEAN NOT NULL DEFAULT FALSE;

UPDATE users_organizations
SET create_new_collections = access_all,
    edit_any_collection = access_all,
    delete_any_collection = access_all,
    atype = 4
WHERE atype = 3;
