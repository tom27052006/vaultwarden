-- Repair the legacy role/permission state while membership `access_all` still exists.
--
-- A plain User carrying the historical membership-level `access_all` bit is deliberately not
-- converted: that state grants dynamic reach over every collection *without* management authority,
-- and the new model has no equivalent. It is refused instead -- and refused *here*, not only in Rust:
-- Vaultwarden's startup preflight already stops such a database before any migration runs and prints
-- the two explicit choices (`RefuseLegacyUserAccessAll` in `src/db/mod.rs`), but a migration run
-- outside that wrapper -- `diesel migration run`, a bare `MigrationHarness`, any other SQL runner
-- -- would not consult it, and 2026-07-24-120000 removes the only source of that reach a few
-- statements later. Repeating the check before this file's first mutation is what makes the silent
-- loss impossible rather than unlikely.
--
-- The duplicate key aborts the migration. It is only inserted when such a membership exists.
CREATE TEMPORARY TABLE __vw_legacy_user_access_all_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_legacy_user_access_all_guard (blocked) VALUES (1);
INSERT INTO __vw_legacy_user_access_all_guard (blocked)
SELECT 1
FROM users_organizations
WHERE atype = 2
  AND access_all = TRUE
LIMIT 1;
DROP TABLE __vw_legacy_user_access_all_guard;

-- Step 1: a legacy Manager -- or a Custom member converted by an earlier revision of this feature --
-- who managed every collection through an organization-local group with `access_all` keeps that
-- authority, materialized into the permission columns it now lives in.
--
-- Earlier revisions derived this authority live from the group instead. That was unsound: "Custom,
-- none of the three collection permissions, member of an `access_all` group" is also the shape of
-- every newly created flagless Custom member, so assigning one to an ordinary `access_all` group
-- handed out organization-wide collection edit and delete, and *removing* a collection permission
-- from a member of such a group activated it. Materializing the authority makes it visible to an
-- owner in the member's permission list and revocable by clearing a checkbox.
--
-- Deliberately not `create_new_collections`: creating collections historically required
-- membership-level `access_all`, and it is an independent permission now.
UPDATE users_organizations
SET edit_any_collection = TRUE,
    delete_any_collection = TRUE
WHERE atype IN (3, 4)
  AND EXISTS (
    SELECT 1
    FROM groups_users AS gu
    INNER JOIN "groups" AS g ON g.uuid = gu.groups_uuid
    WHERE gu.users_organizations_uuid = users_organizations.uuid
      AND g.organizations_uuid = users_organizations.org_uuid
      AND g.access_all = TRUE
  );

-- Step 2: membership `access_all` on a legacy Manager/Custom represented all three collection
-- capabilities. Set only TRUE values so this repair never removes independently configured
-- permissions.
UPDATE users_organizations
SET create_new_collections = TRUE,
    edit_any_collection = TRUE,
    delete_any_collection = TRUE
WHERE atype IN (3, 4)
  AND access_all = TRUE;

-- Convert only after the legacy bit has been copied.
UPDATE users_organizations SET atype = 4 WHERE atype = 3;

-- Clear the same-run marker only after every permission update succeeds.
DELETE FROM __vw_custom_role_same_run_0716 WHERE marker = 1;
