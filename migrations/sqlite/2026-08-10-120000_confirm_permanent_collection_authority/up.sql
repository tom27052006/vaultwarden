-- Make the one semantic change this feature cannot express an owner's decision instead of a default.
--
-- Before the Custom role, a Manager who reached every collection through an organization-local group
-- with `access_all` held that authority *while* the group relationship lasted. It ended when the
-- group was deleted, when its `accessAll` was switched off, when the member left it, and it was inert
-- whenever `ORG_GROUPS_ENABLED` was false. Nothing in the new model expresses a permission bound to a
-- group like that: `edit_any_collection` and `delete_any_collection` live on the membership.
--
-- So the earlier migrations in this chain write the authority onto the membership, and the result is
-- deliberately not identical to what it replaces:
--
--   * it no longer lapses when the last qualifying group disappears, or when `accessAll` is cleared;
--   * it applies even with the groups feature switched off;
--   * `edit_any_collection` additionally satisfies `has_full_access()`, so the member reaches every
--     collection of the organization directly rather than through the group.
--
-- Materializing it silently would be a migration that grants durable organization-wide collection
-- edit and delete on its own authority. Dropping it silently would take a capability away. Neither is
-- ours to choose, so this migration stops and hands the decision to an owner. It grants nothing and
-- revokes nothing itself.
--
-- On a database that never combined the legacy Manager role with an `access_all` group -- the common
-- case -- there is nothing to decide and this is a no-op.
--
-- Review the affected memberships:
--
--     SELECT uo.uuid, uo.user_uuid, uo.org_uuid, uo.status,
--            uo.create_new_collections, uo.edit_any_collection, uo.delete_any_collection,
--            (uo.uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager))
--                AS was_legacy_manager
--     FROM users_organizations uo
--     WHERE uo.atype = 4
--       AND (uo.edit_any_collection = 1 OR uo.delete_any_collection = 1)
--       AND EXISTS (
--         SELECT 1 FROM groups_users gu
--         INNER JOIN "groups" g ON g.uuid = gu.groups_uuid
--         WHERE gu.users_organizations_uuid = uo.uuid
--           AND g.organizations_uuid = uo.org_uuid
--           AND g.access_all = 1);
--
-- Rows with `was_legacy_manager = 1` are the conversion described above. Rows with `0` were never
-- Managers: on a database first upgraded by revision bf54088c they may carry permissions that
-- revision's 2026-08-09-120000 granted in bulk, which nothing can distinguish from a deliberate grant
-- any more -- check them against what you intended.
--
-- Clear whatever you do not want to keep, for example:
--
--     UPDATE users_organizations
--     SET edit_any_collection = 0, delete_any_collection = 0
--     WHERE uuid = '<MEMBERSHIP_UUID>';
--
-- Then record the decision once, with every Vaultwarden instance stopped:
--
--     CREATE TABLE __vw_ack_permanent_collection_authority (acknowledged INTEGER NOT NULL PRIMARY KEY);
--
-- The acknowledgement is consumed at the end of this file, so one decision covers one upgrade.
--
-- The duplicate key aborts the migration. It is only inserted while an unconfirmed membership exists.
CREATE TEMPORARY TABLE __vw_permanent_authority_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_permanent_authority_guard (blocked) VALUES (1);
INSERT INTO __vw_permanent_authority_guard (blocked)
SELECT 1
FROM users_organizations AS uo
WHERE uo.atype = 4
  AND (uo.edit_any_collection = TRUE OR uo.delete_any_collection = TRUE)
  AND EXISTS (
    SELECT 1
    FROM groups_users AS gu
    INNER JOIN "groups" AS g ON g.uuid = gu.groups_uuid
    WHERE gu.users_organizations_uuid = uo.uuid
      AND g.organizations_uuid = uo.org_uuid
      AND g.access_all = TRUE
  )
  AND NOT EXISTS (
    SELECT 1 FROM sqlite_master
    WHERE type = 'table' AND name = '__vw_ack_permanent_collection_authority'
  )
LIMIT 1;
DROP TABLE __vw_permanent_authority_guard;

DROP TABLE IF EXISTS __vw_ack_permanent_collection_authority;
