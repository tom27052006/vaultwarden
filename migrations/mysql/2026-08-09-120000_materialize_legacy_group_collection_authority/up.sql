-- Follow-up repair for databases that already recorded 2026-07-23-120000.
--
-- That migration originally *removed* the direct 0/1/1 collection permissions of a legacy Manager
-- whose authority came from an organization-local `access_all` group, because the runtime derived the
-- authority from the group instead. Deriving it turned out to be unsound -- "Custom, none of the three
-- collection permissions, member of such a group" is also the shape of every newly created flagless
-- Custom member -- so the runtime fallback is gone and 2026-07-23-120000 now materializes the
-- authority into the permission columns.
--
-- Rewriting that file is not enough on its own: a database whose ledger already carries
-- 20260723120000 never runs it again, and would silently lose the capability. Repeat the
-- materialization here, in its own version, so both paths converge on the same state.
--
-- Idempotent: on a database that ran the new 2026-07-23-120000 every affected row already holds these
-- values, so this is a no-op. It only reads `groups` / `groups_users` and writes the two permission
-- columns, so it is also safe after `access_all` has been dropped.
--
-- Deliberately not `create_new_collections`: collection creation historically required
-- membership-level `access_all`.
--
-- Operator note: if you ran an intermediate revision of this feature branch and have since removed
-- these permissions from such a member on purpose, this re-grants them. Audit the memberships that
-- belong to a group with `access_all` afterwards:
--
--     SELECT uo.uuid, uo.org_uuid, uo.atype, uo.edit_any_collection, uo.delete_any_collection
--     FROM users_organizations uo
--     INNER JOIN groups_users gu ON gu.users_organizations_uuid = uo.uuid
--     INNER JOIN groups g ON g.uuid = gu.groups_uuid AND g.organizations_uuid = uo.org_uuid
--     WHERE g.access_all = TRUE;
UPDATE users_organizations
SET edit_any_collection = TRUE,
    delete_any_collection = TRUE
WHERE atype = 4
  AND EXISTS (
    SELECT 1
    FROM groups_users AS gu
    INNER JOIN `groups` AS g ON g.uuid = gu.groups_uuid
    WHERE gu.users_organizations_uuid = users_organizations.uuid
      AND g.organizations_uuid = users_organizations.org_uuid
      AND g.access_all = TRUE
  );