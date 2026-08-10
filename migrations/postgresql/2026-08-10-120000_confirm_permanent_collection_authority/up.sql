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
-- Vaultwarden's startup preflight looks ahead for exactly the condition below and refuses with the
-- full text (`RefuseUnconfirmedPermanentCollectionAuthority` in `src/db/mod.rs`), from the legacy
-- schema as well, so an operator normally never reaches the abort here. Diesel reports only the
-- driver error, so on this path the question would arrive as a bare duplicate-key violation on
-- `__vw_permanent_authority_guard` and nothing else. Keep the two predicates identical.
--
-- Review the affected memberships:
--
--     SELECT uo.uuid, uo.user_uuid, uo.org_uuid, uo.status,
--            uo.create_new_collections, uo.edit_any_collection, uo.delete_any_collection,
--            (uo.uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager))
--                AS was_legacy_manager
--     FROM users_organizations uo
--     WHERE uo.atype = 4
--       AND (uo.edit_any_collection OR uo.delete_any_collection)
--       AND EXISTS (
--         SELECT 1 FROM groups_users gu
--         INNER JOIN "groups" g ON g.uuid = gu.groups_uuid
--         WHERE gu.users_organizations_uuid = uo.uuid
--           AND g.organizations_uuid = uo.org_uuid
--           AND g.access_all);
--
-- Reading the result:
--
--   * `was_legacy_manager = t` and `create_new_collections = f` -- the conversion described above.
--     This membership's collection authority came from the group, and it is about to become
--     permanent. This is the row the question is actually about.
--   * `was_legacy_manager = t` and `create_new_collections = t` -- the authority came from the
--     membership's *own* `access_all` bit, which was never bound to a group. 2026-07-16-120000 turns
--     that stored value into all three permissions. `create_new_collections` is only ever written
--     from that stored bit -- by that statement, and by 2026-07-23-120000's second one, which
--     repeats it under the same `access_all = TRUE` condition; the group-derived grant deliberately
--     never sets it. So the flag is what still tells the two apart after 2026-07-24-120000 has
--     dropped the column they came from, and this row is excluded from the guard below -- nothing
--     changes for it.
--   * `was_legacy_manager = f` -- never a Manager. On a database first upgraded by revision bf54088c
--     they may carry permissions that revision's 2026-08-09-120000 granted in bulk, which nothing can
--     distinguish from a deliberate grant any more -- check them against what you intended.
--
-- An invited or revoked membership is listed too, and deliberately so. It holds no authority today --
-- every guard requires a confirmed membership, and `MembershipStatus::from_i32` rejects the revoked
-- value outright -- but the permission is what it would come back with if it is ever restored, and
-- by then the group it came from may be gone. Status is therefore not part of the predicate.
--
-- Clear whatever you do not want to keep, for example:
--
--     UPDATE users_organizations
--     SET edit_any_collection = FALSE, delete_any_collection = FALSE
--     WHERE uuid = '<MEMBERSHIP_UUID>';
--
-- Then record the decision once, with every Vaultwarden instance stopped:
--
--     CREATE TABLE __vw_ack_permanent_collection_authority (acknowledged INTEGER NOT NULL PRIMARY KEY);
--
-- The acknowledgement is consumed at the end of this file, so one decision covers one upgrade.
--
-- The legacy-Manager record has to exist already: the predicate below reads it to tell a
-- group-derived conversion from a membership that always held its authority outright. Refuse rather
-- than let the reference fail as `relation does not exist` half a statement later; see
-- 2026-07-23-120000 for why this never creates it.
--
-- The duplicate key aborts the migration. It is only inserted while the record table is absent.
CREATE TEMPORARY TABLE __vw_legacy_manager_record_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_legacy_manager_record_guard (blocked) VALUES (1);
INSERT INTO __vw_legacy_manager_record_guard (blocked)
SELECT 1
WHERE to_regclass('__vw_custom_role_legacy_manager') IS NULL;
DROP TABLE __vw_legacy_manager_record_guard;

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
  AND NOT (
    uo.create_new_collections = TRUE
    AND uo.uuid IN (SELECT users_organizations_uuid FROM __vw_custom_role_legacy_manager)
  )
  AND EXISTS (
    SELECT 1
    FROM groups_users AS gu
    INNER JOIN "groups" AS g ON g.uuid = gu.groups_uuid
    WHERE gu.users_organizations_uuid = uo.uuid
      AND g.organizations_uuid = uo.org_uuid
      AND g.access_all = TRUE
  )
  AND to_regclass('__vw_ack_permanent_collection_authority') IS NULL
LIMIT 1;
DROP TABLE __vw_permanent_authority_guard;

DROP TABLE IF EXISTS __vw_ack_permanent_collection_authority;
