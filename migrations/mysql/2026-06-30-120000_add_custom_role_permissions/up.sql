-- Replace the membership-level `access_all` flag with the persisted Custom role and its nine
-- granular permissions.
--
-- Before this migration a member could reach every collection of an organization in two ways that
-- the new model has to express as permissions: the membership's own `access_all` bit, and -- for a
-- Manager -- membership of an organization-local group with `access_all` (base
-- `Collection::is_coll_manageable_by_user` accepts either). The Custom role replaces the Manager
-- role and stores what a member may do, so both have to be written onto the membership here, while
-- `access_all` still exists.
--
-- `groups.access_all` itself is untouched: it is a separate, still-supported feature and keeps
-- granting group members access to every collection.
--
-- Two states cannot be converted without making a decision that belongs to an owner rather than to
-- a migration; both are checked before the first mutation. `src/db/mod.rs` evaluates the same two
-- conditions at startup and prints the full recovery text -- Diesel would surface the aborts below
-- as nothing but a driver-level duplicate-key error.
--
-- Both guards use temporary tables on purpose: on MySQL/MariaDB temporary-table DDL is the only DDL
-- that does not commit implicitly, so a refusal here cannot leave a half-applied migration behind.

-- 1) A plain User carrying membership `access_all`. Only reachable on databases written by
--    Vaultwarden versions before the web vault stopped sending the flag; the bit gave read/write
--    reach over every collection, present and future, *without* any management authority. The new
--    model has no permission for that: `edit_any_collection` would add management authority, and
--    dropping the bit would take the reach away. Refuse and let an owner choose.
--
--    The duplicate key aborts the migration. It is only inserted when such a membership exists.
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
DROP TEMPORARY TABLE __vw_legacy_user_access_all_guard;

-- 2) A Manager whose organization-wide collection authority comes *only* from an organization-local
--    group with `access_all`. That authority lasted exactly as long as the group relationship: it
--    ended with the group, with its `accessAll`, and with the member leaving it, and it was inert
--    while ORG_GROUPS_ENABLED was false. Nothing in the new model is bound to a group like that, so
--    the conversion below writes it onto the membership, where it no longer lapses and where
--    `edit_any_collection` additionally satisfies `has_full_access()`. Granting that silently would
--    hand out durable organization-wide edit and delete; skipping it silently would remove a
--    capability the member has today. An owner decides, once, by creating
--    `__vw_ack_permanent_collection_authority` (consumed at the end of this file).
--
--    A Manager who also carries membership `access_all` is deliberately not part of this: that bit
--    already is a durable membership-level grant, so converting it changes no meaning.
--
--    The duplicate key aborts the migration. It is only inserted when such a membership exists.
CREATE TEMPORARY TABLE __vw_permanent_authority_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_permanent_authority_guard (blocked) VALUES (1);
INSERT INTO __vw_permanent_authority_guard (blocked)
SELECT 1
FROM users_organizations AS uo
WHERE uo.atype = 3
  AND uo.access_all = FALSE
  AND EXISTS (
    SELECT 1
    FROM groups_users AS gu
    INNER JOIN `groups` AS g ON g.uuid = gu.groups_uuid
    WHERE gu.users_organizations_uuid = uo.uuid
      AND g.organizations_uuid = uo.org_uuid
      AND g.access_all = TRUE
  )
  AND NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = DATABASE()
      AND table_name = '__vw_ack_permanent_collection_authority'
  )
LIMIT 1;
DROP TEMPORARY TABLE __vw_permanent_authority_guard;

-- One ALTER TABLE for all nine columns. MySQL/MariaDB commit every DDL statement implicitly, so
-- nine separate statements would leave nine points at which a crash produces a partially migrated
-- schema that can never be re-applied ("Duplicate column name"). A single ALTER is one such point,
-- and on MySQL 8 it is atomic.
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

-- Owners and Admins are not touched: they carried `access_all` implicitly and the new model gives
-- them every permission by role. A plain User cannot reach this point carrying the bit -- guard 1
-- above. So only a Manager becomes Custom, and only a Manager's authority is materialized:
--
--   * membership `access_all` was the "Manage all collections" checkbox and covered all three
--     collection permissions, including creating collections;
--   * a qualifying `access_all` group covered editing and deleting every collection, but never
--     collection creation -- that always required the membership bit.
--
-- The management (manage_users / manage_groups / manage_policies) and access (event logs /
-- import-export / reports) permissions keep their FALSE default: the legacy Manager role had no
-- equivalent of any of them, so granting one here would be a new privilege, not a preserved one.
--
-- Role conversion and permission values are one statement, so `atype = 3` unambiguously still means
-- Manager everywhere it is read.
--
-- Status is deliberately not part of the predicate. An invited, accepted or revoked membership is
-- converted exactly like a confirmed one: none of them holds authority while in that state, and the
-- permissions are what the membership would come back with if it is restored -- which is the same
-- thing `access_all` would have done.
UPDATE users_organizations
SET create_new_collections = access_all,
    edit_any_collection = access_all
        OR EXISTS (
            SELECT 1
            FROM groups_users AS gu
            INNER JOIN `groups` AS g ON g.uuid = gu.groups_uuid
            WHERE gu.users_organizations_uuid = users_organizations.uuid
              AND g.organizations_uuid = users_organizations.org_uuid
              AND g.access_all = TRUE
        ),
    delete_any_collection = access_all
        OR EXISTS (
            SELECT 1
            FROM groups_users AS gu
            INNER JOIN `groups` AS g ON g.uuid = gu.groups_uuid
            WHERE gu.users_organizations_uuid = users_organizations.uuid
              AND g.organizations_uuid = users_organizations.org_uuid
              AND g.access_all = TRUE
        ),
    atype = 4
WHERE atype = 3;

-- The flag is now fully represented by the role model: Owners/Admins hold it implicitly, a Custom
-- member holds it through `edit_any_collection`. Drop the redundant column. This only concerns
-- users_organizations; `groups.access_all` stays.
ALTER TABLE users_organizations DROP COLUMN access_all;

-- The owner decision covers this upgrade only, so consume it. A rollback followed by a second
-- upgrade has to ask again.
DROP TABLE IF EXISTS __vw_ack_permanent_collection_authority;

-- Likewise, never inherit a downgrade acknowledgement left behind by an earlier revert.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
