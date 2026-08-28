-- Replace the membership-level `access_all` flag with the persisted Custom role and its nine
-- granular permissions.
--
-- Two different columns are called `access_all`, and only one of them goes away here. Everything
-- below depends on keeping them apart:
--
--   * `users_organizations.access_all` -- the MEMBERSHIP-level bit. It is what this migration
--     replaces, and it is dropped at the end of this file.
--   * `groups.access_all` -- the GROUP-level flag. A separate, still-supported feature. It is only
--     read here, to decide what a legacy Manager's permissions must be; it is never written, and it
--     keeps granting group members access to every collection afterwards exactly as before.
--
-- Before this migration a Manager reached every collection of an organization through either of
-- them: base `Collection::is_coll_manageable_by_user` accepts the membership bit and an
-- organization-local group carrying the group flag. Only the membership bit has to be expressed as
-- permissions, because only it is going away -- but the capability an owner configured through
-- either route is preserved, so both are read below. While this file runs, `access_all` (the
-- membership column) still exists and `atype = 3` still unambiguously means "legacy Manager".
--
-- One state cannot be converted at all and is refused before the first mutation; `src/db/mod.rs`
-- evaluates the same condition at startup and prints the full recovery text, because Diesel would
-- surface the abort below as nothing but a driver-level duplicate-key error.
--
-- The guard uses a temporary table on purpose: on MySQL/MariaDB temporary-table DDL is the only DDL
-- that does not commit implicitly, so a refusal cannot leave a half-applied migration behind.

-- A plain User carrying membership `access_all`. Only reachable on databases written by Vaultwarden
-- versions before the web vault stopped sending the flag; the bit gave read/write reach over every
-- collection, present and future, *without* any management authority. The new model has no
-- permission for that: `edit_any_collection` would add management authority, and dropping the bit
-- would take the reach away. Refuse and let an owner choose.
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
DROP TEMPORARY TABLE __vw_legacy_user_access_all_guard;

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
-- them every permission by role. A plain User cannot reach this point carrying the bit -- the guard
-- above. So only a Manager becomes Custom, and a Manager's organization-wide collection-management
-- capability is preserved exactly as it is configured right now:
--
--   * membership `access_all` was the "Manage all collections" checkbox and covered all three
--     collection permissions, including creating collections;
--   * an organization-local `access_all` group covered editing and deleting every collection, but
--     never collection creation -- that always required the membership bit;
--   * a Manager with neither keeps all three at FALSE.
--
-- The second case is a deliberate policy choice, not an approximation. The group-derived capability
-- was dynamic: it ended with the group, with the group's own `access_all`, and with the member
-- leaving the group. It was NOT gated on ORG_GROUPS_ENABLED -- base
-- `Collection::is_coll_manageable_by_user` reads `groups.access_all` in SQL with no configuration
-- check, so a Manager in such a group could edit and delete every collection even on an instance
-- that never turned groups on. Nothing in the new model is bound to a group like that, so the
-- capability becomes a membership permission and therefore no longer lapses on its own.
--
-- `edit_any_collection` additionally satisfies `has_full_access()`, which opens two organization-wide
-- reads to this member class that the group route did not: the organization collection list and
-- `GET /ciphers/organization-details`. Both serve data these members could already reach through the
-- group, so nothing becomes newly readable -- only the route does.
--
-- Preserving the capability an owner configured is nevertheless the right trade-off: the alternative
-- is either silently revoking access these members have today, or refusing an ordinary upgrade from
-- an official Vaultwarden database. The permission is visible in the member's permission list
-- afterwards and an owner can clear it with a checkbox.
--
-- The management (manage_users / manage_groups / manage_policies) and access (event logs /
-- import-export / reports) permissions keep their FALSE default. Nothing they unlock was a Manager
-- capability: on the previous release every member mutation (`send_invite`, `delete_member`,
-- `revoke_member`), every policy write (`put_policy`), the organization export (`get_org_export`)
-- and both event-log routes were gated on Admin/Owner. Granting one here would be a new privilege,
-- not a preserved one.
--
-- One *read* is deliberately not carried over, and it is the single place where this conversion
-- takes something away -- and it only affects members who held the MEMBERSHIP bit. On the previous
-- release `has_full_access()` read `self.access_all` and the membership's own role; it never
-- consulted `groups.access_all`, and a Manager ranks below Admin. So it was satisfied by a Manager
-- carrying membership `access_all`, and by nobody whose reach came from a group.
--
-- That check guarded the full member list (`GET /organizations/<org>/users`), so a Manager with the
-- membership bit could read every member's name, e-mail, two-factor state and assignments. They
-- could not change any of it. `manage_users` is not granted to restore that read, because it also
-- carries invite, confirm, revoke, restore and delete, which the Manager role never had -- handing
-- out member administration to preserve a read would be exactly the widening the paragraph above
-- avoids. Such members keep the member-readable `/users/mini-details` list, and an owner who wants
-- the full list back grants `manage_users` as a deliberate act.
--
-- A Manager whose reach came only from a group never had that list, and does not gain it here: it is
-- gated on `manage_users`, which this migration grants to nobody. The group mappings such a Manager
-- could read *are* preserved: reading them follows organization-wide collection reach, which
-- `edit_any_collection` carries.
--
-- Role conversion and permission values are one statement, so `atype = 3` unambiguously still means
-- Manager everywhere it is read.
--
-- Status is deliberately not part of the predicate. An invited, accepted or revoked membership is
-- converted exactly like a confirmed one: none of them holds authority while in that state, and the
-- permissions are what the membership would come back with if it is restored -- which is the same
-- thing `access_all` would have done.
--
-- The group lookup is bound to the membership's own organization. A `groups_users` row pointing at
-- another organization's `access_all` group conveys nothing, exactly as it conveys nothing today.
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

-- Never inherit a downgrade acknowledgement left behind by an earlier revert.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
