-- Lossy revert: this removes the three Custom management permissions and the Custom role itself,
-- which the legacy role/access_all schema cannot represent. The revert therefore
-- requires the same acknowledgement as 2026-07-24-140000/down.sql -- which only announces the loss,
-- it does not authorize it. Create the marker table while every Vaultwarden instance is stopped:
--
--     CREATE TABLE __vw_allow_custom_role_downgrade (acknowledged INTEGER NOT NULL PRIMARY KEY);
CREATE TEMPORARY TABLE __vw_custom_role_downgrade_guard (
    blocked INTEGER NOT NULL PRIMARY KEY
);
INSERT INTO __vw_custom_role_downgrade_guard (blocked) VALUES (1);
-- The duplicate key aborts the revert. It is only inserted while the acknowledgement is absent.
INSERT INTO __vw_custom_role_downgrade_guard (blocked)
SELECT 1 FROM DUAL
WHERE NOT EXISTS (
    SELECT 1 FROM information_schema.tables
    WHERE table_schema = DATABASE() AND table_name = '__vw_allow_custom_role_downgrade'
);
DROP TABLE __vw_custom_role_downgrade_guard;

-- Convert Custom members back to Manager, the representation older server versions
-- expect (they masquerade Manager as Custom in API responses and cannot load type 4).
UPDATE users_organizations SET atype = 3 WHERE atype = 4;
ALTER TABLE users_organizations DROP COLUMN manage_users;
ALTER TABLE users_organizations DROP COLUMN manage_groups;
ALTER TABLE users_organizations DROP COLUMN manage_policies;

-- Oldest lossy step of the chain: nothing below this can lose Custom-role data any more, so the
-- acknowledgement is consumed here. It authorized *this* downgrade, not every future one.
DROP TABLE IF EXISTS __vw_allow_custom_role_downgrade;
