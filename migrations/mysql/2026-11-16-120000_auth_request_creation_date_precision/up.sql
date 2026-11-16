-- DATETIME keeps whole seconds, so two requests of one device in the same second tie, and which of them is the newest,
-- the only one that can be approved, is unknown. Keep the microseconds, as PostgreSQL and SQLite do here and as
-- upstream's DATETIME2 does.
ALTER TABLE auth_requests MODIFY creation_date DATETIME(6) NOT NULL;
