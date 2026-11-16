-- TIMESTAMP keeps the microseconds here, only MySQL needed the change.
-- PostgreSQL rejects a migration that is only comments ("Received an empty query"), hence the no-op.
SELECT 1;
