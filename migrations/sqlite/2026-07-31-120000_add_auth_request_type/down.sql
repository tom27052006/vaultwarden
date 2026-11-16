DROP INDEX auth_requests_creation_date;
DROP INDEX auth_requests_organization_type;

ALTER TABLE auth_requests DROP COLUMN atype;
