ALTER TABLE auth_requests ADD COLUMN atype INTEGER NOT NULL DEFAULT 0;

CREATE INDEX auth_requests_organization_type ON auth_requests (organization_uuid, atype, approved);
CREATE INDEX auth_requests_creation_date ON auth_requests (creation_date);
