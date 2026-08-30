CREATE TABLE organization_scim_key (
  uuid              CHAR(36) NOT NULL PRIMARY KEY,
  org_uuid          VARCHAR(40) NOT NULL UNIQUE,
  key_hash          VARCHAR(255) NOT NULL,
  created_at        TIMESTAMP NOT NULL,
  updated_at        TIMESTAMP NOT NULL,
  last_used_at      TIMESTAMP NULL,
  FOREIGN KEY (org_uuid) REFERENCES organizations (uuid)
);
