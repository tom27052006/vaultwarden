CREATE TABLE organization_scim_key (
  uuid              TEXT NOT NULL PRIMARY KEY,
  org_uuid          TEXT NOT NULL UNIQUE,
  key_hash          TEXT NOT NULL,
  created_at        DATETIME NOT NULL,
  updated_at        DATETIME NOT NULL,
  last_used_at      DATETIME NULL,
  FOREIGN KEY (org_uuid) REFERENCES organizations (uuid)
);
