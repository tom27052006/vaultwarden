CREATE TABLE org_invite_links (
    uuid                  CHAR(36) NOT NULL PRIMARY KEY,
    org_uuid              CHAR(36) NOT NULL UNIQUE REFERENCES organizations (uuid) ON DELETE CASCADE,
    code                  TEXT     NOT NULL,
    allowed_domains       TEXT     NOT NULL,
    invite                TEXT     NOT NULL,
    supports_confirmation BOOLEAN  NOT NULL,
    creation_date         DATETIME NOT NULL,
    revision_date         DATETIME NOT NULL
);
