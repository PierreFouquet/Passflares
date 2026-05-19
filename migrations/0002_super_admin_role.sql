-- Expand user_organizations.role to include 'super_admin'.
-- SQLite cannot ALTER a CHECK constraint, so the table is recreated.

CREATE TABLE user_organizations_new (
    user_id INTEGER NOT NULL,
    organization_id INTEGER NOT NULL,
    role TEXT NOT NULL CHECK(role IN ('member', 'admin', 'super_admin')),
    joined_at TEXT DEFAULT CURRENT_TIMESTAMP,
    PRIMARY KEY (user_id, organization_id),
    FOREIGN KEY (user_id) REFERENCES users(id) ON DELETE CASCADE,
    FOREIGN KEY (organization_id) REFERENCES organizations(id) ON DELETE CASCADE
);

INSERT INTO user_organizations_new (user_id, organization_id, role, joined_at)
SELECT user_id, organization_id, role, joined_at
FROM user_organizations;

DROP TABLE user_organizations;

ALTER TABLE user_organizations_new RENAME TO user_organizations;
