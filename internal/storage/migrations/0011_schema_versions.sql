-- Identity Schemas become immutable versions: updating a named schema
-- appends a new version; identities keep the schema_id that validated
-- them, so old versions stay valid forever (grilling Q6).
ALTER TABLE identity_schemas ADD COLUMN version int NOT NULL DEFAULT 1;
ALTER TABLE identity_schemas DROP CONSTRAINT identity_schemas_tenant_id_name_key;
ALTER TABLE identity_schemas ADD CONSTRAINT identity_schemas_tenant_name_version_key
    UNIQUE (tenant_id, name, version);
