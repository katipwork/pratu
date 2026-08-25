-- Addresses now record which purposes the Identity Schema grants them:
-- verification targets and recovery addresses are schema-declared, not
-- implied. Existing rows predate the distinction and default to
-- verification-only.
ALTER TABLE identity_addresses
    ADD COLUMN for_verification boolean NOT NULL DEFAULT true,
    ADD COLUMN for_recovery boolean NOT NULL DEFAULT false;

CREATE INDEX identity_addresses_recovery_idx
    ON identity_addresses (tenant_id, value) WHERE for_recovery;
