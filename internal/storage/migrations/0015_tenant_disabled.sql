-- Disabling a Tenant is a soft delete (ADR 0008): the row survives, and
-- with it the slug. A slug is a hostname label, so freeing it would let
-- {slug}.{base_domain} come to mean a different identity namespace —
-- releasing a slug therefore has to be a deliberate purge, never a side
-- effect of cleanup.
--
-- NULL means active. The timestamp records when the Tenant first went
-- off, so re-disabling an already-disabled Tenant does not reset it.

ALTER TABLE tenants ADD COLUMN disabled_at timestamptz;
