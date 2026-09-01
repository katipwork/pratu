-- Browser flows drive HTML clients by redirect (ADR 0006): the flow has
-- to carry what the UI re-reads after landing — which step it is on and
-- why the last submission failed — plus where to send the browser when
-- it completes, and a fingerprint of the CSRF secret that created it so
-- only that browser can read it back.
ALTER TABLE flows ADD COLUMN state text NOT NULL DEFAULT '';
ALTER TABLE flows ADD COLUMN ui_messages jsonb NOT NULL DEFAULT '[]'::jsonb;
ALTER TABLE flows ADD COLUMN return_to text NOT NULL DEFAULT '';
ALTER TABLE flows ADD COLUMN csrf_fp text NOT NULL DEFAULT '';
