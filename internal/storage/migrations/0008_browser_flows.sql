-- Browser flows authenticate with cookies and therefore carry CSRF
-- protection; API flows use bearer tokens and need none.
ALTER TABLE flows ADD COLUMN browser boolean NOT NULL DEFAULT false;
