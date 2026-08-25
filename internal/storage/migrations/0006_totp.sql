-- Authenticator assurance level: aal1 = first factor only, aal2 = second
-- factor proven. Existing sessions were all first-factor.
ALTER TABLE sessions ADD COLUMN aal text NOT NULL DEFAULT 'aal1';
