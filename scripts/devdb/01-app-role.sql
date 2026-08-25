-- Dev-only bootstrap: the app role must NOT be a superuser and must not
-- have BYPASSRLS, or every RLS policy (ADR 0004) is silently inert.
-- The server refuses to start if connected with an elevated role.
CREATE ROLE pratu LOGIN PASSWORD 'pratu' NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS;
CREATE DATABASE pratu OWNER pratu;
