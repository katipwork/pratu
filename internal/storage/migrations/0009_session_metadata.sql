-- Device metadata so "log out other devices" lists are recognizable.
ALTER TABLE sessions
    ADD COLUMN ip text NOT NULL DEFAULT '',
    ADD COLUMN user_agent text NOT NULL DEFAULT '';
