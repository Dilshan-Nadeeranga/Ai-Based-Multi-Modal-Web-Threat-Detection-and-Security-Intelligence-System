-- One-time setup, run as a PostgreSQL superuser (e.g. psql -U postgres -f db/setup.sql).
-- Replace the password, then put the same value in backend/api-gateway/.env (DATABASE_URL).
-- Afterwards run: npm run migrate

CREATE ROLE scamtrace_app WITH LOGIN PASSWORD 'change_me_to_a_strong_password';
CREATE DATABASE scamtrace OWNER scamtrace_app;
