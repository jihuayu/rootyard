#!/bin/bash
# Patroni post_bootstrap hook for the Rootyard HA reference profile.
# Patroni calls this once on the initial leader with a libpq conninfo string as
# $1 (superuser, local socket, no password in argv).  Application credentials
# are read from the private service environment, written to a 0600 temporary
# SQL file and never placed on a command line.
set -euo pipefail
conninfo=$1
if [ -z "${ROOTYARD_BOOTSTRAP_DB_PASSWORD:-}" ]; then
    echo "ROOTYARD_BOOTSTRAP_DB_PASSWORD is required" >&2
    exit 1
fi
umask 077
tmp=$(mktemp "${TMPDIR:-/tmp}/rootyard-bootstrap.XXXXXX.sql")
trap 'rm -f "$tmp"' EXIT
cat >"$tmp" <<SQL
SET password_encryption = 'scram-sha-256';
DO \$\$
BEGIN
    IF NOT EXISTS (SELECT 1 FROM pg_catalog.pg_roles WHERE rolname = '@USER@') THEN
        CREATE ROLE "@USER@" LOGIN CREATEDB;
    END IF;
END
\$\$;
ALTER ROLE "@USER@" PASSWORD '$ROOTYARD_BOOTSTRAP_DB_PASSWORD';
SELECT 'CREATE DATABASE "@DATABASE@" OWNER "@USER@"'
WHERE NOT EXISTS (SELECT 1 FROM pg_catalog.pg_database WHERE datname = '@DATABASE@')\gexec
SQL
psql "$conninfo" -X -v ON_ERROR_STOP=1 -f "$tmp"
