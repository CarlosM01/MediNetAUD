#!/bin/sh
# Creates the AUD roles on the first start of the database container.
# Passwords come from the environment, so no credential is stored in the repository.
set -eu

psql -v ON_ERROR_STOP=1 \
  --username "$POSTGRES_USER" \
  --dbname "$POSTGRES_DB" \
  -v db="$POSTGRES_DB" \
  -v owner_pw="$AUD_OWNER_PASSWORD" \
  -v app_pw="$AUD_APP_PASSWORD" <<'SQL'
CREATE ROLE aud_owner LOGIN PASSWORD :'owner_pw';
CREATE ROLE aud_app LOGIN PASSWORD :'app_pw';

ALTER DATABASE :"db" OWNER TO aud_owner;
REVOKE ALL ON DATABASE :"db" FROM PUBLIC;
GRANT CONNECT ON DATABASE :"db" TO aud_app;
SQL
