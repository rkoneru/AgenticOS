#!/usr/bin/env bash
# Run a command with PG_ADMIN_URL set to a superuser URL of a Postgres 16 + pgvector server.
# If PG_ADMIN_URL is already set (CI service container, docker compose), it is used as-is.
# Otherwise a throwaway local cluster is started from the installed PostgreSQL 16 binaries.
set -euo pipefail
if [[ -n "${PG_ADMIN_URL:-}" ]]; then exec "$@"; fi

BIN=${PG_BIN:-/usr/lib/postgresql/16/bin}
[[ -x "$BIN/initdb" ]] || { echo "no PG_ADMIN_URL and no PostgreSQL 16 at $BIN" >&2; exit 2; }
# Pick a free port so concurrent test runs (worktrees, CI shards) never collide.
PORT=${PG_PORT:-$(python3 -c 'import socket; s = socket.socket(); s.bind(("127.0.0.1", 0)); print(s.getsockname()[1])')}
DIR=$(mktemp -d)
RUN=()
if [[ $(id -u) -eq 0 ]]; then # postgres refuses to run as root
  chown postgres:postgres "$DIR"
  RUN=(runuser -u postgres --)
fi
cleanup() { "${RUN[@]}" "$BIN/pg_ctl" -D "$DIR/data" -m immediate stop >/dev/null 2>&1 || true; rm -rf "$DIR"; }
trap cleanup EXIT
"${RUN[@]}" "$BIN/initdb" -D "$DIR/data" -U postgres --auth=trust >/dev/null
"${RUN[@]}" "$BIN/pg_ctl" -D "$DIR/data" -o "-p $PORT -k $DIR -c listen_addresses=127.0.0.1" -w -l "$DIR/log" start >/dev/null
export PG_ADMIN_URL="postgres://postgres@127.0.0.1:$PORT/postgres"
"$@"
