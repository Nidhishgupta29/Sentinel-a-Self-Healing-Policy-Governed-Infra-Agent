#!/usr/bin/env sh
set -eu

dashboard_url="${DASHBOARD_URL:-http://127.0.0.1:8000}"
demo_url="${DEMO_URL:-http://127.0.0.1:8001}"
postmortem_file="$(find postmortems -maxdepth 1 -type f -name '*.md' -print -quit 2>/dev/null || true)"

if [ -z "$postmortem_file" ]; then
    printf '%s\n' "No historical postmortem found under postmortems/" >&2
    exit 1
fi
postmortem_name="${postmortem_file##*/}"

cleanup() {
    docker compose down --remove-orphans
}
trap cleanup EXIT INT TERM

docker compose up -d --build

ready=0
for attempt in $(seq 1 30); do
    if curl --fail --silent --show-error "$dashboard_url/" >/dev/null \
        && curl --fail --silent --show-error "$dashboard_url/postmortem/$postmortem_name" >/dev/null \
        && curl --fail --silent --show-error "$demo_url/health" >/dev/null; then
        ready=1
        break
    fi
    sleep 1
done

if [ "$ready" -ne 1 ]; then
    docker compose ps
    docker compose logs
    exit 1
fi

printf '%s\n' "Smoke test passed: dashboard root, postmortem route, and demo health returned 2xx."
