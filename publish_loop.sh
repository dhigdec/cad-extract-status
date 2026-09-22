#!/bin/bash
set -uo pipefail

ROOT=/tmp/cad-extract-status
INTERVAL=${INTERVAL:-20}
LOG="$ROOT/publish_loop.log"
PIDFILE="$ROOT/publish_loop.pid"
LOCKDIR="$ROOT/.publish_loop.lock"
CLOUD_STATUS_URI=gs://cad-disk-extract-mlproject-501205/_state/status.json
GCLOUD=${GCLOUD:-/opt/homebrew/bin/gcloud}
COMMAND_TIMEOUT_SECONDS=${COMMAND_TIMEOUT_SECONDS:-60}

cd "$ROOT" || exit 1

if [ ! -x "$GCLOUD" ]; then
  GCLOUD=$(command -v gcloud 2>/dev/null || true)
fi
if [ -z "$GCLOUD" ]; then
  echo "$(date -u +%FT%TZ) gcloud not found" >>"$LOG"
  exit 1
fi

acquire_lock() {
  if mkdir "$LOCKDIR" 2>/dev/null; then
    echo "$$" >"$LOCKDIR/pid"
    return 0
  fi

  old_pid=$(cat "$LOCKDIR/pid" 2>/dev/null || true)
  if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
    return 1
  fi

  rm -rf "$LOCKDIR"
  mkdir "$LOCKDIR" || return 1
  echo "$$" >"$LOCKDIR/pid"
}

cleanup() {
  if [ "$(cat "$PIDFILE" 2>/dev/null || true)" = "$$" ]; then
    rm -f "$PIDFILE"
  fi
  if [ "$(cat "$LOCKDIR/pid" 2>/dev/null || true)" = "$$" ]; then
    rm -rf "$LOCKDIR"
  fi
}

run_with_timeout() {
  python3 - "$COMMAND_TIMEOUT_SECONDS" "$@" <<'PY'
import subprocess
import sys

timeout = float(sys.argv[1])
command = sys.argv[2:]
try:
    completed = subprocess.run(command, timeout=timeout)
except subprocess.TimeoutExpired:
    print(f"command timed out after {timeout:g}s: {command[0]}", file=sys.stderr)
    raise SystemExit(124)
raise SystemExit(completed.returncode)
PY
}

fetch_and_write_status() {
  source_tmp=$(mktemp "$ROOT/.gcp-status.XXXXXX") || return 1
  output_tmp=$(mktemp "$ROOT/.status.XXXXXX") || {
    rm -f "$source_tmp"
    return 1
  }

  if ! "$GCLOUD" storage cat "$CLOUD_STATUS_URI" >"$source_tmp" 2>>"$LOG"; then
    echo "$(date -u +%FT%TZ) GCS status fetch failed" >>"$LOG"
    rm -f "$source_tmp" "$output_tmp"
    return 1
  fi

  if ! python3 - "$source_tmp" "$output_tmp" "$CLOUD_STATUS_URI" <<'PY'
import datetime
import json
import sys

source_path, output_path, source_uri = sys.argv[1:]
with open(source_path, encoding="utf-8") as handle:
    cloud = json.load(handle)

if cloud.get("source_of_truth") != "gcp":
    raise ValueError("GCS status is not marked as GCP source of truth")

heartbeat = cloud.get("heartbeat_at")
heartbeat_age = None
if heartbeat:
    stamp = datetime.datetime.fromisoformat(heartbeat.replace("Z", "+00:00"))
    now = datetime.datetime.now(datetime.timezone.utc)
    heartbeat_age = max(0.0, (now - stamp).total_seconds())

source_workers = cloud.get("workers")
if not isinstance(source_workers, list):
    source_workers = []

worker_fields = (
    "shard",
    "state",
    "current_archive",
    "last_archive",
    "archive_bytes",
    "source_bytes_downloaded",
    "shard_remaining",
    "updated_at",
    "alive",
    "exitcode",
)
workers = [
    {key: worker.get(key) for key in worker_fields if key in worker}
    for worker in source_workers
    if isinstance(worker, dict)
]
alive_workers = sum(worker.get("alive") is True for worker in workers)
fresh = heartbeat_age is not None and heartbeat_age < 120

progress = cloud.get("progress")
if not isinstance(progress, dict):
    progress = {}

def object_field(name):
    value = cloud.get(name)
    return value if isinstance(value, dict) else {}

out = {
    "schema": 3,
    "source_of_truth": "gcp",
    "source_status_uri": source_uri,
    "state": cloud.get("state"),
    "health": "alive" if fresh and alive_workers else (
        "stale" if heartbeat else "waiting"
    ),
    "status_last_updated": heartbeat,
    "last_update_iso": heartbeat,
    "cloud_workers_alive": alive_workers,
    "gce": object_field("gce"),
    "compute": object_field("compute"),
    "persistent_disk": object_field("persistent_disk"),
    "gcs": object_field("gcs"),
    "aws_source": object_field("aws_source"),
    "costs": object_field("costs"),
    "archives_combined": {
        "total": progress.get("archives_total"),
        "done": progress.get("done"),
        "remaining": progress.get("remaining"),
        "failed": progress.get("failed_active_checkpoints"),
        "retries": progress.get("retries"),
        "done_local_before_cutover": progress.get("done_before_gcp"),
        "done_on_gcp": progress.get("done_on_gcp"),
    },
    "current": workers,
    "cloud_counts": object_field("counts"),
    "cloud_depth": object_field("nested_depth"),
    "remaining_by_size": cloud.get("remaining_by_size"),
    "finished_depth_by_size": cloud.get("finished_depth_by_size"),
    "last_result": cloud.get("last_result"),
    "last_finished_at": cloud.get("last_finished_at"),
    "proof_object": cloud.get("proof_object"),
}

with open(output_path, "w", encoding="utf-8") as handle:
    json.dump(out, handle, indent=2, sort_keys=True)
    handle.write("\n")
PY
  then
    echo "$(date -u +%FT%TZ) GCP status transform failed" >>"$LOG"
    rm -f "$source_tmp" "$output_tmp"
    return 1
  fi

  mv "$output_tmp" "$ROOT/status.json"
  rm -f "$source_tmp"
}

publish_once() {
  fetch_and_write_status || return 1

  git add -- status.json publish_loop.sh index.html
  if ! git diff --cached --quiet -- status.json publish_loop.sh index.html; then
    git -c user.email="dhiren.gangishetty@deccan.ai" \
        -c user.name="dhiren" commit -m "Publish GCP extract progress" \
        -- status.json publish_loop.sh index.html >>"$LOG" 2>&1 || return 1
  fi

  export GIT_TERMINAL_PROMPT=0
  run_with_timeout git pull --rebase origin main >>"$LOG" 2>&1 || return 1
  if [ "$(git rev-list --count origin/main..HEAD)" -gt 0 ]; then
    run_with_timeout git push origin main >>"$LOG" 2>&1 || return 1
  fi
}

acquire_lock || exit 0
echo "$$" >"$PIDFILE"
trap cleanup EXIT
trap '' HUP
trap 'cleanup; exit 0' INT TERM

while true; do
  publish_once || true
  sleep "$INTERVAL"
done
