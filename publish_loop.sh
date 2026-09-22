#!/bin/bash
set -u

ROOT=/tmp/cad-extract-status
INTERVAL=20
LOG="$ROOT/publish_loop.log"
PIDFILE="$ROOT/publish_loop.pid"
LOCKDIR="$ROOT/.publish_loop.lock"
CLOUD_STATUS_URI=gs://cad-disk-extract-mlproject-501205/status.json
CLOUD_CACHE="$ROOT/.cloud-status.json"
GCLOUD=/opt/homebrew/bin/gcloud

cd "$ROOT" || exit 1

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
  rm -f "$PIDFILE"
  rm -rf "$LOCKDIR"
}

fetch_cloud_status() {
  tmp="$CLOUD_CACHE.tmp"
  if "$GCLOUD" storage cp "$CLOUD_STATUS_URI" "$tmp" --quiet >/dev/null 2>&1; then
    mv "$tmp" "$CLOUD_CACHE"
    return 0
  fi
  rm -f "$tmp"
  return 1
}

write_status() {
  python3 - <<'PY'
import datetime
import json
import os
import urllib.request

root = "/tmp/cad-extract-status"
try:
    cloud = json.load(open(os.path.join(root, ".cloud-status.json")))
except Exception:
    cloud = {}
try:
    local = json.load(urllib.request.urlopen(
        "http://127.0.0.1:8765/status.json", timeout=5
    ))
except Exception:
    local = {}

totals = local.get("totals") or {}
heartbeat = cloud.get("heartbeat_at")
age = None
if heartbeat:
    try:
        stamp = datetime.datetime.fromisoformat(heartbeat.replace("Z", "+00:00"))
        age = round((datetime.datetime.now(datetime.timezone.utc) - stamp).total_seconds(), 1)
    except Exception:
        pass
progress = cloud.get("progress") or {}
workers = cloud.get("workers") or []
fresh = age is not None and age < 120
alive = sum(bool(worker.get("alive")) for worker in workers)
out = {
    "source_of_truth": "gcp",
    "health": "alive" if fresh and alive else "stale",
    "updated": heartbeat,
    "last_update_iso": heartbeat,
    "age_seconds": age,
    "worker_alive": bool(alive),
    "cloud_workers_alive": alive,
    "stalled": not fresh,
    "cloud": cloud,
    "current": workers,
    "current_archive": next(
        (w.get("current_archive") for w in workers if w.get("current_archive")), None
    ),
    "totals": totals,
    "archives": totals.get("archives"),
    "counts": totals.get("counts"),
    "remaining_by_size": local.get("remaining_by_size"),
    "finished_depth_by_size": local.get("finished_depth_by_size"),
    "max_depth_seen": totals.get("max_depth_seen") or local.get("max_depth_seen"),
    "max_depth_cap": 15,
    "depth_cap_hits": totals.get("depth_cap_hits"),
    "archives_combined": {
        "total": progress.get("archives_total", 0),
        "done": progress.get("done", 0),
        "remaining": progress.get("remaining", 0),
        "failed": progress.get("failed_active_checkpoints", 0),
        "retries": progress.get("retries", 0),
        "done_local_before_cutover": progress.get("done_before_gcp", 0),
        "done_on_gcp": progress.get("done_on_gcp", 0),
    },
    "cloud_counts": cloud.get("counts") or {},
    "cloud_depth": cloud.get("nested_depth") or {},
    "gcs": cloud.get("gcs") or {},
    "aws_source": cloud.get("aws_source") or {},
}
tmp = os.path.join(root, ".status.json.tmp")
with open(tmp, "w") as handle:
    json.dump(out, handle, indent=2)
    handle.write("\n")
os.replace(tmp, os.path.join(root, "status.json"))
PY
}

publish_once() {
  fetch_cloud_status || echo "$(date -u +%FT%TZ) GCS status fetch failed" >>"$LOG"
  write_status >>"$LOG" 2>&1 || return 1
  git add status.json publish_loop.sh index.html
  if git diff --cached --quiet -- status.json publish_loop.sh index.html; then
    return 0
  fi
  git -c user.email="dhiren.gangishetty@deccan.ai" \
      -c user.name="dhiren" commit -m "Publish GCP extract progress" \
      -- status.json publish_loop.sh index.html >>"$LOG" 2>&1 || return 1
  export GIT_TERMINAL_PROMPT=0
  git pull --rebase origin main >>"$LOG" 2>&1 || return 1
  git push origin main >>"$LOG" 2>&1
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
