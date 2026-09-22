#!/bin/bash
set -u

ROOT=/tmp/cad-extract-status
INTERVAL=20
LOG="$ROOT/publish_loop.log"
PIDFILE="$ROOT/publish_loop.pid"
LOCKDIR="$ROOT/.publish_loop.lock"

# Source of truth is the cloud worker status mirrored out of S3.
CLOUD_STATUS_URI=s3://annotationprod/cad-disk-extract/status.json
CLOUD_CACHE="$ROOT/.cloud-status.json"
# Read-only fallback credentials live outside the repository and are never committed.
MIRROR_ENV=/tmp/cad-extract-status-creds/mirror.env

cd "$ROOT" || exit 1

acquire_lock() {
  if mkdir "$LOCKDIR" 2>/dev/null; then
    echo "$$" >"$LOCKDIR/pid"
    return 0
  fi

  old_pid=$(cat "$LOCKDIR/pid" 2>/dev/null || true)
  if [ -n "$old_pid" ] && kill -0 "$old_pid" 2>/dev/null; then
    echo "publisher already running as PID $old_pid" >&2
    return 1
  fi

  rm -rf "$LOCKDIR"
  mkdir "$LOCKDIR" 2>/dev/null || return 1
  echo "$$" >"$LOCKDIR/pid"
}

cleanup() {
  rm -f "$PIDFILE"
  rm -rf "$LOCKDIR"
}

run_timeout() {
  limit=$1
  shift
  python3 - "$limit" "$@" <<'PY'
import subprocess
import sys

timeout = float(sys.argv[1])
command = sys.argv[2:]
try:
    result = subprocess.run(command, timeout=timeout)
except subprocess.TimeoutExpired:
    print(f"timed out after {timeout:g}s: {command[0]}", file=sys.stderr)
    raise SystemExit(124)
raise SystemExit(result.returncode)
PY
}

fetch_cloud_status() {
  tmp="$ROOT/.cloud-status.json.tmp"
  if run_timeout 25 aws s3 cp "$CLOUD_STATUS_URI" "$tmp" \
      --profile annotationprod-publish --only-show-errors >/dev/null 2>&1; then
    mv "$tmp" "$CLOUD_CACHE"
    return 0
  fi
  if [ -r "$MIRROR_ENV" ]; then
    set +x
    if (
      . "$MIRROR_ENV"
      AWS_ACCESS_KEY_ID="$CAD_MIRROR_KEY" \
      AWS_SECRET_ACCESS_KEY="$CAD_MIRROR_SECRET" \
      AWS_DEFAULT_REGION=ap-south-1 \
      run_timeout 25 aws s3 cp "$CLOUD_STATUS_URI" "$tmp" --only-show-errors >/dev/null 2>&1
    ); then
      mv "$tmp" "$CLOUD_CACHE"
      return 0
    fi
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

# Cloud status mirrored from S3 is the source of truth for live progress and cost.
cloud = {}
try:
    with open(os.path.join(root, ".cloud-status.json")) as handle:
        cloud = json.load(handle) or {}
except Exception:
    cloud = {}

# The local monitor supplies the historical baseline and the by-size depth tables.
status = {}
try:
    with urllib.request.urlopen("http://127.0.0.1:8765/status.json", timeout=8) as response:
        status = json.load(response)
except Exception:
    try:
        with open(os.path.join(root, "status.json")) as handle:
            status = json.load(handle) or {}
    except Exception:
        status = {}

totals = status.get("totals") or {}
local_s3 = status.get("s3") or totals.get("s3") or {}

out = {
    "source_of_truth": "cloud-ec2",
    "health": status.get("health"),
    "updated": status.get("last_update_iso"),
    "last_update_iso": status.get("last_update_iso"),
    "age_seconds": status.get("age_seconds"),
    "worker_alive": status.get("worker_alive"),
    "stalled": status.get("stalled"),
    "current": status.get("current"),
    "current_archive": status.get("current_archive"),
    "last_finished": status.get("last_finished"),
    "totals": totals,
    "archives": totals.get("archives"),
    "counts": totals.get("counts"),
    "remaining_by_size": status.get("remaining_by_size"),
    "finished_depth_by_size": status.get("finished_depth_by_size"),
    "max_depth_seen": totals.get("max_depth_seen") or status.get("max_depth_seen"),
    "max_depth_cap": totals.get("max_depth_cap") or status.get("max_depth_cap"),
    "depth_cap_hits": totals.get("depth_cap_hits"),
    "s3": local_s3,
    "s3_stored_bytes": local_s3.get("stored_bytes"),
    "s3_stored_gb": local_s3.get("stored_gb"),
    "estimated_monthly_usd": local_s3.get("estimated_monthly_usd"),
    "local_baseline": {
        "note": (
            "Archives completed by the laptop run before cutover to EC2. "
            "Extraction, unzip and counting now happen on EC2 only."
        ),
        "health": status.get("health"),
        "updated": status.get("last_update_iso"),
        "archives": totals.get("archives"),
    },
}

if cloud:
    heartbeat = cloud.get("heartbeat_at")
    age = None
    if heartbeat:
        try:
            stamp = datetime.datetime.fromisoformat(heartbeat.replace("Z", "+00:00"))
            age = round(
                (datetime.datetime.now(datetime.timezone.utc) - stamp).total_seconds(), 1
            )
        except Exception:
            age = None

    progress = cloud.get("progress") or {}
    counts = cloud.get("counts") or {}
    workers = cloud.get("workers") or []
    prefix = cloud.get("s3_prefix") or {}

    cutover = {}
    try:
        with open(os.path.join(root, ".cutover.json")) as handle:
            cutover = json.load(handle) or {}
    except Exception:
        cutover = {}

    archives = totals.get("archives") or {}
    local_done = cutover.get("local_done_at_cutover")
    if local_done is None:
        local_done = sum(
            int(value.get("completed_ok") or 0)
            for value in archives.values()
            if isinstance(value, dict)
        ) or int(archives.get("done") or 0)

    cloud_done = progress.get("completed_ok") or 0
    cloud_failed = progress.get("failed") or 0
    cloud_total = progress.get("manifest_total") or 0
    grand_total = cutover.get("grand_total_archives") or (local_done + cloud_total)
    preclaimed = cutover.get("overlap_preclaimed_skipped_by_cloud") or 0

    current = [
        {
            "shard": worker.get("shard"),
            "state": worker.get("state"),
            "archive": worker.get("current_archive") or worker.get("last_archive"),
        }
        for worker in workers
    ]
    active = [item for item in current if item.get("archive")]

    alive = cloud.get("worker_processes_alive") or 0
    fresh = age is not None and age < 120
    out.update({
        "cloud": cloud,
        "health": "ok" if (fresh and alive) else ("stale" if cloud else status.get("health")),
        "updated": heartbeat,
        "last_update_iso": heartbeat,
        "age_seconds": age,
        "worker_alive": bool(alive),
        "cloud_workers_alive": alive,
        "stalled": not fresh,
        "current": active or current,
        "current_archive": (active[0].get("archive") if active else None),
        "archives_combined": {
            "total": grand_total,
            "done": local_done + cloud_done,
            "remaining": max(0, grand_total - local_done - cloud_done - cloud_failed),
            "failed": cloud_failed,
            "retries": progress.get("retries"),
            "done_local_before_cutover": local_done,
            "done_on_ec2": cloud_done,
            "ec2_manifest_total": cloud_total,
            "ec2_skipped_already_done_locally": preclaimed,
        },
        "cloud_counts": counts,
        "cloud_depth": cloud.get("nested_depth"),
    })

    if prefix.get("stored_bytes") is not None:
        merged = dict(local_s3)
        merged.update({
            "scope": "whole cad-disk-extract/ prefix measured from EC2",
            "prefix": prefix.get("prefix"),
            "object_count": prefix.get("object_count"),
            "stored_bytes": prefix.get("stored_bytes"),
            "stored_gb": prefix.get("stored_gb"),
            "estimated_monthly_usd": prefix.get("estimated_s3_monthly_usd"),
            "cost_rate_usd_per_gb_month": prefix.get("cost_rate_usd_per_gb_month", 0.025),
            "scanned_at": prefix.get("scanned_at"),
        })
        out["s3"] = merged
        out["s3_stored_bytes"] = merged.get("stored_bytes")
        out["s3_stored_gb"] = merged.get("stored_gb")
        out["estimated_monthly_usd"] = merged.get("estimated_monthly_usd")

tmp = os.path.join(root, ".status.json.tmp")
with open(tmp, "w") as handle:
    json.dump(out, handle, indent=2)
    handle.write("\n")
os.replace(tmp, os.path.join(root, "status.json"))
PY
}

publish_once() {
  if ! fetch_cloud_status; then
    echo "$(date -u +%FT%TZ) cloud status fetch failed" >>"$LOG"
  fi

  if ! write_status >>"$LOG" 2>&1; then
    echo "$(date -u +%FT%TZ) status build failed" >>"$LOG"
    return 1
  fi

  git add status.json publish_loop.sh
  if git diff --cached --quiet -- status.json publish_loop.sh; then
    return 0
  fi

  if ! git -c user.email="dhiren.gangishetty@deccan.ai" \
      -c user.name="dhiren" commit -m "Update extract progress" \
      -- status.json publish_loop.sh >>"$LOG" 2>&1; then
    return 1
  fi

  export GIT_TERMINAL_PROMPT=0
  if ! run_timeout 30 git pull --rebase origin main >>"$LOG" 2>&1; then
    return 1
  fi
  run_timeout 30 git push origin main >>"$LOG" 2>&1
}

acquire_lock || exit 0
echo "$$" >"$PIDFILE"
trap cleanup EXIT INT TERM HUP

while true; do
  publish_once || true
  sleep "$INTERVAL"
done
