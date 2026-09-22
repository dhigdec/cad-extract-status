#!/bin/bash
set -u

ROOT=/tmp/cad-extract-status
INTERVAL=20
LOG="$ROOT/publish_loop.log"
PIDFILE="$ROOT/publish_loop.pid"
LOCKDIR="$ROOT/.publish_loop.lock"

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

write_status() {
  python3 - <<'PY'
import json
import os
import urllib.request

root = "/tmp/cad-extract-status"
with urllib.request.urlopen("http://127.0.0.1:8765/status.json", timeout=10) as response:
    status = json.load(response)

totals = status.get("totals") or {}
s3 = status.get("s3") or totals.get("s3") or {}
out = {
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
    "s3": s3,
    "s3_stored_bytes": s3.get("stored_bytes"),
    "s3_stored_gb": s3.get("stored_gb"),
    "estimated_monthly_usd": s3.get("estimated_monthly_usd"),
}

tmp = os.path.join(root, ".status.json.tmp")
with open(tmp, "w") as handle:
    json.dump(out, handle, indent=2)
    handle.write("\n")
os.replace(tmp, os.path.join(root, "status.json"))
PY
}

publish_once() {
  if ! write_status >>"$LOG" 2>&1; then
    echo "$(date -u +%FT%TZ) local status fetch failed" >>"$LOG"
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
