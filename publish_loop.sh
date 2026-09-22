#!/bin/bash
set -u
cd /tmp/cad-extract-status || exit 1
INTERVAL=20
LOG=/tmp/cad-extract-status/publish_loop.log

ensure_monitor() {
  if curl -sS -m 2 http://127.0.0.1:8765/status.json >/dev/null 2>&1; then
    return 0
  fi
  # Start ONLY the monitor; never touch deep_count.py / supervisor
  nohup python3 /tmp/deep_count/monitor_server.py >> /tmp/deep_count/monitor_server.log 2>&1 </dev/null &
  sleep 1
}

while true; do
  ensure_monitor
  python3 - << 'PY' >>"$LOG" 2>&1
import json, urllib.request, sys
try:
    with urllib.request.urlopen("http://127.0.0.1:8765/status.json", timeout=10) as r:
        st = json.load(r)
except Exception as e:
    print("fetch failed:", e, flush=True)
    sys.exit(1)

totals = st.get("totals") or {}
counts = totals.get("counts")
out = {
    "health": st.get("health"),
    "updated": st.get("last_update_iso"),
    "last_update_iso": st.get("last_update_iso"),
    "age_seconds": st.get("age_seconds"),
    "worker_alive": st.get("worker_alive"),
    "current": st.get("current"),
    "current_archive": st.get("current_archive"),
    "last_finished": st.get("last_finished"),
    "totals": totals,
    "archives": totals.get("archives"),
    "counts": counts,
    "remaining_by_size": st.get("remaining_by_size"),
    "finished_depth_by_size": st.get("finished_depth_by_size"),
    "max_depth_seen": totals.get("max_depth_seen") or st.get("max_depth_seen"),
    "max_depth_cap": totals.get("max_depth_cap") or st.get("max_depth_cap"),
    "depth_cap_hits": totals.get("depth_cap_hits"),
    "s3": st.get("s3") or totals.get("s3") or {},
}
for key in ("s3_stored_bytes", "s3_stored_gb", "estimated_monthly_usd"):
    if key in st and st[key] is not None:
        out[key] = st[key]

with open("/tmp/cad-extract-status/status.json", "w") as fh:
    json.dump(out, fh, indent=2)
    fh.write("\n")
print("updated", out.get("updated"), "health", out.get("health"), flush=True)
PY
  if [ $? -ne 0 ]; then
    sleep "$INTERVAL"
    continue
  fi
  git add status.json
  if ! git diff --cached --quiet; then
    # Sync with any concurrent publisher (e.g. S3 shift worker) before commit/push
    git pull --rebase --autostash origin main >>"$LOG" 2>&1 || true
    git add status.json
    if ! git diff --cached --quiet; then
      git -c user.email="dhiren.gangishetty@deccan.ai" -c user.name="dhiren" commit -m "Update extract progress" >/dev/null
      if ! git push origin main >>"$LOG" 2>&1; then
        git pull --rebase --autostash origin main >>"$LOG" 2>&1 || true
        git push origin main >>"$LOG" 2>&1 || true
      fi
    fi
  fi
  sleep "$INTERVAL"
done
