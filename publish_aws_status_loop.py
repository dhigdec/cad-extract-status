#!/usr/bin/env python3
"""Local 20s publisher: private EC2 status -> public browser status.json.

SSM SendCommand is denied for this profile, so this laptop loop is the sole
enriching publisher for s3://cad-extract-status-874846752452/status.json.
Does not stop/reboot/terminate EC2. Does not touch rclone. No secrets logged.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import sys
import time
import traceback
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

PROFILE = os.environ.get("AWS_PROFILE", "annotationprod-publish")
REGION = "ap-south-1"
PRIVATE_BUCKET = "annotationprod"
PRIVATE_KEY = "cad-disk-extract/_state/ec2-status.json"
PUBLIC_BUCKET = "cad-extract-status-874846752452"
PUBLIC_KEY = "status.json"
CLAIMS_PREFIX = "cad-disk-extract/_state/ec2-claims/"
RESULTS_PREFIX = "cad-disk-extract/_state/ec2-results/"
# Fleet launched ~06:49 UTC 22 Sep 2026 (ap-south-1)
FLEET_START = dt.datetime(2026, 9, 22, 6, 49, 33, tzinfo=dt.timezone.utc)
INTERVAL = int(os.environ.get("INTERVAL", "20"))
ROOT = Path(__file__).resolve().parent
LOG = ROOT / "publish_aws_status_loop.log"
PIDFILE = ROOT / "publish_aws_status_loop.pid"
LOCKDIR = ROOT / ".publish_aws_status_loop.lock"


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def log(msg: str) -> None:
    line = f"{utc_now()} {msg}"
    print(line, flush=True)
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def s3():
    return boto3.Session(profile_name=PROFILE, region_name=REGION).client("s3")


def count_prefix(client, prefix: str) -> int:
    total = 0
    token = None
    while True:
        kwargs = {
            "Bucket": PRIVATE_BUCKET,
            "Prefix": prefix,
            "MaxKeys": 1000,
        }
        if token:
            kwargs["ContinuationToken"] = token
        resp = client.list_objects_v2(**kwargs)
        total += int(resp.get("KeyCount") or 0)
        if not resp.get("IsTruncated"):
            return total
        token = resp.get("NextContinuationToken")


_COUNT_CACHE = {"claims": 0, "results": 0, "at": 0.0}


def refresh_counts(client, ttl: float = 30.0) -> tuple[int, int]:
    now = time.time()
    if _COUNT_CACHE["at"] and (now - float(_COUNT_CACHE["at"])) < ttl:
        return int(_COUNT_CACHE["claims"]), int(_COUNT_CACHE["results"])
    claims = count_prefix(client, CLAIMS_PREFIX)
    results = count_prefix(client, RESULTS_PREFIX)
    _COUNT_CACHE.update({"claims": claims, "results": results, "at": now})
    return claims, results


def basename_only(value: object) -> str | None:
    if not isinstance(value, str) or not value:
        return None
    clean = value.split("?", 1)[0].replace("\\", "/")
    name = clean.rsplit("/", 1)[-1].strip()
    return name or None


def worker_rows(instance: dict) -> list[dict]:
    rows = []
    workers = instance.get("workers") or {}
    if isinstance(workers, dict):
        items = sorted(workers.items(), key=lambda kv: str(kv[0]))
        for wid, meta in items:
            if not isinstance(meta, dict):
                continue
            rows.append(
                {
                    "worker_id": str(wid),
                    "alive": bool(meta.get("alive")),
                    "state": "running" if meta.get("alive") else "down",
                    "current_archive": basename_only(meta.get("current")),
                    "last_outcome": meta.get("last_outcome"),
                    "ok": meta.get("ok"),
                    "error": meta.get("error"),
                    "skipped": meta.get("skipped"),
                    "band": meta.get("band"),
                    "instance_name": instance.get("name"),
                }
            )
    elif isinstance(workers, list):
        for idx, meta in enumerate(workers):
            if not isinstance(meta, dict):
                continue
            rows.append(
                {
                    "worker_id": str(meta.get("worker_id") or idx),
                    "alive": bool(meta.get("alive", True)),
                    "state": meta.get("state") or "running",
                    "current_archive": basename_only(
                        meta.get("current_archive") or meta.get("current")
                    ),
                    "instance_name": instance.get("name"),
                }
            )
    return rows


def enrich(private: dict, claims: int, results: int) -> dict:
    fleet = private.get("fleet") if isinstance(private.get("fleet"), dict) else {}
    instances = fleet.get("instances") if isinstance(fleet.get("instances"), list) else []
    archives = private.get("archives") if isinstance(private.get("archives"), dict) else {}
    cost_in = private.get("cost_estimate") if isinstance(private.get("cost_estimate"), dict) else {}

    workers_alive = int(fleet.get("workers_alive") or 0)
    workers_configured = int(fleet.get("workers_configured") or 0)
    updated = private.get("updated_at_iso") or utc_now()

    now = dt.datetime.now(dt.timezone.utc)
    uptime_seconds = max(0.0, (now - FLEET_START).total_seconds())
    uptime_hours = uptime_seconds / 3600.0

    hourly = float(cost_in.get("hourly_ec2_plus_ebs_usd") or 0.0)
    if hourly <= 0 and instances:
        hourly = sum(
            float(i.get("compute_hourly_estimate_usd") or 0)
            + float(i.get("ebs_hourly_estimate_usd") or 0)
            for i in instances
            if isinstance(i, dict)
        )
    accrued = round(hourly * uptime_hours, 4)
    hourly = round(hourly, 4)

    compute_hourly = round(
        sum(float(i.get("compute_hourly_estimate_usd") or 0) for i in instances if isinstance(i, dict)),
        4,
    )
    ebs_hourly = round(
        sum(float(i.get("ebs_hourly_estimate_usd") or 0) for i in instances if isinstance(i, dict)),
        4,
    )

    disks = {}
    for disk_name in ("Disk-1", "Disk-2", "combined"):
        src = archives.get(disk_name) if isinstance(archives.get(disk_name), dict) else {}
        done = int(src.get("completed_ok") or src.get("completed_total") or 0)
        total = int(src.get("manifest_total") or 0)
        remaining = int(src.get("remaining") if src.get("remaining") is not None else max(0, total - done))
        disks[disk_name] = {
            "archives": {
                "total": total,
                "done": done,
                "remaining": remaining,
                "failed": int(src.get("failed") or 0),
                "baseline_completed_ok": int(src.get("baseline_completed_ok") or 0),
                "ec2_new_ok": int(src.get("ec2_new_ok") or 0),
                "manifest_total": total,
                "completed_ok": done,
            }
        }

    combined = (disks.get("combined") or {}).get("archives") or {}
    archives_combined = {
        "total": combined.get("total"),
        "done": combined.get("done"),
        "remaining": combined.get("remaining"),
        "failed": combined.get("failed"),
        "baseline_completed_ok": combined.get("baseline_completed_ok"),
        "ec2_new_ok": combined.get("ec2_new_ok"),
    }
    progress = {
        "archives_total": archives_combined.get("total"),
        "done": archives_combined.get("done"),
        "remaining": archives_combined.get("remaining"),
        "failed": archives_combined.get("failed"),
    }

    vms = {}
    public_instances = []
    for inst in instances:
        if not isinstance(inst, dict):
            continue
        name = str(inst.get("name") or inst.get("id") or "unknown")
        ch = float(inst.get("compute_hourly_estimate_usd") or 0)
        eh = float(inst.get("ebs_hourly_estimate_usd") or 0)
        inst_hourly = round(ch + eh, 4)
        inst_accrued = round(inst_hourly * uptime_hours, 4)
        rows = worker_rows(inst)
        entry = {
            "name": name,
            "id": inst.get("id"),
            "type": inst.get("type"),
            "az": inst.get("az"),
            "state": inst.get("state") or "running",
            "workers_alive": inst.get("workers_alive"),
            "workers_configured": inst.get("workers_configured"),
            "compute_hourly_estimate_usd": ch,
            "ebs_hourly_estimate_usd": eh,
        }
        public_instances.append(entry)
        vms[name] = {
            "instance_name": name,
            "instance_id": inst.get("id"),
            "machine_type": inst.get("type"),
            "type": inst.get("type"),
            "zone": inst.get("az"),
            "state": inst.get("state") or "running",
            "workers_alive": inst.get("workers_alive"),
            "workers_expected": inst.get("workers_configured"),
            "worker_count": inst.get("workers_configured"),
            "workers": rows,
            "costs": {
                "hourly_compute_disk_estimate_usd": inst_hourly,
                "accrued_compute_disk_estimate_usd": inst_accrued,
                "estimate_label": "estimate_only_not_aws_bill",
            },
        }

    cost_estimate = {
        "label": "estimate_only_not_aws_bill",
        "currency": "USD",
        "hourly_ec2_plus_ebs_usd": hourly,
        "accrued_ec2_plus_ebs_usd": accrued,
        "fleet_start_utc": FLEET_START.isoformat().replace("+00:00", "Z"),
        "uptime_seconds": round(uptime_seconds, 1),
        "uptime_hours": round(uptime_hours, 4),
        "ec2_hourly_estimate_usd": compute_hourly,
        "gp3_hourly_estimate_usd": ebs_hourly,
        "notes": [
            "Rough on-demand ap-south-1 EC2 + gp3 estimate for this 11-instance fleet",
            "Accrued since fleet launch ~06:49 UTC 22 Sep 2026",
            "Not an AWS invoice; excludes data transfer and S3 request costs",
        ],
    }

    recent = []
    for row in (private.get("recent_ec2_results") or [])[:20]:
        if not isinstance(row, dict):
            continue
        recent.append(
            {
                "instance": row.get("instance"),
                "disk": row.get("disk"),
                "archive": basename_only(row.get("archive")),
                "stored_files": row.get("stored_files"),
                "finished_at": row.get("finished_at"),
            }
        )

    out = {
        "schema": 4,
        "schema_id": "cad-ec2-public-status/v1",
        "source_of_truth": "aws",
        "pipeline": "aws-ec2",
        "region": private.get("region") or REGION,
        "bootstrapping": False,
        "health": "alive" if workers_alive > 0 else "stale",
        "state": "extracting" if workers_alive > 0 else "idle",
        "heartbeat_at": updated,
        "status_last_updated": updated,
        "last_update_iso": updated,
        "updated_at_iso": updated,
        "published_at": utc_now(),
        "publisher": {
            "mode": "local_laptop_loop",
            "interval_seconds": INTERVAL,
            "reason": "ssm_SendCommand_denied",
        },
        "workers_alive": workers_alive,
        "workers_configured": workers_configured,
        "cloud_workers_alive": workers_alive,
        "fleet": {
            "instances": public_instances,
            "workers_alive": workers_alive,
            "workers_configured": workers_configured,
            "instance_count": len(public_instances),
        },
        "vms": vms,
        "archives": {
            name: (disks[name]["archives"] if name in disks else {})
            for name in ("Disk-1", "Disk-2", "combined")
        },
        "disks": disks,
        "archives_combined": archives_combined,
        "progress": progress,
        "skip_count": private.get("skip_count"),
        "skip_policy": private.get("skip_policy"),
        "claims_count": claims,
        "results_count": results,
        "cost_estimate": cost_estimate,
        "costs": {
            "label": "Estimates only; EC2 on-demand + gp3 for this fleet; not an AWS invoice",
            "combined_hourly_compute_disk_usd": hourly,
            "combined_accrued_estimate_usd": accrued,
            "instance_count": len(public_instances),
            "estimate_label": "estimate_only_not_aws_bill",
        },
        "compute": {
            "estimate_label": "Estimate only; aggregate across EC2 fleet, not an AWS invoice",
            "hourly_estimate_usd": compute_hourly,
            "accrued_estimate_usd": round(compute_hourly * uptime_hours, 4),
            "instance_count": len(public_instances),
            "uptime_hours": round(uptime_hours, 4),
            "uptime_seconds": round(uptime_seconds, 1),
            "fleet_start_utc": FLEET_START.isoformat().replace("+00:00", "Z"),
        },
        "persistent_disk": {
            "type": "gp3",
            "estimate_label": "gp3 estimate at ~$0.0912/GB-month ap-south-1",
            "hourly_estimate_usd": ebs_hourly,
            "accrued_estimate_usd": round(ebs_hourly * uptime_hours, 4),
        },
        "gce": {
            "instance_count": len(public_instances),
            "worker_count": workers_alive,
            "state": "extracting" if workers_alive > 0 else "idle",
            "platform": "aws-ec2",
            "region": REGION,
        },
        "recent_ec2_results": recent,
        "ec2_counts_delta": private.get("ec2_counts_delta"),
    }
    return out


def publish_once(client) -> dict:
    obj = client.get_object(Bucket=PRIVATE_BUCKET, Key=PRIVATE_KEY)
    private = json.loads(obj["Body"].read())
    claims, results = refresh_counts(client)
    public = enrich(private, claims, results)
    body = json.dumps(public, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    put_kwargs = {
        "Bucket": PUBLIC_BUCKET,
        "Key": PUBLIC_KEY,
        "Body": body,
        "ContentType": "application/json",
        "CacheControl": "no-store",
    }
    try:
        client.put_object(**put_kwargs, ACL="public-read")
    except ClientError as exc:
        # Bucket may already be public via policy; object write without ACL is fine.
        if exc.response.get("Error", {}).get("Code") in {
            "AccessDenied",
            "AccessControlListNotSupported",
            "InvalidArgument",
        }:
            client.put_object(**put_kwargs)
        else:
            raise
    (ROOT / "status.public.json").write_bytes(body)
    return public


def acquire_lock() -> bool:
    try:
        LOCKDIR.mkdir(exist_ok=False)
        (LOCKDIR / "pid").write_text(str(os.getpid()))
        return True
    except FileExistsError:
        pass
    old = (LOCKDIR / "pid").read_text().strip() if (LOCKDIR / "pid").exists() else ""
    if old.isdigit():
        try:
            os.kill(int(old), 0)
            return False
        except OSError:
            pass
    import shutil

    shutil.rmtree(LOCKDIR, ignore_errors=True)
    LOCKDIR.mkdir()
    (LOCKDIR / "pid").write_text(str(os.getpid()))
    return True


def cleanup() -> None:
    try:
        if PIDFILE.exists() and PIDFILE.read_text().strip() == str(os.getpid()):
            PIDFILE.unlink(missing_ok=True)
    except Exception:
        pass
    try:
        if (LOCKDIR / "pid").exists() and (LOCKDIR / "pid").read_text().strip() == str(os.getpid()):
            import shutil

            shutil.rmtree(LOCKDIR, ignore_errors=True)
    except Exception:
        pass


def main() -> int:
    if not acquire_lock():
        log("another publisher holds the lock; exiting")
        return 0
    PIDFILE.write_text(str(os.getpid()))
    client = s3()
    log(
        f"starting local AWS status publisher interval={INTERVAL}s "
        f"public=s3://{PUBLIC_BUCKET}/{PUBLIC_KEY}"
    )
    while True:
        try:
            public = publish_once(client)
            fleet = public.get("fleet") or {}
            cost = public.get("cost_estimate") or {}
            log(
                "published workers_alive=%s claims=%s results=%s hourly=%s accrued=%s"
                % (
                    fleet.get("workers_alive"),
                    public.get("claims_count"),
                    public.get("results_count"),
                    cost.get("hourly_ec2_plus_ebs_usd"),
                    cost.get("accrued_ec2_plus_ebs_usd"),
                )
            )
        except Exception as exc:
            log(f"publish failed: {type(exc).__name__}: {exc}")
            log(traceback.format_exc().splitlines()[-1])
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        cleanup()
