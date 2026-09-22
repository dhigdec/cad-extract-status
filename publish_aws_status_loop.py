#!/usr/bin/env python3
"""Cloud ~20s publisher: private EC2 state -> public browser status.json.

Merges reconciliation baseline + skip-list archive identity + new EC2 results
without double-counting (identity = sha256 of canonical source_key).

Publishes disks.*.counts / counts paths expected by cad-extract-status index.html:
  category.{raw,weak,sha256}, family.by_ext.{ext}.{raw,weak,sha256},
  block.{distinct_blocks,total_block_bytes,unique_block_bytes,duplicate_block_bytes}.

Does not stop/reboot/terminate EC2. Does not touch rclone. No secrets logged.
"""
from __future__ import annotations

import datetime as dt
import json
import os
import threading
import time
import traceback
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import boto3
from botocore.exceptions import ClientError

REGION = "ap-south-1"
PRIVATE_BUCKET = "annotationprod"
PRIVATE_KEY = "cad-disk-extract/_state/ec2-status.json"
PUBLIC_BUCKET = "cad-extract-status-874846752452"
PUBLIC_KEY = "status.json"
CLAIMS_PREFIX = "cad-disk-extract/_state/ec2-claims/"
RESULTS_PREFIX = "cad-disk-extract/_state/ec2-results/"
LEGACY_RESULTS_PREFIX = "cad-disk-extract/_state/results/"
SKIP_KEY = "cad-disk-extract/_control/ec2-skip-done.json"
RECON_SUMMARY_KEY = "cad-disk-extract/_state/reconciliation/summary.json"
MERGE_RULES_KEY = "cad-disk-extract/_control/final-merge-rules.json"

FLEET_START = dt.datetime(2026, 9, 22, 6, 49, 33, tzinfo=dt.timezone.utc)
INTERVAL = int(os.environ.get("INTERVAL", "20"))
ROOT = Path(os.environ.get("CAD_STATUS_ROOT", str(Path(__file__).resolve().parent)))
LOG = ROOT / "publish_aws_status_loop.log"
PIDFILE = ROOT / "publish_aws_status_loop.pid"
LOCKDIR = ROOT / ".publish_aws_status_loop.lock"
CACHE_DIR = ROOT / ".status_cache"
BASELINE_CACHE = CACHE_DIR / "historical_baseline.json"
BASELINE_SCHEMA = "historical-baseline/v2-assets"

RAW_KEYS = ("pdf", "cad_pdf", "other_pdf", "2d", "3d", "nc1")
DISKS = ("Disk-1", "Disk-2", "combined")
MANIFEST_TOTAL = {"Disk-1": 1154, "Disk-2": 2466, "combined": 3620}
EXT_2D = (".dxf", ".dwg", ".dg", ".dpm")
EXT_3D = (".stp", ".step", ".ifc", ".db1", ".sat", ".obj", ".stl", ".gltf", ".glb")
ALL_EXTS = (".pdf",) + EXT_2D + EXT_3D + (".nc1",)
FAMILY_OF = {
    ".pdf": "pdf",
    ".dxf": "2d",
    ".dwg": "2d",
    ".dg": "2d",
    ".dpm": "2d",
    ".stp": "3d",
    ".step": "3d",
    ".ifc": "3d",
    ".db1": "3d",
    ".sat": "3d",
    ".obj": "3d",
    ".stl": "3d",
    ".gltf": "3d",
    ".glb": "3d",
    ".nc1": "nc1",
}


def utc_now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat().replace("+00:00", "Z")


def log(msg: str) -> None:
    line = f"{utc_now()} {msg}"
    print(line, flush=True)
    with LOG.open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")


def s3():
    return boto3.Session(region_name=REGION).client("s3")


def get_json(client, key: str):
    body = client.get_object(Bucket=PRIVATE_BUCKET, Key=key)["Body"].read()
    return json.loads(body)


def put_json(client, bucket: str, key: str, doc: dict, public: bool = False) -> None:
    body = json.dumps(doc, separators=(",", ":"), ensure_ascii=True).encode("utf-8")
    kwargs = {
        "Bucket": bucket,
        "Key": key,
        "Body": body,
        "ContentType": "application/json",
        "CacheControl": "no-store",
    }
    if public:
        try:
            client.put_object(**kwargs, ACL="public-read")
            return
        except ClientError as exc:
            code = exc.response.get("Error", {}).get("Code")
            if code not in {"AccessDenied", "AccessControlListNotSupported", "InvalidArgument"}:
                raise
    client.put_object(**kwargs)


def list_keys(client, prefix: str) -> list[str]:
    keys: list[str] = []
    token = None
    while True:
        kwargs = {"Bucket": PRIVATE_BUCKET, "Prefix": prefix, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        resp = client.list_objects_v2(**kwargs)
        for item in resp.get("Contents") or []:
            key = item["Key"]
            if key.endswith(".json"):
                keys.append(key)
        if not resp.get("IsTruncated"):
            return keys
        token = resp.get("NextContinuationToken")


def count_prefix(client, prefix: str) -> int:
    total = 0
    token = None
    while True:
        kwargs = {"Bucket": PRIVATE_BUCKET, "Prefix": prefix, "MaxKeys": 1000}
        if token:
            kwargs["ContinuationToken"] = token
        resp = client.list_objects_v2(**kwargs)
        total += int(resp.get("KeyCount") or 0)
        if not resp.get("IsTruncated"):
            return total
        token = resp.get("NextContinuationToken")


def empty_raw() -> dict:
    return {k: 0 for k in RAW_KEYS}


def empty_ext() -> dict:
    return {ext: 0 for ext in ALL_EXTS}


def add_raw(dst: dict, src: dict | None) -> None:
    if not isinstance(src, dict):
        return
    for key in RAW_KEYS:
        dst[key] = int(dst.get(key) or 0) + int(src.get(key) or 0)


def add_ext(dst: dict, src: dict | None) -> None:
    if not isinstance(src, dict):
        return
    for ext, value in src.items():
        if not isinstance(ext, str):
            continue
        name = ext if ext.startswith(".") else f".{ext}"
        name = name.lower()
        if name not in dst:
            continue
        if isinstance(value, dict):
            dst[name] = int(dst.get(name) or 0) + int(value.get("raw") or 0)
        else:
            try:
                dst[name] = int(dst.get(name) or 0) + int(value or 0)
            except (TypeError, ValueError):
                continue


def metric_node(
    raw: int | None,
    weak: int | None,
    sha256: int | None,
    *,
    weak_status: str | None = None,
    sha_status: str | None = None,
) -> dict:
    node: dict = {}
    if raw is not None:
        node["raw"] = int(raw)
    if weak is None:
        node["weak"] = None
        if weak_status:
            node["weak_status"] = weak_status
    else:
        node["weak"] = int(weak)
        if weak_status:
            node["weak_status"] = weak_status
    if sha256 is None:
        node["sha256"] = None
        if sha_status:
            node["sha256_status"] = sha_status
    else:
        node["sha256"] = int(sha256)
        if sha_status:
            node["sha256_status"] = sha_status
    return node


def load_skip(client) -> dict:
    skip = get_json(client, SKIP_KEY)
    by_disk = {"Disk-1": 0, "Disk-2": 0}
    ids: set[str] = set()
    results_only: list[dict] = []
    for row in skip.get("archives") or []:
        if not isinstance(row, dict):
            continue
        digest = str(row.get("sha256") or "")
        if not digest:
            continue
        ids.add(digest)
        disk = row.get("disk") if row.get("disk") in ("Disk-1", "Disk-2") else None
        if disk:
            by_disk[disk] += 1
        if row.get("provenance") == "results":
            results_only.append(
                {
                    "sha256": digest,
                    "disk": disk or "Disk-1",
                    "result_key": row.get("result_key")
                    or f"_state/results/{digest}.json",
                }
            )
    return {
        "skip_count": int(skip.get("skip_count") or len(ids)),
        "ids": ids,
        "by_disk": by_disk,
        "results_only": results_only,
        "created_at_utc": skip.get("created_at_utc"),
        "identity": skip.get("identity"),
    }


def fetch_result_payload(client, result_key: str) -> tuple[str | None, dict]:
    key = result_key
    if key.startswith("_state/"):
        key = f"cad-disk-extract/{key}"
    try:
        doc = get_json(client, key)
    except Exception:
        return None, {}
    digest = doc.get("source_key_sha256") or Path(key).stem
    raw = doc.get("raw") if isinstance(doc.get("raw"), dict) else {}
    extensions = doc.get("extensions") if isinstance(doc.get("extensions"), dict) else {}
    block_bytes = int(doc.get("block_bytes") or 0)
    return (str(digest) if digest else None), {
        "raw": raw,
        "extensions": extensions,
        "block_bytes": block_bytes,
        "pdf_classes": doc.get("pdf_classes") if isinstance(doc.get("pdf_classes"), dict) else {},
    }


def recon_assets(summary: dict) -> dict:
    disks_out = {
        d: {
            "raw": empty_raw(),
            "extensions": empty_ext(),
            "weak": empty_raw(),
            "sha256": empty_raw(),
            "weak_by_ext": empty_ext(),
            "sha_by_ext": empty_ext(),
            "pdf_classes": {},
        }
        for d in ("Disk-1", "Disk-2")
    }
    disks = summary.get("disks") or {}
    for disk in ("Disk-1", "Disk-2"):
        src = disks.get(disk) or {}
        add_raw(disks_out[disk]["raw"], src.get("raw") if isinstance(src.get("raw"), dict) else {})
        add_ext(
            disks_out[disk]["extensions"],
            src.get("extensions") if isinstance(src.get("extensions"), dict) else {},
        )
        classes = src.get("pdf_classes") if isinstance(src.get("pdf_classes"), dict) else {}
        disks_out[disk]["pdf_classes"] = {k: int(v or 0) for k, v in classes.items()}

    dedup = summary.get("dedup") or {}
    weak_by = ((dedup.get("weak_name_size") or {}).get("by_disk")) or {}
    sha_by = ((dedup.get("sha256") or {}).get("by_disk")) or {}
    for disk in ("Disk-1", "Disk-2"):
        w = weak_by.get(disk) or {}
        s = sha_by.get(disk) or {}
        for key in RAW_KEYS:
            if key in w:
                disks_out[disk]["weak"][key] = int(w.get(key) or 0)
            if key in s:
                disks_out[disk]["sha256"][key] = int(s.get(key) or 0)
        for ext, val in (w.get("by_extension") or {}).items():
            name = ext if str(ext).startswith(".") else f".{ext}"
            if name in disks_out[disk]["weak_by_ext"]:
                disks_out[disk]["weak_by_ext"][name] = int(val or 0)
        for ext, val in (s.get("by_extension") or {}).items():
            name = ext if str(ext).startswith(".") else f".{ext}"
            if name in disks_out[disk]["sha_by_ext"]:
                disks_out[disk]["sha_by_ext"][name] = int(val or 0)

    # Prefer recon combined exact unions when present.
    weak_combined = (dedup.get("weak_name_size") or {}).get("combined") or {}
    sha_combined = (dedup.get("sha256") or {}).get("combined") or {}
    combined_raw = empty_raw()
    combined_ext = empty_ext()
    combined_weak = empty_raw()
    combined_sha = empty_raw()
    combined_weak_ext = empty_ext()
    combined_sha_ext = empty_ext()
    combined_classes: dict[str, int] = {}
    for disk in ("Disk-1", "Disk-2"):
        add_raw(combined_raw, disks_out[disk]["raw"])
        add_ext(combined_ext, disks_out[disk]["extensions"])
        for k, v in disks_out[disk]["pdf_classes"].items():
            combined_classes[k] = int(combined_classes.get(k) or 0) + int(v or 0)
    for key in RAW_KEYS:
        if key in weak_combined:
            combined_weak[key] = int(weak_combined.get(key) or 0)
        else:
            combined_weak[key] = disks_out["Disk-1"]["weak"][key] + disks_out["Disk-2"]["weak"][key]
        if key in sha_combined:
            combined_sha[key] = int(sha_combined.get(key) or 0)
        else:
            combined_sha[key] = disks_out["Disk-1"]["sha256"][key] + disks_out["Disk-2"]["sha256"][key]
    for ext, val in (weak_combined.get("by_extension") or {}).items():
        name = ext if str(ext).startswith(".") else f".{ext}"
        if name in combined_weak_ext:
            combined_weak_ext[name] = int(val or 0)
    for ext, val in (sha_combined.get("by_extension") or {}).items():
        name = ext if str(ext).startswith(".") else f".{ext}"
        if name in combined_sha_ext:
            combined_sha_ext[name] = int(val or 0)
    if not any(combined_weak_ext.values()):
        for disk in ("Disk-1", "Disk-2"):
            add_ext(combined_weak_ext, disks_out[disk]["weak_by_ext"])
    if not any(combined_sha_ext.values()):
        for disk in ("Disk-1", "Disk-2"):
            add_ext(combined_sha_ext, disks_out[disk]["sha_by_ext"])

    disks_out["combined"] = {
        "raw": combined_raw,
        "extensions": combined_ext,
        "weak": combined_weak,
        "sha256": combined_sha,
        "weak_by_ext": combined_weak_ext,
        "sha_by_ext": combined_sha_ext,
        "pdf_classes": combined_classes,
    }

    block = dedup.get("block") or {}
    block_out = {
        "Disk-1": {
            "distinct_blocks": (block.get("distinct_hashes_by_disk") or {}).get("Disk-1"),
            "total_block_bytes": (block.get("total_hashed_bytes_by_disk") or {}).get("Disk-1"),
            "unique_block_bytes": None,
            "duplicate_block_bytes": None,
        },
        "Disk-2": {
            "distinct_blocks": (block.get("distinct_hashes_by_disk") or {}).get("Disk-2"),
            "total_block_bytes": (block.get("total_hashed_bytes_by_disk") or {}).get("Disk-2"),
            "unique_block_bytes": None,
            "duplicate_block_bytes": None,
        },
        "combined": {
            "distinct_blocks": block.get("distinct_hashes_combined"),
            "total_block_bytes": block.get("total_hashed_bytes_combined"),
            "unique_block_bytes": None,
            "duplicate_block_bytes": block.get("duplicate_bytes"),
        },
    }
    return {
        "assets": disks_out,
        "block": block_out,
        "block_meta": {
            "distinct_hashes_status": block.get("distinct_hashes_status"),
            "duplicate_bytes_status": block.get("duplicate_bytes_status"),
            "reason": block.get("reason"),
            "completed_archives": block.get("completed_archives"),
        },
        "weak_meta": {
            "status": (dedup.get("weak_name_size") or {}).get("status"),
            "reason": (dedup.get("weak_name_size") or {}).get("reason"),
            "completed_archives": (dedup.get("weak_name_size") or {}).get("completed_archives"),
            "pdf_subtype_scope": (dedup.get("weak_name_size") or {}).get("pdf_subtype_scope"),
        },
        "sha_meta": {
            "status": (dedup.get("sha256") or {}).get("status"),
            "reason": (dedup.get("sha256") or {}).get("reason"),
            "completed_archives": (dedup.get("sha256") or {}).get("completed_archives"),
        },
    }


def build_historical_baseline(client) -> dict:
    CACHE_DIR.mkdir(exist_ok=True)
    if BASELINE_CACHE.exists():
        try:
            cached = json.loads(BASELINE_CACHE.read_text())
            age = time.time() - float(cached.get("built_at_epoch") or 0)
            if age < 3600 and cached.get("schema") == BASELINE_SCHEMA:
                log(f"using cached historical baseline age_s={int(age)}")
                cached["ids"] = set(cached.get("ids_list") or [])
                return cached
        except Exception:
            pass

    log("building historical baseline v2 from skip + reconciliation + results_only")
    skip = load_skip(client)
    summary = get_json(client, RECON_SUMMARY_KEY)
    recon = recon_assets(summary)

    results_only_raw = {d: empty_raw() for d in ("Disk-1", "Disk-2")}
    results_only_ext = {d: empty_ext() for d in ("Disk-1", "Disk-2")}
    results_only_block_bytes = {"Disk-1": 0, "Disk-2": 0}
    results_only_classes = {"Disk-1": {}, "Disk-2": {}}
    fetched = 0
    failed = 0

    def one(row: dict):
        return row["disk"], fetch_result_payload(client, row["result_key"])

    with ThreadPoolExecutor(max_workers=16) as pool:
        futures = [pool.submit(one, row) for row in skip["results_only"]]
        for fut in as_completed(futures):
            disk, (digest, payload) = fut.result()
            if not payload:
                failed += 1
                continue
            if digest and digest not in skip["ids"]:
                failed += 1
                continue
            add_raw(results_only_raw[disk], payload.get("raw"))
            add_ext(results_only_ext[disk], payload.get("extensions"))
            results_only_block_bytes[disk] += int(payload.get("block_bytes") or 0)
            for k, v in (payload.get("pdf_classes") or {}).items():
                results_only_classes[disk][k] = int(results_only_classes[disk].get(k) or 0) + int(v or 0)
            fetched += 1

    historical_raw = {"Disk-1": empty_raw(), "Disk-2": empty_raw()}
    historical_ext = {"Disk-1": empty_ext(), "Disk-2": empty_ext()}
    historical_classes = {"Disk-1": {}, "Disk-2": {}}
    for disk in ("Disk-1", "Disk-2"):
        add_raw(historical_raw[disk], recon["assets"][disk]["raw"])
        add_raw(historical_raw[disk], results_only_raw[disk])
        add_ext(historical_ext[disk], recon["assets"][disk]["extensions"])
        add_ext(historical_ext[disk], results_only_ext[disk])
        classes = dict(recon["assets"][disk]["pdf_classes"])
        for k, v in results_only_classes[disk].items():
            classes[k] = int(classes.get(k) or 0) + int(v or 0)
        historical_classes[disk] = classes

    combined_raw = empty_raw()
    combined_ext = empty_ext()
    combined_classes: dict[str, int] = {}
    for disk in ("Disk-1", "Disk-2"):
        add_raw(combined_raw, historical_raw[disk])
        add_ext(combined_ext, historical_ext[disk])
        for k, v in historical_classes[disk].items():
            combined_classes[k] = int(combined_classes.get(k) or 0) + int(v or 0)
    historical_raw["combined"] = combined_raw
    historical_ext["combined"] = combined_ext
    historical_classes["combined"] = combined_classes

    block = recon["block"]
    for disk in ("Disk-1", "Disk-2"):
        total = block[disk].get("total_block_bytes")
        extra = results_only_block_bytes[disk]
        if total is None and extra:
            block[disk]["total_block_bytes"] = extra
        elif total is not None:
            block[disk]["total_block_bytes"] = int(total) + int(extra)
    c_total = block["combined"].get("total_block_bytes")
    c_extra = results_only_block_bytes["Disk-1"] + results_only_block_bytes["Disk-2"]
    if c_total is None and c_extra:
        block["combined"]["total_block_bytes"] = c_extra
    elif c_total is not None:
        block["combined"]["total_block_bytes"] = int(c_total) + int(c_extra)

    baseline_archives = {
        "Disk-1": int(skip["by_disk"]["Disk-1"]),
        "Disk-2": int(skip["by_disk"]["Disk-2"]),
        "combined": int(skip["skip_count"]),
    }

    out = {
        "schema": BASELINE_SCHEMA,
        "built_at": utc_now(),
        "built_at_epoch": time.time(),
        "skip_count": skip["skip_count"],
        "identity": skip["identity"]
        or "SHA-256 hex digest of the exact canonical source_key",
        "ids_list": sorted(skip["ids"]),
        "baseline_archives": baseline_archives,
        "historical_raw": historical_raw,
        "historical_extensions": historical_ext,
        "historical_pdf_classes": historical_classes,
        "recon_weak": {d: recon["assets"][d]["weak"] for d in DISKS},
        "recon_sha256": {d: recon["assets"][d]["sha256"] for d in DISKS},
        "recon_weak_by_ext": {d: recon["assets"][d]["weak_by_ext"] for d in DISKS},
        "recon_sha_by_ext": {d: recon["assets"][d]["sha_by_ext"] for d in DISKS},
        "recon_block": block,
        "weak_meta": recon["weak_meta"],
        "sha_meta": recon["sha_meta"],
        "block_meta": recon["block_meta"],
        "recon_archives_done": int(
            (((summary.get("combined") or {}).get("archives") or {}).get("done")) or 1956
        ),
        "results_only_added": len(skip["results_only"]),
        "results_only_fetched": fetched,
        "results_only_failed": failed,
        "results_only_raw": results_only_raw,
        "results_only_extensions": results_only_ext,
        "results_only_block_bytes": results_only_block_bytes,
        "notes": [
            "Archive done baseline = UNION skip list (ledger done + _state/results ok).",
            "Raw/extension totals = reconciliation summary + results_only raw + new EC2 raw.",
            "Weak/SHA-256/block-distinct values are exact for the reconciliation 1956-archive set.",
            "results_only + new EC2 weak/SHA/block-hash global unions stay pending (recon hash sets not retained in summary).",
            "duplicate/unique block bytes pending: result schemas lack per-occurrence block lengths.",
        ],
    }
    serializable = dict(out)
    BASELINE_CACHE.write_text(json.dumps(serializable))
    out["ids"] = set(out["ids_list"])
    log(
        "baseline ready skip=%s d1=%s d2=%s results_only_fetched=%s failed=%s pdf_raw_combined=%s"
        % (
            out["skip_count"],
            baseline_archives["Disk-1"],
            baseline_archives["Disk-2"],
            fetched,
            failed,
            historical_raw["combined"]["pdf"],
        )
    )
    return out


_COUNT_CACHE = {"claims": 0, "results": 0, "at": 0.0}
_EC2_CACHE = {"keys": set(), "by_disk": {}, "raw": {}, "extensions": {}, "block_bytes": {}, "pdf_classes": {}, "recent": [], "at": 0.0}
_BASELINE = None
_BASELINE_LOCK = threading.Lock()


def get_baseline(client) -> dict:
    global _BASELINE
    with _BASELINE_LOCK:
        if _BASELINE is None:
            _BASELINE = build_historical_baseline(client)
        return _BASELINE


def refresh_counts(client, ttl: float = 30.0) -> tuple[int, int]:
    now = time.time()
    if _COUNT_CACHE["at"] and (now - float(_COUNT_CACHE["at"])) < ttl:
        return int(_COUNT_CACHE["claims"]), int(_COUNT_CACHE["results"])
    claims = count_prefix(client, CLAIMS_PREFIX)
    results = count_prefix(client, RESULTS_PREFIX)
    _COUNT_CACHE.update({"claims": claims, "results": results, "at": now})
    return claims, results


def refresh_ec2_new(client, skip_ids: set[str], private: dict | None = None, ttl: float = 15.0) -> dict:
    """New EC2 ok counts by disk, excluding skip-list identities.

    Fast path: when result key stems have zero overlap with the skip set, trust
    private aggregator ec2_new_ok + ec2_counts_delta (workers never re-extract
    skip-list archives). Avoids downloading multi-MB result bodies every 20s.
    """
    now = time.time()
    keys = set(list_keys(client, RESULTS_PREFIX))
    if (
        _EC2_CACHE["at"]
        and (now - float(_EC2_CACHE["at"])) < ttl
        and keys == _EC2_CACHE.get("keys")
    ):
        return _EC2_CACHE

    stems = {Path(k).stem for k in keys}
    skipped_overlap = sum(1 for s in stems if s in skip_ids)
    private = private if isinstance(private, dict) else {}
    priv_arch = private.get("archives") if isinstance(private.get("archives"), dict) else {}
    priv_delta = private.get("ec2_counts_delta") if isinstance(private.get("ec2_counts_delta"), dict) else {}

    by_disk = {"Disk-1": 0, "Disk-2": 0, "combined": 0}
    raw = {"Disk-1": empty_raw(), "Disk-2": empty_raw(), "combined": empty_raw()}
    extensions = {"Disk-1": empty_ext(), "Disk-2": empty_ext(), "combined": empty_ext()}
    block_bytes = {"Disk-1": 0, "Disk-2": 0, "combined": 0}
    pdf_classes = {"Disk-1": {}, "Disk-2": {}, "combined": {}}
    recent = []
    ok = 0
    failed = 0

    use_fast = skipped_overlap == 0 and bool(priv_arch)
    if use_fast:
        for disk in ("Disk-1", "Disk-2"):
            by_disk[disk] = int((priv_arch.get(disk) or {}).get("ec2_new_ok") or 0)
            add_raw(raw[disk], priv_delta.get(disk) if isinstance(priv_delta.get(disk), dict) else {})
        by_disk["combined"] = by_disk["Disk-1"] + by_disk["Disk-2"]
        add_raw(raw["combined"], raw["Disk-1"])
        add_raw(raw["combined"], raw["Disk-2"])
        ok = by_disk["combined"]
        failed = int((priv_arch.get("combined") or {}).get("ec2_failed") or 0)
        for row in (private.get("recent_ec2_results") or [])[:20]:
            if isinstance(row, dict):
                recent.append(row)
    else:
        by_disk = {"Disk-1": 0, "Disk-2": 0}
        raw = {"Disk-1": empty_raw(), "Disk-2": empty_raw()}
        extensions = {"Disk-1": empty_ext(), "Disk-2": empty_ext()}
        block_bytes = {"Disk-1": 0, "Disk-2": 0}
        pdf_classes = {"Disk-1": {}, "Disk-2": {}}

        def load(key: str):
            try:
                return key, get_json(client, key)
            except Exception as exc:
                return key, {"_error": str(exc)}

        with ThreadPoolExecutor(max_workers=12) as pool:
            for key, doc in pool.map(load, sorted(keys)):
                if not isinstance(doc, dict) or doc.get("_error"):
                    failed += 1
                    continue
                digest = str(doc.get("source_key_sha256") or Path(key).stem)
                if digest in skip_ids:
                    continue
                if doc.get("status") != "ok":
                    if doc.get("status") == "error":
                        failed += 1
                    continue
                disk = doc.get("disk") if doc.get("disk") in ("Disk-1", "Disk-2") else "Disk-1"
                by_disk[disk] += 1
                ok += 1
                add_raw(raw[disk], doc.get("raw") if isinstance(doc.get("raw"), dict) else {})
                add_ext(extensions[disk], doc.get("extensions") if isinstance(doc.get("extensions"), dict) else {})
                block_bytes[disk] += int(doc.get("block_bytes") or 0)
                for ck, cv in (doc.get("pdf_classes") or {}).items():
                    pdf_classes[disk][ck] = int(pdf_classes[disk].get(ck) or 0) + int(cv or 0)
                recent.append(
                    {
                        "instance": doc.get("instance_name"),
                        "disk": disk,
                        "archive": Path(str(doc.get("source_key") or "")).name,
                        "stored_files": doc.get("stored_files"),
                        "finished_at": doc.get("finished_at"),
                        "source_key_sha256": digest,
                    }
                )

        recent.sort(key=lambda r: r.get("finished_at") or "", reverse=True)
        combined_raw = empty_raw()
        combined_ext = empty_ext()
        combined_classes: dict[str, int] = {}
        for disk in ("Disk-1", "Disk-2"):
            add_raw(combined_raw, raw[disk])
            add_ext(combined_ext, extensions[disk])
            for k, v in pdf_classes[disk].items():
                combined_classes[k] = int(combined_classes.get(k) or 0) + int(v or 0)
        raw["combined"] = combined_raw
        extensions["combined"] = combined_ext
        pdf_classes["combined"] = combined_classes
        block_bytes["combined"] = block_bytes["Disk-1"] + block_bytes["Disk-2"]
        by_disk["combined"] = by_disk["Disk-1"] + by_disk["Disk-2"]

    _EC2_CACHE.update(
        {
            "keys": keys,
            "by_disk": by_disk,
            "raw": raw,
            "extensions": extensions,
            "block_bytes": block_bytes,
            "pdf_classes": pdf_classes,
            "recent": recent[:20],
            "ok": ok,
            "failed": failed,
            "skipped_overlap": skipped_overlap,
            "fast_path": use_fast,
            "at": now,
        }
    )
    return _EC2_CACHE


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
    return rows


def build_counts(baseline: dict, ec2: dict) -> tuple[dict, dict]:
    pending_reasons: dict[str, str] = {}
    weak_status = "exact_reconciliation_1956_archives_only"
    sha_status = "exact_reconciliation_1956_archives_only"
    pending_reasons["weak_name_size"] = (
        "Published weak counts are exact for the reconciliation 1956-archive set only. "
        "results_only + new EC2 archives lack a global re-union because reconciliation "
        "summary retains exact counts but not weak-key sets."
    )
    pending_reasons["sha256_post_baseline"] = (
        "Published SHA-256 distinct counts are exact for the reconciliation 1956-archive set only. "
        "results_only + new EC2 sha256 lists are not unioned into these cells without recon hash sets."
    )
    pending_reasons["duplicate_block_bytes"] = (
        baseline.get("block_meta", {}).get("reason")
        or "cloud/result schemas retain distinct block hashes but not every block occurrence length"
    )
    pending_reasons["unique_block_bytes"] = (
        "Cannot derive unique block bytes without exact duplicate block bytes"
    )

    out = {}
    for disk in DISKS:
        hist_raw = (baseline.get("historical_raw") or {}).get(disk) or empty_raw()
        ec2_raw = (ec2.get("raw") or {}).get(disk) or empty_raw()
        hist_ext = (baseline.get("historical_extensions") or {}).get(disk) or empty_ext()
        ec2_ext = (ec2.get("extensions") or {}).get(disk) or empty_ext()
        weak = (baseline.get("recon_weak") or {}).get(disk) or empty_raw()
        sha = (baseline.get("recon_sha256") or {}).get(disk) or empty_raw()
        weak_ext = (baseline.get("recon_weak_by_ext") or {}).get(disk) or empty_ext()
        sha_ext = (baseline.get("recon_sha_by_ext") or {}).get(disk) or empty_ext()
        classes = dict((baseline.get("historical_pdf_classes") or {}).get(disk) or {})
        for k, v in ((ec2.get("pdf_classes") or {}).get(disk) or {}).items():
            classes[k] = int(classes.get(k) or 0) + int(v or 0)

        cats: dict = {}
        for key in RAW_KEYS:
            raw_total = int(hist_raw.get(key) or 0) + int(ec2_raw.get(key) or 0)
            cats[key] = metric_node(
                raw_total,
                int(weak.get(key) or 0),
                int(sha.get(key) or 0),
                weak_status=weak_status,
                sha_status=sha_status,
            )
            if key == "other_pdf":
                cats[key]["label"] = "non_cad_pdf"

        # Extension breakdown under family nodes (HTML extensionValue path).
        by_ext_2d = {}
        for ext in EXT_2D:
            by_ext_2d[ext] = metric_node(
                int(hist_ext.get(ext) or 0) + int(ec2_ext.get(ext) or 0),
                int(weak_ext.get(ext) or 0),
                int(sha_ext.get(ext) or 0),
                weak_status=weak_status,
                sha_status=sha_status,
            )
        by_ext_3d = {}
        for ext in EXT_3D:
            by_ext_3d[ext] = metric_node(
                int(hist_ext.get(ext) or 0) + int(ec2_ext.get(ext) or 0),
                int(weak_ext.get(ext) or 0),
                int(sha_ext.get(ext) or 0),
                weak_status=weak_status,
                sha_status=sha_status,
            )
        cats["2d"]["by_ext"] = by_ext_2d
        cats["3d"]["by_ext"] = by_ext_3d
        cats["pdf"]["by_ext"] = {
            ".pdf": metric_node(
                int(hist_ext.get(".pdf") or 0) + int(ec2_ext.get(".pdf") or 0),
                int(weak_ext.get(".pdf") or 0),
                int(sha_ext.get(".pdf") or 0),
                weak_status=weak_status,
                sha_status=sha_status,
            )
        }
        cats["nc1"]["by_ext"] = {
            ".nc1": metric_node(
                int(hist_ext.get(".nc1") or 0) + int(ec2_ext.get(".nc1") or 0),
                int(weak_ext.get(".nc1") or 0),
                int(sha_ext.get(".nc1") or 0),
                weak_status=weak_status,
                sha_status=sha_status,
            )
        }

        cats["pdf_cad_binary"] = {
            "cad_pdf": cats["cad_pdf"],
            "other_pdf": cats["other_pdf"],
        }
        cats["pdf_by_drawing_type"] = {
            name: {"raw": int(val or 0)} for name, val in sorted(classes.items())
        }

        block_src = ((baseline.get("recon_block") or {}).get(disk) or {})
        total_bytes = block_src.get("total_block_bytes")
        ec2_bytes = int(((ec2.get("block_bytes") or {}).get(disk)) or 0)
        if total_bytes is None:
            total_bytes = ec2_bytes if ec2_bytes else None
        else:
            total_bytes = int(total_bytes) + ec2_bytes
        distinct = block_src.get("distinct_blocks")
        cats["block"] = {
            "distinct_blocks": int(distinct) if distinct is not None else None,
            "block_sha256": int(distinct) if distinct is not None else None,
            "total_block_bytes": int(total_bytes) if total_bytes is not None else None,
            "unique_block_bytes": None,
            "duplicate_block_bytes": None,
            "distinct_status": "exact_reconciliation_1956_archives_only"
            if distinct is not None
            else "pending",
            "duplicate_status": "pending",
            "unique_status": "pending",
        }
        out[disk] = cats

    return out, pending_reasons


def enrich(private: dict, claims: int, results: int, baseline: dict, ec2: dict) -> dict:
    fleet = private.get("fleet") if isinstance(private.get("fleet"), dict) else {}
    instances = fleet.get("instances") if isinstance(fleet.get("instances"), list) else []
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
    if hourly <= 0:
        hourly = 43.1659
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

    base_arch = baseline["baseline_archives"]
    ec2_by = ec2["by_disk"]
    disks = {}
    for disk in DISKS:
        base_done = int(base_arch[disk])
        ec2_new = int(ec2_by.get(disk) or 0)
        total = MANIFEST_TOTAL[disk]
        done = base_done + ec2_new
        disks[disk] = {
            "archives": {
                "total": total,
                "done": done,
                "remaining": max(0, total - done),
                "failed": 0,
                "baseline_completed_ok": base_done,
                "ec2_new_ok": ec2_new,
                "manifest_total": total,
                "completed_ok": done,
                "done_before_gcp": base_done,
                "done_on_gcp": 0,
            },
            "counts": None,
            "baseline": {
                "finished_archives": base_done,
                "raw_counts_included": True,
                "scope": "skip-list UNION (ledger done + _state/results ok); raw from recon + results_only",
                "identity": baseline.get("identity"),
            },
            "ec2_new": {
                "finished_archives": ec2_new,
                "raw_counts_included": True,
                "scope": "ec2-results whose source_key sha256 is NOT in skip-list",
                "skipped_overlap": int(ec2.get("skipped_overlap") or 0),
            },
        }

    counts, pending_reasons = build_counts(baseline, ec2)
    for disk in DISKS:
        disks[disk]["counts"] = counts[disk]

    archives = {disk: disks[disk]["archives"] for disk in DISKS}
    # Guard: per-disk done must sum to combined done.
    d1 = archives["Disk-1"]["done"]
    d2 = archives["Disk-2"]["done"]
    if d1 + d2 != archives["combined"]["done"]:
        archives["combined"]["done"] = d1 + d2
        archives["combined"]["completed_ok"] = d1 + d2
        archives["combined"]["remaining"] = max(0, MANIFEST_TOTAL["combined"] - (d1 + d2))
        archives["combined"]["baseline_completed_ok"] = (
            archives["Disk-1"]["baseline_completed_ok"] + archives["Disk-2"]["baseline_completed_ok"]
        )
        archives["combined"]["ec2_new_ok"] = (
            archives["Disk-1"]["ec2_new_ok"] + archives["Disk-2"]["ec2_new_ok"]
        )
        disks["combined"]["archives"] = archives["combined"]

    combined = archives["combined"]
    progress = {
        "archives_total": combined["total"],
        "done": combined["done"],
        "remaining": combined["remaining"],
        "failed": 0,
        "done_before_gcp": combined["baseline_completed_ok"],
        "by_disk": {
            "Disk-1": {
                "archives_total": archives["Disk-1"]["total"],
                "done": archives["Disk-1"]["done"],
                "remaining": archives["Disk-1"]["remaining"],
                "baseline_completed_ok": archives["Disk-1"]["baseline_completed_ok"],
                "ec2_new_ok": archives["Disk-1"]["ec2_new_ok"],
            },
            "Disk-2": {
                "archives_total": archives["Disk-2"]["total"],
                "done": archives["Disk-2"]["done"],
                "remaining": archives["Disk-2"]["remaining"],
                "baseline_completed_ok": archives["Disk-2"]["baseline_completed_ok"],
                "ec2_new_ok": archives["Disk-2"]["ec2_new_ok"],
            },
        },
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
                "accrued_compute_disk_estimate_usd": round(inst_hourly * uptime_hours, 4),
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

    return {
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
            "mode": "ec2_status_instance",
            "interval_seconds": INTERVAL,
            "reason": "dedicated_status_publisher_instance",
            "count_merge": "skip_union_baseline_plus_ec2_results_by_source_key_sha256",
            "asset_schema": "disks.*.counts + counts + cloud_counts",
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
        "archives": archives,
        "disks": disks,
        "archives_combined": {
            "total": combined["total"],
            "done": combined["done"],
            "remaining": combined["remaining"],
            "failed": 0,
            "baseline_completed_ok": combined["baseline_completed_ok"],
            "ec2_new_ok": combined["ec2_new_ok"],
        },
        "progress": progress,
        "counts": counts,
        "cloud_counts": counts.get("combined"),
        "skip_count": baseline["skip_count"],
        "skip_policy": "sha256(source_key); never re-extract skip-list archives; never double-count EC2 overlaps",
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
        "recent_ec2_results": ec2.get("recent") or [],
        "ec2_counts_delta": {
            "Disk-1": ec2["raw"]["Disk-1"],
            "Disk-2": ec2["raw"]["Disk-2"],
            "combined": ec2["raw"]["combined"],
            "note": "New EC2-only raw counts for archives NOT in skip-list; not double-counted into baseline",
        },
        "pending_reasons": pending_reasons,
        "dedup": {
            "sha256": {
                "status": "exact_for_reconciliation_baseline_only",
                "completed_archives": baseline.get("recon_archives_done"),
                "post_baseline_status": "pending",
                "reason": pending_reasons.get("sha256_post_baseline"),
            },
            "weak_name_size": {
                "status": "exact_for_reconciliation_baseline_only",
                "completed_archives": baseline.get("recon_archives_done"),
                "post_baseline_status": "pending",
                "reason": pending_reasons.get("weak_name_size"),
            },
            "block": {
                "distinct_status": "exact_for_reconciliation_baseline_only",
                "duplicate_bytes_status": "pending",
                "unique_bytes_status": "pending",
                "reason": pending_reasons.get("duplicate_block_bytes"),
            },
        },
        "merge_notes": [
            "Historical archive identity baseline is the 2507-id skip UNION.",
            "Historical raw/extensions = reconciliation summary + results_only (_state/results).",
            "New EC2 raw/extensions/archives added only when source_key sha256 is absent from skip list.",
            "Weak/SHA-256/block-distinct cells publish reconciliation exact values (1956 archives).",
            "duplicate/unique block bytes remain pending (no occurrence lengths in historical records).",
            "GCS→S3 copy of old extracted files does not change counts.",
        ],
    }


def ensure_merge_rules(client) -> None:
    doc = {
        "schema": "cad-final-merge-rules/v1",
        "updated_at": utc_now(),
        "identity": "sha256(canonical source_key); basename matching forbidden",
        "end_state": {
            "files": "S3 holds copied historical extracts plus new EC2 extracts under the same destination layout",
            "counts": "Unified by archive id; never sum the same archive from GCS copy and EC2/history twice",
        },
        "rules": [
            "Skip-list / ledger / _state/results / _state/ec2-results are archive-identity sources of truth.",
            "When GCS→S3 file copy finishes, do NOT re-add historical archive raw counts; they are already in the baseline.",
            "Only append ec2-results whose source_key sha256 is not in the historical skip UNION.",
            "If an EC2 result overlaps the skip list, keep baseline counts and ignore the overlapping EC2 count.",
            "Dedup sha256/weak/block-distinct that are exact in reconciliation stay published; post-baseline global unions stay pending until hash sets can be re-unioned.",
            "duplicate/unique block bytes stay pending while historical records lack per-occurrence block lengths.",
        ],
        "inputs": {
            "skip_list": SKIP_KEY,
            "reconciliation_summary": RECON_SUMMARY_KEY,
            "legacy_results": LEGACY_RESULTS_PREFIX,
            "ec2_results": RESULTS_PREFIX,
        },
    }
    put_json(client, PRIVATE_BUCKET, MERGE_RULES_KEY, doc, public=False)


def publish_once(client) -> dict:
    baseline = get_baseline(client)
    private = get_json(client, PRIVATE_KEY)
    claims, results = refresh_counts(client)
    ec2 = refresh_ec2_new(client, baseline["ids"], private=private)
    public = enrich(private, claims, results, baseline, ec2)
    put_json(client, PUBLIC_BUCKET, PUBLIC_KEY, public, public=True)
    (ROOT / "status.public.json").write_text(
        json.dumps(public, separators=(",", ":"), ensure_ascii=True)
    )
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
    try:
        ensure_merge_rules(client)
    except Exception as exc:
        log(f"merge rules write failed: {type(exc).__name__}: {exc}")
    get_baseline(client)
    log(
        f"starting local AWS status publisher interval={INTERVAL}s "
        f"public=s3://{PUBLIC_BUCKET}/{PUBLIC_KEY}"
    )
    while True:
        try:
            public = publish_once(client)
            fleet = public.get("fleet") or {}
            cost = public.get("cost_estimate") or {}
            arch = (public.get("archives") or {}).get("combined") or {}
            comb = ((public.get("counts") or {}).get("combined") or {})
            pdf = comb.get("pdf") or {}
            two_d = comb.get("2d") or {}
            log(
                "published workers_alive=%s claims=%s results=%s hourly=%s "
                "done=%s/%s pdf_raw=%s 2d_raw=%s ec2_new=%s"
                % (
                    fleet.get("workers_alive"),
                    public.get("claims_count"),
                    public.get("results_count"),
                    cost.get("hourly_ec2_plus_ebs_usd"),
                    arch.get("done"),
                    arch.get("total"),
                    pdf.get("raw"),
                    two_d.get("raw"),
                    arch.get("ec2_new_ok"),
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
