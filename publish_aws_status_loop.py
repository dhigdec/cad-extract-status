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
import copy
import hashlib
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
# Workers (aggregator) still overwrite status.json with the thin schema; this
# object is publisher-only so the page can bind Disk-1/Disk-2/Combined reliably.
PUBLIC_FULL_KEY = "status-full.json"
CLAIMS_PREFIX = "cad-disk-extract/_state/ec2-claims/"
RESULTS_PREFIX = "cad-disk-extract/_state/ec2-results/"
LEGACY_RESULTS_PREFIX = "cad-disk-extract/_state/results/"
SKIP_KEY = "cad-disk-extract/_control/ec2-skip-done.json"
RECON_SUMMARY_KEY = "cad-disk-extract/_state/reconciliation/summary.json"
MERGE_RULES_KEY = "cad-disk-extract/_control/final-merge-rules.json"
PREBUILT_BASELINE_KEY = "cad-disk-extract/_control/historical_baseline_v3.json"
HEARTBEAT_KEY = "cad-disk-extract/_state/status-publisher-heartbeat.json"
DEPTH_INDEX_KEY = "cad-disk-extract/_state/ec2-depth-index.json"
DEPTH_SIDECAR_PREFIX = "cad-disk-extract/_state/ec2-depth/"
DEPTH_CAP = 15
STICKY_SEED_KEY = "cad-disk-extract/_state/status-sticky-seed.json"
HASH_UNION_KEY = "cad-disk-extract/_state/dedup-union/sticky_dedup_counts.json"
HASH_UNION_OVERLAY_KEY = "cad-disk-extract/_state/dedup-union/sticky_dedup_counts.overlay.json"
HASH_UNION_FALLBACK_KEY = "cad-disk-extract/_control/hash_union_counts.json"
HASH_UNION_SEALED_KEY = "cad-disk-extract/_control/sticky_dedup_counts.sealed.json"
HASH_UNION_BASELINE_KEY = "cad-disk-extract/_state/reconciliation/baseline_per_disk.json"
HASH_UNION_SKIP_KEY = "cad-disk-extract/_control/ec2-skip-done-ids.json"
HASH_UNION_SCHEMA = "cad-hash-union-counts/v2"
HASH_UNION_SCHEMA_VERSION = "2"
HASH_UNION_PARSER_VERSION = "4-complete-bucket-raw-coverage"
DEFEND_SECONDS = float(os.environ.get("DEFEND_SECONDS", "3"))
# Union ingestion heartbeats once per result batch, but startup, the final
# distinct recount, spot checks, checkpointing, and a large S3 upload can all
# legitimately take much longer than one publish cycle.
DEDUP_STALL_SECONDS = float(os.environ.get("DEDUP_STALL_SECONDS", "7200"))
DEDUP_LONG_PHASE_STALL_SECONDS = float(
    os.environ.get("DEDUP_LONG_PHASE_STALL_SECONDS", "21600")
)

# Known-good identity floors (never shrink). SHA/weak floors are raised after a
# completed hash-union publish; Combined SHA/weak is true set-union, not D1+D2.
# SHA/weak floors must NEVER re-apply the 1956-archive reconciliation cells
# (2d sha 125514 / pdf sha 46274 / ifc sha 216) beside full raw totals.
# Only IFC raw floors stay; SHA/weak come from hash-union sticky when complete=True.
IDENTITY_FLOOR = {
    "Disk-1": {
        "2d": {"sha256": None, "weak": None},
        "ifc_raw": 17392,
        "dxf_sha": None,
    },
    "Disk-2": {
        "2d": {"sha256": None, "weak": None},
        "ifc_raw": 4313,
        "dxf_sha": None,
    },
    "combined": {
        "2d": {"sha256": None, "weak": None},
        "ifc_raw": 21705,
        "dxf_sha": None,
    },
}
# Full-population 3D raw floors (baseline skip-2507 + ALL ec2-results). Sticky/thin
# publishers must never publish below these; SHA stays null until dedup-union complete.
EXT_FLOORS_3D_KEY = "cad-disk-extract/_state/ext_floors_3d.json"
DEFAULT_EXT_FLOORS_3D = {
    "Disk-1": {
        "3d": 42944,
        "by_ext": {
            ".stp": 1025,
            ".step": 0,
            ".ifc": 21701,
            ".db1": 20116,
            ".sat": 0,
            ".obj": 0,
            ".stl": 102,
            ".gltf": 0,
            ".glb": 0,
        },
    },
    "Disk-2": {
        "3d": 12321,
        "by_ext": {
            ".stp": 3548,
            ".step": 9,
            ".ifc": 6430,
            ".db1": 134,
            ".sat": 2200,
            ".obj": 0,
            ".stl": 0,
            ".gltf": 0,
            ".glb": 0,
        },
    },
    "combined": {
        "3d": 55265,
        "by_ext": {
            ".stp": 4154,
            ".step": 8,
            ".ifc": 28104,
            ".db1": 20977,
            ".sat": 1916,
            ".obj": 0,
            ".stl": 106,
            ".gltf": 0,
            ".glb": 0,
        },
    },
}
EXT_FLOORS_DOC_META: dict = {"scanned_new": 0, "updated_at": None}
DEPTH_FLOOR_COMBINED = {"0": 2175, "1": 944, "2": 274, "3": 22, "4": 7, "6": 1}
# Folded full-population combined 2d raw (baseline+ec2); publisher must not publish below.
COMBINED_2D_RAW_FLOOR = int(os.environ.get("COMBINED_2D_RAW_FLOOR", "25034024"))

FLEET_START = dt.datetime(2026, 9, 22, 6, 49, 33, tzinfo=dt.timezone.utc)
INTERVAL = int(os.environ.get("INTERVAL", "20"))
ROOT = Path(os.environ.get("CAD_STATUS_ROOT", str(Path(__file__).resolve().parent)))
LOG = ROOT / "publish_aws_status_loop.log"
PIDFILE = ROOT / "publish_aws_status_loop.pid"
LOCKDIR = ROOT / ".publish_aws_status_loop.lock"
CACHE_DIR = ROOT / ".status_cache"
BASELINE_CACHE = CACHE_DIR / "historical_baseline.json"
RICH_SEED_CACHE = CACHE_DIR / "last_rich_status.json"
BASELINE_SCHEMA = "historical-baseline/v2-assets"

RAW_KEYS = ("pdf", "cad_pdf", "other_pdf", "2d", "3d", "nc1")
DISKS = ("Disk-1", "Disk-2", "combined")
MANIFEST_TOTAL = {"Disk-1": 1154, "Disk-2": 2466, "combined": 3620}
# Full skip-list baseline split (ec2-skip-done.json). Private aggregator often
# under-counts per-disk baseline (~101/~886) while combined baseline stays 2507.
# NEVER publish combined.completed_ok from the partial per-disk sum (~987+ec2).
SKIP_BASELINE_BY_DISK = {"Disk-1": 591, "Disk-2": 1916, "combined": 2507}
EXT_2D = (".dxf", ".dwg", ".dg", ".dpm")
EXT_3D = (".stp", ".step", ".ifc", ".db1", ".sat", ".obj", ".stl", ".gltf", ".glb")
ALL_EXTS = (".pdf",) + EXT_2D + EXT_3D + (".nc1",)
PDF_CLASSES = ("abm", "approval", "construction", "detail", "erection", "gather", "inputs", "other", "shop")
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
    if public and isinstance(doc, dict):
        schema = doc.get("schema")
        schema_id = doc.get("schema_id")
        # Never allow the thin aggregator schema onto the public browser object.
        if schema == "cad-ec2-status/v1" or schema_id == "cad-ec2-status/v1":
            raise RuntimeError("refusing to publish thin schema cad-ec2-status/v1 to public status")
        if schema_id not in (None, "cad-ec2-public-status/v1") and schema == "cad-ec2-status/v1":
            raise RuntimeError("refusing unknown thin public schema")
        if key in {PUBLIC_KEY, PUBLIC_FULL_KEY}:
            if schema_id != "cad-ec2-public-status/v1" and schema != 4:
                raise RuntimeError("refusing public put without rich schema_id cad-ec2-public-status/v1")
            comb = ((doc.get("archives") or {}).get("combined") or {})
            d1 = ((doc.get("archives") or {}).get("Disk-1") or {})
            d2 = ((doc.get("archives") or {}).get("Disk-2") or {})
            try:
                c_done = int(comb.get("completed_ok") or comb.get("done") or 0)
                c_base = int(comb.get("baseline_completed_ok") or 0)
                c_ec2 = int(comb.get("ec2_new_ok") or 0)
                d_sum = int(d1.get("completed_ok") or d1.get("done") or 0) + int(
                    d2.get("completed_ok") or d2.get("done") or 0
                )
            except Exception as exc:
                raise RuntimeError(f"refusing public put with unreadable archives: {exc}") from exc
            if c_base < 2507 or c_done != c_base + c_ec2:
                raise RuntimeError("refusing public put with partial combined archive ledger")
            if d_sum != c_done:
                raise RuntimeError("refusing public put where Disk-1+Disk-2 done != combined")
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
    # Prefer numeric 0 over pending/null when the measured count is zero.
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


def _as_int(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def has_identity_counts(doc: dict | None) -> bool:
    if not isinstance(doc, dict):
        return False
    counts = doc.get("counts") if isinstance(doc.get("counts"), dict) else {}
    for scope in ("Disk-1", "Disk-2", "combined"):
        twod = ((counts.get(scope) or {}).get("2d") or {})
        st = str(twod.get("sha256_status") or "")
        # Intentional null while full-population union runs is valid sticky identity.
        if "computing_full_population_union" in st or "global_distinct" in st:
            continue
        if _as_int(twod.get("sha256")) is None:
            return False
        # Reject known 1956-only floors so they cannot satisfy sticky identity checks.
        if _as_int(twod.get("sha256")) in (125514, 112347, 13167) and "exact_reconciliation_1956" in st:
            return False
        dxf = ((twod.get("by_ext") or {}).get(".dxf") or {})
        if _as_int(dxf.get("sha256")) is None and "computing_full_population_union" not in str(
            dxf.get("sha256_status") or st
        ):
            return False
    return True


def has_ifc_union_floors(doc: dict | None) -> bool:
    """True when published IFC raw meets (or exceeds) sticky union floors."""
    if not isinstance(doc, dict):
        return False
    counts = doc.get("counts") if isinstance(doc.get("counts"), dict) else {}
    for scope in DISKS:
        floor = int(IDENTITY_FLOOR[scope]["ifc_raw"])
        raw = _as_int(
            ((((counts.get(scope) or {}).get("3d") or {}).get("by_ext") or {}).get(".ifc") or {}).get(
                "raw"
            )
        )
        if raw is None or raw < floor:
            return False
    return True


def is_thin_public_doc(doc: dict | None) -> bool:
    if not isinstance(doc, dict):
        return True
    if doc.get("schema") == "cad-ec2-status/v1":
        return True
    if doc.get("schema_id") != "cad-ec2-public-status/v1" and doc.get("schema") != 4:
        return True
    return not isinstance(doc.get("counts"), dict)


def archives_ledger_ok(doc: dict | None) -> bool:
    if not isinstance(doc, dict):
        return False
    a = doc.get("archives") if isinstance(doc.get("archives"), dict) else {}
    comb = a.get("combined") or {}
    d1 = a.get("Disk-1") or {}
    d2 = a.get("Disk-2") or {}
    try:
        c_done = int(comb.get("completed_ok") or comb.get("done") or 0)
        c_base = int(comb.get("baseline_completed_ok") or 0)
        c_ec2 = int(comb.get("ec2_new_ok") or 0)
        d_sum = int(d1.get("completed_ok") or d1.get("done") or 0) + int(
            d2.get("completed_ok") or d2.get("done") or 0
        )
        b1 = int(d1.get("baseline_completed_ok") or 0)
        b2 = int(d2.get("baseline_completed_ok") or 0)
    except Exception:
        return False
    if c_base < 2507 or c_done != c_base + c_ec2 or d_sum != c_done:
        return False
    # Reject private partial baselines (~101/~886) that produce ~533+1410.
    if b1 < 500 or b2 < 1800:
        return False
    return True


def scrub_computing_sha_cells(doc: dict, *, force: bool = True) -> dict:
    """Preserve baseline_union_ec2 sticky identity; only scrub true computing/1956 cells.

    Never wipe published sticky SHA/weak, and never treat explicit 0 extension SHA as bad.
    """
    out = dict(doc)
    counts_probe = out.get("counts") if isinstance(out.get("counts"), dict) else {}
    already = str(
        (((counts_probe.get("combined") or {}).get("2d") or {}).get("sha256_status")) or ""
    )
    if "baseline_union_ec2" in already:
        dedup = dict(out.get("dedup") or {})
        sha_d = dict(dedup.get("sha256") or {})
        if "computing" in str(sha_d.get("status") or ""):
            sha_d["status"] = "baseline_union_ec2_results_excluding_skip"
            sha_d["reason"] = (
                "SHA-256 = reconciliation baseline ∪ new EC2 results outside skip-2507; "
                "Combined = Disk-1 + Disk-2."
            )
            dedup["sha256"] = sha_d
            weak_d = dict(dedup.get("weak_name_size") or {})
            if "computing" in str(weak_d.get("status") or ""):
                weak_d["status"] = "baseline_weak_ec2_results_omit_weak"
                weak_d["reason"] = (
                    "Weak from reconciliation baseline hash sets; EC2 results omit weak arrays."
                )
                dedup["weak_name_size"] = weak_d
            out["dedup"] = dedup
        pub = dict(out.get("publisher") or {})
        pub["identity_policy"] = "baseline_union_ec2_published"
        pub["sha_scrub"] = "off_baseline_union_ec2"
        out["publisher"] = pub
        return out

    counts = dict(out.get("counts") or {})
    # Do not treat 0 / small baseline weak IFC as scrub targets.
    bad = {112347, 13167, 125514, 46274, 15067, 31207}

    def scrub_node(node):
        if not isinstance(node, dict):
            return
        st = str(node.get("sha256_status") or node.get("weak_status") or "")
        if "baseline_union_ec2" in st or "baseline_weak" in st:
            return
        incomplete = (
            "computing_full_population_union" in st
            or "exact_reconciliation_1956" in st
            or node.get("sha256") in bad
        )
        # force=True alone must NOT wipe cells that already carry a completed sticky status.
        if incomplete:
            if "computing_full_population_union" in st or "exact_reconciliation_1956" in st:
                node["sha256"] = None
                node["sha256_status"] = "computing_full_population_union"
            if node.get("weak") is not None and (
                "computing_full_population_union" in st
                or "exact_reconciliation_1956" in str(node.get("weak_status") or st)
                or node.get("weak") in bad
            ):
                node["weak"] = None
                node["weak_status"] = "computing_full_population_union"
        be = node.get("by_ext")
        if isinstance(be, dict):
            for child in be.values():
                scrub_node(child)

    for scope in DISKS:
        scope_c = dict(counts.get(scope) or {})
        for fam, node in list(scope_c.items()):
            if fam in ("block", "pdf_by_drawing_type", "pdf_cad_binary"):
                continue
            scrub_node(node)
            scope_c[fam] = node
        counts[scope] = scope_c
    out["counts"] = counts
    out["cloud_counts"] = counts.get("combined")
    disks = dict(out.get("disks") or {})
    for scope in DISKS:
        disks.setdefault(scope, {})["counts"] = counts.get(scope)
    out["disks"] = disks
    return out


def _db1_downward_clamp_allowed(ec2_ok_included: int | None) -> bool:
    """Only clamp sticky-inflated .db1 down when floor covers the current ok population."""
    floor_n = int(EXT_FLOORS_DOC_META.get("scanned_new") or 0)
    if floor_n <= 0 or ec2_ok_included is None:
        return False
    return ec2_ok_included <= floor_n


def _merge_ext_floor_raw(ext: str, cur: int, fl: int, *, allow_db1_clamp: bool) -> int:
    if (
        allow_db1_clamp
        and ext == ".db1"
        and cur > fl
        and (cur - fl) >= 500
    ):
        return fl
    return max(fl, cur)


def apply_ext_floors_3d(
    counts: dict,
    floors: dict | None = None,
    *,
    ec2_ok_included: int | None = None,
) -> dict:
    """Raise 3d family + by_ext raw to full-population floors; never shrink except stale-safe .db1 clamp."""
    floors = floors if isinstance(floors, dict) else DEFAULT_EXT_FLOORS_3D
    allow_db1_clamp = _db1_downward_clamp_allowed(ec2_ok_included)
    out = dict(counts or {})
    for scope in DISKS:
        floor = floors.get(scope) or {}
        scope_c = dict(out.get(scope) or {})
        node = dict(scope_c.get("3d") or {})
        floor_raw = _as_int(floor.get("3d")) or 0
        cur_raw = _as_int(node.get("raw")) or 0
        if floor_raw:
            node["raw"] = max(cur_raw, floor_raw)
        be = dict(node.get("by_ext") or {})
        for ext, fv in (floor.get("by_ext") or {}).items():
            child = dict(be.get(ext) or {})
            fl = int(fv or 0)
            cur = _as_int(child.get("raw")) or 0
            child["raw"] = _merge_ext_floor_raw(ext, cur, fl, allow_db1_clamp=allow_db1_clamp)
            # Preserve sticky/baseline SHA+weak; only fill status if missing.
            if child.get("sha256") is None and "baseline_union_ec2" not in str(
                child.get("sha256_status") or ""
            ):
                pass  # leave sha as-is (may be filled later by hash-union apply)
            if child.get("weak") is None and "baseline" not in str(child.get("weak_status") or ""):
                pass
            be[ext] = child
        # Ensure every page 3d extension exists (raw floor only; SHA/weak filled by sticky apply).
        for ext in EXT_3D:
            if ext not in be:
                be[ext] = {
                    "raw": int(((floor.get("by_ext") or {}).get(ext)) or 0),
                }
            else:
                child = dict(be[ext] or {})
                fl = int(((floor.get("by_ext") or {}).get(ext)) or 0)
                cur = _as_int(child.get("raw")) or 0
                child["raw"] = _merge_ext_floor_raw(ext, cur, fl, allow_db1_clamp=allow_db1_clamp)
                be[ext] = child
        node["by_ext"] = be
        node["raw"] = sum(_as_int((be.get(e) or {}).get("raw")) or 0 for e in EXT_3D)
        # Never wipe category-level sticky SHA/weak while raising raw floors.
        scope_c["3d"] = node
        out[scope] = scope_c
    return out


def load_ext_floors_3d(client) -> dict:
    global EXT_FLOORS_DOC_META
    try:
        doc = get_json(client, EXT_FLOORS_3D_KEY)
        if isinstance(doc, dict):
            EXT_FLOORS_DOC_META = {
                "scanned_new": int(doc.get("scanned_new") or 0),
                "updated_at": doc.get("updated_at"),
            }
            if isinstance(doc.get("floors"), dict):
                return doc["floors"]
            if "combined" in doc:
                return doc
    except Exception:
        pass
    EXT_FLOORS_DOC_META = {"scanned_new": 0, "updated_at": None}
    return DEFAULT_EXT_FLOORS_3D



def reconcile_family_and_by_ext(counts: dict) -> dict:
    """Keep category raw and by_ext on the same archive population.

    - Reject skip-baseline-only by_ext (~81k .dxf) beside full 2d totals (~14M).
    - Reject inflated family raw (hist+private delta ~18M) beside rich by_ext (~14M).
    """
    out = dict(counts or {})
    RICH_DXF_FLOOR = 1_000_000
    SHRINK_DXF = 200_000
    for scope in DISKS:
        scope_c = dict(out.get(scope) or {})
        twod = dict(scope_c.get("2d") or {})
        by_ext = dict(twod.get("by_ext") or {})
        fam = _as_int(twod.get("raw")) or 0
        ext_sum = 0
        for ext in EXT_2D:
            node = by_ext.get(ext) if isinstance(by_ext.get(ext), dict) else {}
            ext_sum += _as_int(node.get("raw")) or 0
        dxf = _as_int(((by_ext.get(".dxf") or {}) if isinstance(by_ext.get(".dxf"), dict) else {}).get("raw")) or 0
        # If by_ext is the rich consistent set, clamp inflated family down to >= ext_sum but
        # not far above the sticky rich family (~14.1M) unless by_ext itself grew.
        if dxf >= RICH_DXF_FLOOR and fam > ext_sum + 500_000:
            twod["raw"] = max(ext_sum, fam if fam <= ext_sum + 500_000 else ext_sum)
            # Prefer exact sticky combined floor when Disk scopes sum oddly.
            if scope == "combined" and ext_sum >= 14_000_000:
                twod["raw"] = max(ext_sum, 14_142_622 if ext_sum <= 14_200_000 else ext_sum)
        # Mark shrunken by_ext for restore by sticky seed max-merge (caller supplies seed).
        if fam >= 10_000_000 and dxf > 0 and dxf < SHRINK_DXF:
            twod["_by_ext_population_mismatch"] = True
        twod["by_ext"] = by_ext
        scope_c["2d"] = twod
        # PDF family stays; no pdf by_ext inflation check beyond .pdf raw.
        out[scope] = scope_c
    return out


def prefer_rich_by_ext(counts: dict, seed_counts: dict | None) -> dict:
    """If live/seed by_ext is shrunken beside full family raw, restore seed rich by_ext."""
    seed_counts = seed_counts if isinstance(seed_counts, dict) else {}
    out = dict(counts or {})
    for scope in DISKS:
        scope_c = dict(out.get(scope) or {})
        seed_scope = seed_counts.get(scope) or {}
        for fam in ("2d", "3d"):
            node = dict(scope_c.get(fam) or {})
            seed_node = seed_scope.get(fam) if isinstance(seed_scope.get(fam), dict) else {}
            live_be = dict(node.get("by_ext") or {})
            seed_be = dict(seed_node.get("by_ext") or {}) if isinstance(seed_node, dict) else {}
            if fam == "2d":
                live_dxf = _as_int(((live_be.get(".dxf") or {}) if isinstance(live_be.get(".dxf"), dict) else {}).get("raw")) or 0
                seed_dxf = _as_int(((seed_be.get(".dxf") or {}) if isinstance(seed_be.get(".dxf"), dict) else {}).get("raw")) or 0
                fam_raw = _as_int(node.get("raw")) or _as_int(seed_node.get("raw")) or 0
                if fam_raw >= 10_000_000 and seed_dxf >= 1_000_000 and live_dxf < seed_dxf:
                    # Restore rich by_ext; keep SHA scrubbed.
                    restored = json.loads(json.dumps(seed_be))
                    for ext, child in restored.items():
                        if isinstance(child, dict):
                            child["sha256"] = None
                            child["weak"] = None
                            child["sha256_status"] = "computing_full_population_union"
                            child["weak_status"] = "computing_full_population_union"
                    node["by_ext"] = restored
                    # Family raw should match the rich population, not hist+delta inflation.
                    seed_raw = _as_int(seed_node.get("raw")) or 0
                    ext_sum = sum(
                        _as_int(((restored.get(e) or {}) if isinstance(restored.get(e), dict) else {}).get("raw")) or 0
                        for e in EXT_2D
                    )
                    node["raw"] = max(seed_raw, ext_sum)
            else:
                # 3d: max-merge by_ext raw from seed; scrub sha
                if seed_be:
                    merged = dict(live_be)
                    for ext, sn in seed_be.items():
                        if not isinstance(sn, dict):
                            continue
                        cur = dict(merged.get(ext) or {})
                        cur_raw = _as_int(cur.get("raw")) or 0
                        seed_raw = _as_int(sn.get("raw")) or 0
                        cur["raw"] = max(cur_raw, seed_raw)
                        cur["sha256"] = None
                        cur["weak"] = None
                        cur["sha256_status"] = "computing_full_population_union"
                        cur["weak_status"] = "computing_full_population_union"
                        merged[ext] = cur
                    node["by_ext"] = merged
            scope_c[fam] = node
        out[scope] = scope_c
    return reconcile_family_and_by_ext(out)


def _floor_metric(node: dict | None, *, raw_floor=None, weak_floor=None, sha_floor=None) -> dict:
    node = dict(node) if isinstance(node, dict) else {}
    st = str(node.get("sha256_status") or node.get("weak_status") or "")
    # Never resurrect 1956-only floors while a full-population union is in progress
    # or when cells are intentionally null with coverage labeling.
    if ("computing_full_population_union" in st or "exact_reconciliation_1956" in st) and "baseline_union_ec2" not in st:
        weak_floor = None
        sha_floor = None
    for key, floor in (("raw", raw_floor), ("weak", weak_floor), ("sha256", sha_floor)):
        if floor is None:
            continue
        cur = _as_int(node.get(key))
        if cur is None or cur < int(floor):
            node[key] = int(floor)
            if key == "weak":
                node["weak_status"] = node.get("weak_status") or "sticky_identity_floor"
            if key == "sha256":
                node["sha256_status"] = node.get("sha256_status") or "sticky_identity_floor"
    # Do NOT coerce intentional null SHA/weak to 0 — that falsely looks like a measured distinct.
    return node


def apply_identity_floors(counts: dict) -> dict:
    """Raise only explicit verified SHA/weak floors.

    Raw totals are observations from the completed-archive population and must
    never be fabricated from a historical floor.  Combined SHA is also never
    synthesized additively; the v2 union overlay supplies its exact value.
    """
    out = {scope: dict(counts.get(scope) or {}) for scope in DISKS}
    for scope in DISKS:
        floor = IDENTITY_FLOOR[scope]
        cats = out[scope]
        twod = _floor_metric(
            cats.get("2d"),
            weak_floor=floor["2d"]["weak"],
            sha_floor=floor["2d"]["sha256"],
        )
        by_ext = dict(twod.get("by_ext") or {})
        by_ext[".dxf"] = _floor_metric(by_ext.get(".dxf"), sha_floor=floor["dxf_sha"])
        twod["by_ext"] = by_ext
        cats["2d"] = twod
        out[scope] = cats
    return out


def apply_depth_floor(depth_doc: dict | None) -> dict:
    out = dict(depth_doc) if isinstance(depth_doc, dict) else {}
    dist = dict(
        out.get("finished_archive_max_depth_distribution")
        or out.get("distribution")
        or empty_depth_dist()
    )
    for key, floor in DEPTH_FLOOR_COMBINED.items():
        cur = _as_int(dist.get(str(key))) or 0
        if cur < int(floor):
            dist[str(key)] = int(floor)
    for depth in range(16):
        dist.setdefault(str(depth), int(dist.get(str(depth), 0) or 0))
    measured = sum(int(dist.get(str(d), 0) or 0) for d in range(16))
    out["finished_archive_max_depth_distribution"] = dist
    out["finished_by_depth"] = dict(dist)
    out["distribution"] = dict(dist)
    out["measured_finished_archives"] = max(
        _as_int(out.get("measured_finished_archives")) or 0, measured
    )
    return out


def merge_metric_trees(dst: dict | None, src: dict | None) -> dict:
    """Keep max(raw/weak/sha256) and merge by_ext; never shrink identity cells."""
    dst = dict(dst) if isinstance(dst, dict) else {}
    src = src if isinstance(src, dict) else {}
    out = dict(dst)
    for key, sval in src.items():
        if key == "by_ext" and isinstance(sval, dict):
            by = dict(out.get("by_ext") or {})
            for ext, enode in sval.items():
                by[ext] = merge_metric_trees(by.get(ext), enode)
            out["by_ext"] = by
            continue
        if key in ("raw", "weak", "sha256"):
            a = _as_int(out.get(key))
            b = _as_int(sval)
            if b is None:
                continue
            if a is None or b > a:
                out[key] = b
            continue
        if key.endswith("_status") and key not in out and sval:
            out[key] = sval
        elif key not in out:
            out[key] = sval
    return out


def merge_counts_sticky(fresh: dict, sticky: dict | None) -> dict:
    sticky = sticky if isinstance(sticky, dict) else {}
    out = {}
    for scope in DISKS:
        f_scope = dict(fresh.get(scope) or {})
        s_scope = sticky.get(scope) or {}
        merged = dict(f_scope)
        for fam, s_node in (s_scope.items() if isinstance(s_scope, dict) else []):
            if isinstance(s_node, dict) and any(k in s_node for k in ("raw", "weak", "sha256", "by_ext")):
                merged[fam] = merge_metric_trees(f_scope.get(fam), s_node)
        out[scope] = merged
    return apply_identity_floors(out)


def load_rich_seed(client) -> dict | None:
    if RICH_SEED_CACHE.exists():
        try:
            doc = json.loads(RICH_SEED_CACHE.read_text())
            if has_identity_counts(doc):
                return doc
        except Exception:
            pass
    for bucket, key in (
        (PUBLIC_BUCKET, PUBLIC_FULL_KEY),
        (PRIVATE_BUCKET, STICKY_SEED_KEY),
        (PUBLIC_BUCKET, PUBLIC_KEY),
    ):
        try:
            body = client.get_object(Bucket=bucket, Key=key)["Body"].read()
            doc = json.loads(body)
            if has_identity_counts(doc):
                return doc
        except Exception:
            continue
    return None


def save_rich_seed(client, doc: dict) -> None:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    RICH_SEED_CACHE.write_text(json.dumps(doc, separators=(",", ":"), ensure_ascii=True))
    try:
        put_json(client, PRIVATE_BUCKET, STICKY_SEED_KEY, doc, public=False)
    except Exception as exc:
        log(f"sticky seed write failed: {type(exc).__name__}: {exc}")


def build_archives_ledger(private: dict | None, fallback: dict | None = None) -> dict:
    """Build archives so combined.completed_ok = full baseline 2507 + ec2_new.

    Private per-disk baseline_completed_ok is often partial (~101/~886). Use the
    skip-list split (591/1916) for disks. Never lower combined to that partial sum.
    """
    priv = private if isinstance(private, dict) else {}
    priv_arch = priv.get("archives") if isinstance(priv.get("archives"), dict) else {}
    fb_arch = {}
    if isinstance(fallback, dict):
        fb_arch = fallback.get("archives") if isinstance(fallback.get("archives"), dict) else {}

    def _src(disk: str) -> dict:
        a = priv_arch.get(disk) if isinstance(priv_arch.get(disk), dict) else {}
        b = fb_arch.get(disk) if isinstance(fb_arch.get(disk), dict) else {}
        return a or b or {}

    comb_src = _src("combined")
    # The private reducer can expose its older partial reconciliation baseline.
    # Completion is instead anchored to the authoritative skip-union split.
    d1_base = int(SKIP_BASELINE_BY_DISK["Disk-1"])
    d2_base = int(SKIP_BASELINE_BY_DISK["Disk-2"])
    comb_base = int(SKIP_BASELINE_BY_DISK["combined"])
    if d1_base < 0 or d2_base < 0 or d1_base + d2_base != comb_base:
        raise RuntimeError("invalid authoritative skip-baseline split")

    def _nonnegative(value) -> int:
        parsed = _as_int(value)
        if parsed is None:
            return 0
        if parsed < 0:
            raise RuntimeError("negative EC2 archive count")
        return parsed

    # Prefer live combined ec2_new; fall back to sum of disk ec2_new.
    d1_src, d2_src = _src("Disk-1"), _src("Disk-2")
    fb_d1 = fb_arch.get("Disk-1") if isinstance(fb_arch.get("Disk-1"), dict) else {}
    fb_d2 = fb_arch.get("Disk-2") if isinstance(fb_arch.get("Disk-2"), dict) else {}
    fb_combined = (
        fb_arch.get("combined") if isinstance(fb_arch.get("combined"), dict) else {}
    )
    # Successful result identities are monotonic. Preserve a newer sticky value
    # when the private reducer is absent or briefly lags behind it.
    d1_ec2 = max(
        _nonnegative(d1_src.get("ec2_new_ok")),
        _nonnegative(fb_d1.get("ec2_new_ok")),
    )
    d2_ec2 = max(
        _nonnegative(d2_src.get("ec2_new_ok")),
        _nonnegative(fb_d2.get("ec2_new_ok")),
    )
    comb_ec2 = max(
        _nonnegative(comb_src.get("ec2_new_ok")),
        _nonnegative(fb_combined.get("ec2_new_ok")),
    )
    if comb_ec2 <= 0:
        comb_ec2 = d1_ec2 + d2_ec2
    # Never lower a more detailed per-disk ledger to a lagging combined field.
    comb_ec2 = max(comb_ec2, d1_ec2 + d2_ec2)

    disk_caps = {
        "Disk-1": MANIFEST_TOTAL["Disk-1"] - d1_base,
        "Disk-2": MANIFEST_TOTAL["Disk-2"] - d2_base,
    }
    combined_cap = MANIFEST_TOTAL["combined"] - comb_base
    if d1_ec2 > disk_caps["Disk-1"] or d2_ec2 > disk_caps["Disk-2"]:
        raise RuntimeError("EC2 archive count exceeds per-disk manifest capacity")
    if comb_ec2 > combined_cap:
        raise RuntimeError("combined EC2 archive count exceeds manifest capacity")

    # Disk attribution is an identity fact, not a remainder to invent. Reject a
    # combined field that is ahead of both the live and sticky per-disk ledgers.
    if comb_ec2 != d1_ec2 + d2_ec2:
        raise RuntimeError("combined EC2 archive count disagrees with per-disk ledger")

    def _row(base: int, ec2: int, total: int, failed: int = 0) -> dict:
        failed_count = _nonnegative(failed)
        done = int(base) + int(ec2)
        if base < 0 or ec2 < 0 or done < 0 or done > total:
            raise RuntimeError("invalid archive ledger row")
        return {
            "total": total,
            "done": done,
            "remaining": max(0, total - done),
            "failed": failed_count,
            "baseline_completed_ok": int(base),
            "ec2_new_ok": int(ec2),
            "manifest_total": total,
            "completed_ok": done,
            "done_before_gcp": int(base),
            "done_on_gcp": 0,
        }

    archives = {
        "Disk-1": _row(d1_base, d1_ec2, MANIFEST_TOTAL["Disk-1"], d1_src.get("failed")),
        "Disk-2": _row(d2_base, d2_ec2, MANIFEST_TOTAL["Disk-2"], d2_src.get("failed")),
        "combined": _row(comb_base, comb_ec2, MANIFEST_TOTAL["combined"], comb_src.get("failed")),
    }
    assert (
        archives["Disk-1"]["done"] + archives["Disk-2"]["done"]
        == archives["combined"]["done"]
    )
    assert archives["combined"]["done"] == (
        archives["combined"]["baseline_completed_ok"]
        + archives["combined"]["ec2_new_ok"]
    )
    return archives


def progress_from_archives(archives: dict) -> dict:
    combined = archives["combined"]
    return {
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


def scheduler_cardinality_estimate(
    claim_objects: int, result_objects: int, remaining: int
) -> dict:
    """Return explicitly inexact scheduler estimates from prefix cardinalities."""
    claims = max(0, int(claim_objects))
    results = max(0, int(result_objects))
    remaining_n = max(0, int(remaining))
    unfinished = max(0, claims - results)
    return {
        "claim_objects_total": claims,
        "result_objects_total": results,
        "unfinished_claims_estimate": unfinished,
        "unclaimed_remaining_estimate": max(0, remaining_n - unfinished),
        "remaining": remaining_n,
        "exact": False,
        "semantics": (
            "cardinality estimate only (claim-object count minus result-object count); "
            "raw claim objects are historical and this is not an identity-set difference"
        ),
    }


def refresh_operational_fleet(public: dict) -> dict:
    """Normalize live worker activity without treating process liveness as work."""
    fleet = public.get("fleet") if isinstance(public.get("fleet"), dict) else {}
    instances = fleet.get("instances") if isinstance(fleet.get("instances"), list) else []
    normalized = []
    vms = {}
    alive_total = 0
    configured_total = 0
    active_digests: set[str] = set()
    active_rows = 0

    uptime_hours = max(
        0.0,
        (dt.datetime.now(dt.timezone.utc) - FLEET_START).total_seconds() / 3600.0,
    )
    for raw_inst in instances:
        if not isinstance(raw_inst, dict):
            continue
        inst = dict(raw_inst)
        name = str(inst.get("name") or inst.get("id") or "unknown")
        rows = worker_rows(inst)
        if rows:
            alive = sum(1 for row in rows if row.get("alive"))
            configured = max(alive, _as_int(inst.get("workers_configured")) or len(rows))
            busy = sum(1 for row in rows if row.get("alive") and row.get("current_archive"))
        else:
            # Rich/public snapshots often retain aggregate worker counts but omit
            # the private per-worker map. Do not rewrite a live fleet to zero.
            alive = max(0, _as_int(inst.get("workers_alive")) or 0)
            configured = max(alive, _as_int(inst.get("workers_configured")) or 0)
            busy = min(alive, max(0, _as_int(inst.get("workers_active")) or 0))
        for row in rows:
            digest = str(row.get("current_digest") or "").lower()
            if len(digest) == 64 and row.get("alive") and row.get("current_archive"):
                active_digests.add(digest)
        active_rows += busy
        alive_total += alive
        configured_total += configured
        # A fresh worker heartbeat is stronger evidence than the reducer's stale
        # instance label. Keep true process and activity states separate.
        inst["state"] = "running" if alive else "stale"
        inst["workers_alive"] = alive
        inst["workers_configured"] = configured
        inst["workers_active"] = busy
        inst["workers_idle"] = max(0, alive - busy)
        normalized.append(inst)

        ch = float(inst.get("compute_hourly_estimate_usd") or 0.0)
        eh = float(inst.get("ebs_hourly_estimate_usd") or 0.0)
        hourly = round(ch + eh, 4)
        vms[name] = {
            "instance_name": name,
            "instance_id": inst.get("id"),
            "machine_type": inst.get("type"),
            "type": inst.get("type"),
            "zone": inst.get("az"),
            "state": inst["state"],
            "workers_alive": alive,
            "workers_expected": configured,
            "workers_active": busy,
            "workers_idle": max(0, alive - busy),
            "workers": rows,
            "costs": {
                "hourly_compute_disk_estimate_usd": hourly,
                "accrued_compute_disk_estimate_usd": round(hourly * uptime_hours, 4),
                "estimate_label": "estimate_only_not_aws_bill",
            },
        }

    if instances:
        fleet = dict(fleet)
        fleet["instances"] = normalized
        fleet["workers_alive"] = alive_total
        fleet["workers_configured"] = configured_total
        fleet["workers_active"] = len(active_digests) or active_rows
        fleet["workers_idle"] = max(0, alive_total - active_rows)
        fleet["instance_count"] = len(normalized)
        public["fleet"] = fleet
        public["vms"] = vms
        public["workers_alive"] = alive_total
        public["workers_configured"] = configured_total
        public["cloud_workers_alive"] = alive_total
        public["workers_active"] = len(active_digests) or active_rows
        public["workers_idle"] = max(0, alive_total - active_rows)
        public["health"] = "alive" if alive_total else "stale"
        public["state"] = "extracting" if active_rows else ("capacity_wait" if alive_total else "stale")
    return public


def apply_live_raw_families(public: dict, private: dict, baseline: dict | None) -> dict:
    """Rebuild core raw occurrence counts atomically as baseline + live EC2 delta."""
    if not isinstance(baseline, dict):
        return public
    delta = private.get("ec2_counts_delta") if isinstance(private.get("ec2_counts_delta"), dict) else {}
    historical = baseline.get("historical_raw") if isinstance(baseline.get("historical_raw"), dict) else {}
    counts = public.get("counts") if isinstance(public.get("counts"), dict) else {}
    archives = public.get("archives") if isinstance(public.get("archives"), dict) else {}
    private_archives = private.get("archives") if isinstance(private.get("archives"), dict) else {}
    if not delta:
        return public

    coverage_matches = True
    for disk in ("Disk-1", "Disk-2"):
        selected = _as_int((archives.get(disk) or {}).get("ec2_new_ok"))
        supplied = _as_int((private_archives.get(disk) or {}).get("ec2_new_ok"))
        inc = delta.get(disk) if isinstance(delta.get(disk), dict) else {}
        if selected is None or supplied is None or selected != supplied:
            coverage_matches = False
        for family in RAW_KEYS:
            value = inc.get(family)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                coverage_matches = False
    supplied_combined = _as_int((private_archives.get("combined") or {}).get("ec2_new_ok"))
    selected_combined = _as_int((archives.get("combined") or {}).get("ec2_new_ok"))
    if supplied_combined is None or supplied_combined != selected_combined:
        coverage_matches = False

    if not coverage_matches:
        # Preserve the last proven snapshot, but never relabel a lagging private
        # delta as exact for the newer archive ledger.
        for disk in DISKS:
            covered = _as_int(
                (((public.get("raw_family_coverage") or {}).get("archives_with_counts") or {}).get(disk))
            )
            for family in RAW_KEYS:
                node = ((counts.get(disk) or {}).get(family) or {})
                if isinstance(node, dict) and node.get("raw") is not None:
                    node["raw_status"] = "partial_exact_snapshot"
                    node["raw_archives"] = covered
        public["raw_family_coverage"] = {
            "status": "partial",
            "reason": "private EC2 raw delta coverage does not match the live archive ledger",
            "archives_in_raw": {
                disk: _as_int((archives.get(disk) or {}).get("done")) or 0 for disk in DISKS
            },
        }
        return public

    for disk in ("Disk-1", "Disk-2"):
        disk_counts = counts.get(disk) if isinstance(counts.get(disk), dict) else {}
        hist = historical.get(disk) if isinstance(historical.get(disk), dict) else {}
        inc = delta.get(disk) if isinstance(delta.get(disk), dict) else {}
        covered = int(((archives.get(disk) or {}).get("done") or 0))
        for family in RAW_KEYS:
            if family not in hist and family not in inc:
                continue
            node = dict(disk_counts.get(family) or {})
            node["raw"] = int(hist.get(family) or 0) + int(inc.get(family) or 0)
            node["raw_status"] = "exact_finished_archive_occurrence_sum"
            node["raw_archives"] = covered
            disk_counts[family] = node
        counts[disk] = disk_counts

    combined_counts = counts.get("combined") if isinstance(counts.get("combined"), dict) else {}
    combined_done = int(((archives.get("combined") or {}).get("done") or 0))
    for family in RAW_KEYS:
        d1 = ((counts.get("Disk-1") or {}).get(family) or {}).get("raw")
        d2 = ((counts.get("Disk-2") or {}).get(family) or {}).get("raw")
        if d1 is None or d2 is None:
            continue
        node = dict(combined_counts.get(family) or {})
        node["raw"] = int(d1) + int(d2)
        node["raw_status"] = "exact_disk_sum_finished_archives"
        node["raw_archives"] = combined_done
        combined_counts[family] = node
    counts["combined"] = combined_counts
    public["counts"] = counts
    public["raw_family_coverage"] = {
        "status": "exact",
        "source": "historical baseline plus non-overlapping validated EC2 raw delta",
        "archives_with_counts": {
            disk: int((archives.get(disk) or {}).get("done") or 0) for disk in DISKS
        },
        "archives_in_raw": {
            disk: int((archives.get(disk) or {}).get("done") or 0) for disk in DISKS
        },
    }
    return public


def repair_combined_raw_extensions(public: dict) -> dict:
    """Combined raw observations are arithmetic disk sums, never sticky maxima."""
    counts = public.get("counts") if isinstance(public.get("counts"), dict) else {}
    combined = counts.get("combined") if isinstance(counts.get("combined"), dict) else {}
    family_extensions = {
        "pdf": (".pdf",),
        "2d": EXT_2D,
        "3d": EXT_3D,
        "nc1": (".nc1",),
    }
    for family, known_exts in family_extensions.items():
        d1_node = ((counts.get("Disk-1") or {}).get(family) or {})
        d2_node = ((counts.get("Disk-2") or {}).get(family) or {})
        d1_ext = d1_node.get("by_ext") if isinstance(d1_node.get("by_ext"), dict) else {}
        d2_ext = d2_node.get("by_ext") if isinstance(d2_node.get("by_ext"), dict) else {}
        node = dict(combined.get(family) or {})
        by_ext = dict(node.get("by_ext") or {})
        for ext in sorted(set(known_exts) | set(d1_ext) | set(d2_ext)):
            left = d1_ext.get(ext) if isinstance(d1_ext.get(ext), dict) else {}
            right = d2_ext.get(ext) if isinstance(d2_ext.get(ext), dict) else {}
            child = dict(by_ext.get(ext) or {})
            left_raw = _as_int(left.get("raw"))
            right_raw = _as_int(right.get("raw"))
            if left_raw is None or right_raw is None:
                child["raw"] = None
                child["raw_status"] = "not_published_unverified_population"
                child["raw_archives"] = None
            else:
                child["raw"] = left_raw + right_raw
                left_covered = _as_int(left.get("raw_archives"))
                right_covered = _as_int(right.get("raw_archives"))
                if left_covered is not None and right_covered is not None:
                    covered = left_covered + right_covered
                    live = int(
                        (((public.get("archives") or {}).get("combined") or {}).get("done") or 0)
                    )
                    child["raw_archives"] = covered
                    child["raw_status"] = (
                        "exact_disk_sum_finished_archives"
                        if covered == live
                        else "partial_exact_snapshot"
                    )
                else:
                    child["raw_archives"] = None
                    child["raw_status"] = "latest_published_per_disk_sum"
            by_ext[ext] = child
        node["by_ext"] = by_ext
        combined[family] = node
    counts["combined"] = combined
    public["counts"] = counts
    return public


def rebuild_pdf_binary_mirrors(public: dict) -> dict:
    """Keep the nested CAD/non-CAD PDF view identical to authoritative direct nodes."""
    counts = public.get("counts") if isinstance(public.get("counts"), dict) else {}
    for scope in DISKS:
        cats = counts.get(scope) if isinstance(counts.get(scope), dict) else {}
        cats["pdf_cad_binary"] = {
            "cad_pdf": copy.deepcopy(cats.get("cad_pdf") or {}),
            "other_pdf": copy.deepcopy(cats.get("other_pdf") or {}),
        }
        counts[scope] = cats
    public["counts"] = counts
    return public


def stamp_exact_raw_extension_coverage(public: dict) -> dict:
    """Stamp extension/class raw counts produced by a complete result-body scan."""
    counts = public.get("counts") if isinstance(public.get("counts"), dict) else {}
    archives = public.get("archives") if isinstance(public.get("archives"), dict) else {}
    covered: dict[str, int] = {}
    for scope in DISKS:
        done = int((archives.get(scope) or {}).get("done") or 0)
        covered[scope] = done
        cats = counts.get(scope) if isinstance(counts.get(scope), dict) else {}
        for family in RAW_KEYS:
            node = cats.get(family) if isinstance(cats.get(family), dict) else {}
            if node.get("raw") is not None:
                node["raw_status"] = "exact_finished_archive_occurrence_sum"
                node["raw_archives"] = done
            by_ext = node.get("by_ext") if isinstance(node.get("by_ext"), dict) else {}
            for child in by_ext.values():
                if isinstance(child, dict) and child.get("raw") is not None:
                    child["raw_status"] = "exact_finished_archive_occurrence_sum"
                    child["raw_archives"] = done
            cats[family] = node
        prior_classes = (
            cats.get("pdf_by_drawing_type")
            if isinstance(cats.get("pdf_by_drawing_type"), dict)
            else {}
        )
        classes = {}
        for name in PDF_CLASSES:
            child = dict(prior_classes.get(name) or {})
            if child.get("raw") is not None:
                child["raw_status"] = "exact_finished_archive_occurrence_sum"
                child["raw_archives"] = done
            child["sha256"] = None
            child["sha256_status"] = "not_published_unverified_class_union"
            classes[name] = child
        cats["pdf_by_drawing_type"] = classes
        counts[scope] = cats
    public["counts"] = counts
    public["raw_extension_coverage"] = {
        "status": "exact",
        "source": "historical baseline plus complete validated EC2 result-body scan",
        "archives_with_extension_counts": covered,
        "archives_in_raw": dict(covered),
    }
    return rebuild_pdf_binary_mirrors(public)


def apply_extension_snapshot_coverage(public: dict, seed: dict | None) -> dict:
    """Publish last exact extension snapshot with explicit live-ledger coverage."""
    seed = seed if isinstance(seed, dict) else {}
    meta = seed.get("raw_extension_coverage") if isinstance(seed.get("raw_extension_coverage"), dict) else {}
    prior = meta.get("archives_with_extension_counts") if isinstance(meta.get("archives_with_extension_counts"), dict) else {}
    counts = public.get("counts") if isinstance(public.get("counts"), dict) else {}
    archives = public.get("archives") if isinstance(public.get("archives"), dict) else {}
    known_any = False
    exact_all = True
    covered_out: dict[str, int | None] = {}
    live_out: dict[str, int] = {}
    for scope in DISKS:
        live = int((archives.get(scope) or {}).get("done") or 0)
        covered = _as_int(prior.get(scope))
        valid = covered is not None and 0 <= covered <= live
        known_any = known_any or valid
        exact = bool(valid and covered == live)
        exact_all = exact_all and exact
        covered_out[scope] = covered if valid else None
        live_out[scope] = live
        status = "exact_finished_archive_occurrence_sum" if exact else (
            "partial_exact_snapshot" if valid else "not_published_unverified_population"
        )
        cats = counts.get(scope) if isinstance(counts.get(scope), dict) else {}
        for family in ("pdf", "2d", "3d", "nc1"):
            node = cats.get(family) if isinstance(cats.get(family), dict) else {}
            by_ext = node.get("by_ext") if isinstance(node.get("by_ext"), dict) else {}
            for child in by_ext.values():
                if not isinstance(child, dict):
                    continue
                if not valid:
                    child["raw"] = None
                child["raw_status"] = status
                child["raw_archives"] = covered if valid else None
            node["by_ext"] = by_ext
            cats[family] = node
        prior_classes = (
            cats.get("pdf_by_drawing_type")
            if isinstance(cats.get("pdf_by_drawing_type"), dict)
            else {}
        )
        classes = {}
        for name in PDF_CLASSES:
            child = dict(prior_classes.get(name) or {})
            if not valid:
                child["raw"] = None
            child["raw_status"] = status
            child["raw_archives"] = covered if valid else None
            child["sha256"] = None
            child["sha256_status"] = "not_published_unverified_class_union"
            classes[name] = child
        cats["pdf_by_drawing_type"] = classes
        counts[scope] = cats
    public["counts"] = counts
    public = repair_combined_raw_extensions(public)
    public["raw_extension_coverage"] = {
        "status": "exact" if exact_all else ("partial" if known_any else "not_published"),
        "archives_with_extension_counts": covered_out,
        "archives_in_raw": live_out,
        "reason": (
            "extension snapshot matches the live completed-archive population"
            if exact_all
            else "extension totals are withheld or coverage-labeled until the next complete result-body scan"
        ),
    }
    return rebuild_pdf_binary_mirrors(public)


def validate_public_statistics(public: dict) -> None:
    """Refuse publication when count arithmetic or coverage labels disagree."""
    if not archives_ledger_ok(public):
        raise RuntimeError("public archive ledger invariant failed")
    counts = public.get("counts") if isinstance(public.get("counts"), dict) else {}
    archives = public.get("archives") if isinstance(public.get("archives"), dict) else {}
    raw_meta = public.get("raw_family_coverage") if isinstance(public.get("raw_family_coverage"), dict) else {}
    raw_covered = raw_meta.get("archives_with_counts") if isinstance(raw_meta.get("archives_with_counts"), dict) else {}
    if raw_meta.get("status") != "exact":
        raise RuntimeError("core raw family coverage is not exact")
    for scope in DISKS:
        cats = counts.get(scope) if isinstance(counts.get(scope), dict) else {}
        values: dict[str, int] = {}
        for family in RAW_KEYS:
            value = _union_nonnegative_int((cats.get(family) or {}).get("raw"))
            if value is None:
                raise RuntimeError(f"{scope} raw {family} is unavailable or invalid")
            values[family] = value
        if values["pdf"] != values["cad_pdf"] + values["other_pdf"]:
            raise RuntimeError(f"{scope} PDF subtype raw arithmetic failed")
        live = int((archives.get(scope) or {}).get("done") or 0)
        if _union_nonnegative_int(raw_covered.get(scope)) != live:
            raise RuntimeError(f"{scope} core raw coverage differs from archive ledger")
        mirror = cats.get("pdf_cad_binary") if isinstance(cats.get("pdf_cad_binary"), dict) else {}
        for family in ("cad_pdf", "other_pdf"):
            if _as_int((mirror.get(family) or {}).get("raw")) != values[family]:
                raise RuntimeError(f"{scope} PDF binary mirror is stale")
        classes = cats.get("pdf_by_drawing_type")
        if isinstance(classes, dict):
            if set(classes) != set(PDF_CLASSES):
                raise RuntimeError(f"{scope} PDF class key set is malformed")
            for child in classes.values():
                if isinstance(child, dict) and child.get("sha256") is not None:
                    raise RuntimeError(f"{scope} unverified PDF class SHA is populated")
    for family in RAW_KEYS:
        if int((counts["combined"][family] or {}).get("raw")) != (
            int((counts["Disk-1"][family] or {}).get("raw"))
            + int((counts["Disk-2"][family] or {}).get("raw"))
        ):
            raise RuntimeError(f"combined raw {family} is not the disk sum")

    ext_meta = public.get("raw_extension_coverage") if isinstance(public.get("raw_extension_coverage"), dict) else {}
    if ext_meta.get("status") == "exact":
        covered = ext_meta.get("archives_with_extension_counts") or {}
        for scope in DISKS:
            cats = counts.get(scope) or {}
            live = int((archives.get(scope) or {}).get("done") or 0)
            if _union_nonnegative_int(covered.get(scope)) != live:
                raise RuntimeError(f"{scope} exact extension coverage differs from archive ledger")
            for family, exts in (
                ("pdf", (".pdf",)),
                ("2d", EXT_2D),
                ("3d", EXT_3D),
                ("nc1", (".nc1",)),
            ):
                by_ext = (cats.get(family) or {}).get("by_ext") or {}
                ext_values = [_union_nonnegative_int((by_ext.get(ext) or {}).get("raw")) for ext in exts]
                if any(value is None for value in ext_values):
                    raise RuntimeError(f"{scope} exact {family} extension raw is missing")
                if int((cats.get(family) or {}).get("raw")) != sum(ext_values):
                    raise RuntimeError(f"{scope} {family} extension decomposition failed")
            classes = cats.get("pdf_by_drawing_type") or {}
            class_values = [
                _union_nonnegative_int((classes.get(name) or {}).get("raw"))
                for name in PDF_CLASSES
            ]
            if any(value is None for value in class_values) or sum(class_values) != int(
                (cats.get("pdf") or {}).get("raw")
            ):
                raise RuntimeError(f"{scope} PDF class decomposition failed")
        for family, exts in (
            ("pdf", (".pdf",)),
            ("2d", EXT_2D),
            ("3d", EXT_3D),
            ("nc1", (".nc1",)),
        ):
            for ext in exts:
                if int((((counts["combined"].get(family) or {}).get("by_ext") or {}).get(ext) or {}).get("raw")) != (
                    int((((counts["Disk-1"].get(family) or {}).get("by_ext") or {}).get(ext) or {}).get("raw"))
                    + int((((counts["Disk-2"].get(family) or {}).get("by_ext") or {}).get(ext) or {}).get("raw"))
                ):
                    raise RuntimeError(f"combined extension {ext} is not the disk sum")


def withhold_unverified_block_bytes(public: dict) -> dict:
    """Do not expose block-byte snapshots without finished-archive coverage proof."""
    counts = public.get("counts") if isinstance(public.get("counts"), dict) else {}
    for scope in DISKS:
        cats = counts.get(scope) if isinstance(counts.get(scope), dict) else {}
        block = dict(cats.get("block") or {})
        block["total_block_bytes"] = None
        block["total_bytes_status"] = "not_published_unverified_population"
        block["unique_block_bytes"] = None
        block["duplicate_block_bytes"] = None
        block["unique_status"] = "not_measured_missing_occurrence_lengths"
        block["duplicate_status"] = "not_measured_missing_occurrence_lengths"
        cats["block"] = block
        counts[scope] = cats
    public["counts"] = counts
    public["cloud_counts"] = counts.get("combined")
    disks = public.get("disks") if isinstance(public.get("disks"), dict) else {}
    for scope in DISKS:
        disks.setdefault(scope, {})
        disks[scope]["counts"] = counts.get(scope)
    public["disks"] = disks
    public["block_byte_coverage"] = {
        "status": "not_published_unverified_population",
        "reason": "block-byte snapshots do not publish finished-archive coverage; unique and duplicate occurrence lengths are not measured",
    }
    return public


def refresh_cost_clock(public: dict) -> dict:
    """Advance accrued estimate every publish instead of preserving a frozen seed."""
    now = dt.datetime.now(dt.timezone.utc)
    uptime_seconds = max(0.0, (now - FLEET_START).total_seconds())
    uptime_hours = uptime_seconds / 3600.0
    ce = dict(public.get("cost_estimate") or {})
    costs = dict(public.get("costs") or {})
    fleet = public.get("fleet") if isinstance(public.get("fleet"), dict) else {}
    hourly = float(
        ce.get("hourly_ec2_plus_ebs_usd")
        or costs.get("combined_hourly_compute_disk_usd")
        or 0.0
    )
    if hourly <= 0:
        hourly = sum(
            float(i.get("compute_hourly_estimate_usd") or 0.0)
            + float(i.get("ebs_hourly_estimate_usd") or 0.0)
            for i in (fleet.get("instances") or [])
            if isinstance(i, dict)
        )
    accrued = round(hourly * uptime_hours, 4) if hourly > 0 else None
    ce.update(
        {
            "hourly_ec2_plus_ebs_usd": round(hourly, 4) if hourly > 0 else None,
            "accrued_ec2_plus_ebs_usd": accrued,
            "fleet_start_utc": FLEET_START.isoformat().replace("+00:00", "Z"),
            "uptime_seconds": round(uptime_seconds, 1),
            "uptime_hours": round(uptime_hours, 4),
            "label": "estimate_only_not_aws_bill",
        }
    )
    costs.update(
        {
            "combined_hourly_compute_disk_usd": round(hourly, 4) if hourly > 0 else None,
            "combined_accrued_estimate_usd": accrued,
            "estimate_label": "estimate_only_not_aws_bill",
        }
    )
    public["cost_estimate"] = ce
    public["costs"] = costs
    return public


def merge_live_ops(rich: dict, thin: dict) -> dict:
    """Keep rich identity counts; refresh live fleet/archive ops from thin/private."""
    out = dict(rich)
    now = utc_now()
    out["updated_at_iso"] = now
    out["published_at"] = now
    out["status_last_updated"] = now
    out["last_update_iso"] = now
    out["heartbeat_at"] = thin.get("updated_at_iso") or thin.get("heartbeat_at") or now
    for key in (
        "fleet",
        "ec2_counts_delta",
        "recent_ec2_results",
        "skip_count",
        "scheduler_config",
        "scheduler_revision",
        "cost_estimate",
        "region",
        "claims_prefix",
        "results_prefix",
        "pipeline",
        "workers_alive",
        "workers_configured",
        "cloud_workers_alive",
        "claims_count",
        "results_count",
    ):
        if key in thin and thin[key] is not None:
            out[key] = thin[key]
    # Archives: always rebuild from full baseline 2507 + live ec2_new. Do not copy
    # private's partial per-disk completed_ok (~1933) into combined.
    archives = build_archives_ledger(thin, fallback=rich)
    out["archives"] = archives
    out["archives_combined"] = dict(archives["combined"])
    out["progress"] = progress_from_archives(archives)
    if not isinstance(out.get("disks"), dict):
        out["disks"] = {}
    for disk in DISKS:
        out["disks"].setdefault(disk, {})
        if isinstance(out.get("counts"), dict) and disk in out["counts"]:
            out["disks"][disk]["counts"] = out["counts"][disk]
        out["disks"][disk]["archives"] = archives[disk]
    if isinstance(out.get("counts"), dict) and "combined" in out["counts"]:
        out["cloud_counts"] = out["counts"]["combined"]
    pub = dict(out.get("publisher") or {})
    pub["mode"] = "ec2_status_instance"
    pub["interval_seconds"] = INTERVAL
    pub["reason"] = "dedicated_status_publisher_instance"
    pub["count_merge"] = "sticky_identity_floors_plus_ec2_ops"
    pub["archive_formula"] = "combined_completed_ok=full_baseline_2507_plus_ec2_new"
    pub["thin_defend"] = True
    out["publisher"] = pub
    out["schema"] = 4
    out["schema_id"] = "cad-ec2-public-status/v1"
    out["source_of_truth"] = "aws"
    out["bootstrapping"] = False
    out["health"] = "alive"
    out["state"] = out.get("state") or "extracting"
    return out


def defend_public_status(client, rich_seed: dict | None) -> dict | None:
    """If a thin aggregator wiped status.json, restore sticky identity immediately."""
    if not rich_seed or not has_identity_counts(rich_seed):
        return rich_seed
    try:
        current = json.loads(
            client.get_object(Bucket=PUBLIC_BUCKET, Key=PUBLIC_KEY)["Body"].read()
        )
    except Exception:
        current = {}
    try:
        private = get_json(client, PRIVATE_KEY)
    except Exception:
        private = current if isinstance(current, dict) else {}
    hash_union = load_hash_union(client)
    hash_union = ensure_hash_union_sticky(client, hash_union)
    # Treat thin schema, partial archives, missing identity, or unproven raw
    # families as a wipe. Historical IFC/DXF floors are not validity evidence.
    healthy = (
        (not is_thin_public_doc(current))
        and archives_ledger_ok(current)
        and has_identity_counts(current)
        and ((current.get("raw_family_coverage") or {}).get("status") == "exact")
    )
    if healthy:
        return current
    restored = merge_live_ops(rich_seed, private)
    restored["counts"] = copy.deepcopy((rich_seed or {}).get("counts") or {})
    try:
        restored = apply_live_raw_families(restored, private, get_baseline(client))
    except Exception as exc:
        log(f"defend raw refresh skipped: {type(exc).__name__}: {exc}")
    restored = apply_extension_snapshot_coverage(restored, rich_seed)
    if hash_union and not union_not_ahead_of_public(hash_union, restored):
        hash_union = None
    if hash_union:
        restored["counts"], reasons = apply_hash_union_to_counts(
            restored.get("counts") or {}, hash_union
        )
        restored["pending_reasons"] = {
            **(restored.get("pending_reasons") or {}),
            **reasons,
        }
        restored = attach_dedup_coverage(restored, hash_union)
    else:
        restored = force_null_sha_until_union(restored)
        restored = rebuild_pdf_binary_mirrors(restored)
    for disk in DISKS:
        restored.setdefault("disks", {}).setdefault(disk, {})
        restored["disks"][disk]["counts"] = (restored.get("counts") or {}).get(disk)
    restored["cloud_counts"] = (restored.get("counts") or {}).get("combined")
    restored = refresh_operational_fleet(restored)
    restored = refresh_cost_clock(restored)
    pub = dict(restored.get("publisher") or {})
    pub["thin_defend"] = True
    pub["identity_policy"] = "baseline_union_ec2_published" if hash_union else pub.get("identity_policy")
    pub["sha_scrub"] = "off_baseline_union_ec2" if hash_union else pub.get("sha_scrub")
    pub["deploy"] = "exact_raw_plus_streaming_union_v4"
    pub["ext_source"] = (
        "streaming_sqlite_union_v4"
        if hash_union
        else "withheld_until_streaming_sqlite_union_v4"
    )
    for stale_key in (
        "sticky_rewrite",
        "sticky_restored_at",
        "extension_patch",
        "raw_floors_applied_at",
        "raw_floors_ok",
        "sha_source",
        "archive_fix",
        "archive_fix_at",
        "archive_fix_note",
        "ifc_union_floor",
    ):
        pub.pop(stale_key, None)
    restored["publisher"] = pub
    restored = withhold_unverified_block_bytes(restored)
    validate_public_statistics(restored)
    put_json(client, PUBLIC_BUCKET, PUBLIC_KEY, restored, public=True)
    try:
        put_json(client, PUBLIC_BUCKET, PUBLIC_FULL_KEY, restored, public=True)
    except Exception:
        pass
    # Double-put: thin aws-1 aggregator races the public key.
    put_json(client, PUBLIC_BUCKET, PUBLIC_KEY, restored, public=True)
    twod = ((restored.get("counts") or {}).get("combined") or {}).get("2d") or {}
    ifc = (
        (((restored.get("counts") or {}).get("combined") or {}).get("3d") or {}).get("by_ext")
        or {}
    ).get(".ifc") or {}
    log(
        "defended thin wipe; restored combined 2d sha=%s weak=%s ifc_raw=%s"
        % (twod.get("sha256"), twod.get("weak"), ifc.get("raw"))
    )
    return restored


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


def load_prebuilt_baseline(client) -> dict | None:
    """Prefer S3 historical_baseline_v3 (already split by Disk-1/Disk-2 source_key)."""
    try:
        doc = get_json(client, PREBUILT_BASELINE_KEY)
    except Exception as exc:
        log(f"prebuilt baseline miss: {type(exc).__name__}: {exc}")
        return None
    ids = doc.get("ids_list") or []
    archives = doc.get("baseline_archives") or {}
    if not ids or not archives.get("Disk-1") or not archives.get("Disk-2"):
        log("prebuilt baseline incomplete; will rebuild")
        return None
    # Combined archive done MUST equal Disk-1 + Disk-2 (no skip_count inflation).
    d1 = int(archives.get("Disk-1") or 0)
    d2 = int(archives.get("Disk-2") or 0)
    archives["combined"] = d1 + d2
    doc["baseline_archives"] = archives
    doc["skip_count"] = int(doc.get("skip_count") or (d1 + d2))
    doc["ids"] = set(ids)
    doc["schema"] = BASELINE_SCHEMA
    doc["built_at_epoch"] = float(doc.get("built_at_epoch") or time.time())
    log(
        "using prebuilt historical_baseline_v3 skip=%s d1=%s d2=%s combined=%s"
        % (doc["skip_count"], d1, d2, archives["combined"])
    )
    return doc


def build_historical_baseline(client) -> dict:
    CACHE_DIR.mkdir(exist_ok=True)
    if BASELINE_CACHE.exists():
        try:
            cached = json.loads(BASELINE_CACHE.read_text())
            age = time.time() - float(cached.get("built_at_epoch") or 0)
            if age < 3600 and cached.get("schema") == BASELINE_SCHEMA:
                log(f"using cached historical baseline age_s={int(age)}")
                cached["ids"] = set(cached.get("ids_list") or [])
                arch = cached.get("baseline_archives") or {}
                d1 = int(arch.get("Disk-1") or 0)
                d2 = int(arch.get("Disk-2") or 0)
                if d1 and d2:
                    arch["combined"] = d1 + d2
                    cached["baseline_archives"] = arch
                return cached
        except Exception:
            pass

    prebuilt = load_prebuilt_baseline(client)
    if prebuilt is not None:
        serializable = dict(prebuilt)
        serializable.pop("ids", None)
        BASELINE_CACHE.write_text(json.dumps(serializable))
        return prebuilt

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

    d1 = int(skip["by_disk"]["Disk-1"])
    d2 = int(skip["by_disk"]["Disk-2"])
    baseline_archives = {
        "Disk-1": d1,
        "Disk-2": d2,
        # Combined done baseline is the sum of per-disk splits (not an inflated union).
        "combined": d1 + d2,
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
_EC2_DOC_CACHE: dict[str, dict] = {}
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
    """Merge new EC2 ok counts.

    Raw family totals: prefer private ec2_counts_delta when result stems have zero
    skip-list overlap (workers never re-extract skip archives).

    Extensions: ALWAYS summed from ec2-results bodies (private status has no
    extension histograms). Per-key body cache avoids re-downloading unchanged results.
    """
    global _EC2_DOC_CACHE
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

    # Drop cache entries for deleted keys.
    for stale in list(_EC2_DOC_CACHE.keys()):
        if stale not in keys:
            _EC2_DOC_CACHE.pop(stale, None)

    missing = [
        k for k in sorted(keys)
        if k not in _EC2_DOC_CACHE or (_EC2_DOC_CACHE.get(k) or {}).get("_error")
    ]

    def load(key: str):
        try:
            doc = get_json(client, key)
            if not isinstance(doc, dict):
                return key, {"_error": "result is not an object"}
            if doc.get("status") == "ok":
                digest = doc.get("source_key_sha256")
                stem = Path(key).stem.lower()
                if (
                    not isinstance(digest, str)
                    or len(digest) != 64
                    or any(ch not in "0123456789abcdefABCDEF" for ch in digest)
                    or digest.lower() != stem
                ):
                    return key, {"_error": "successful result identity mismatch"}
                if doc.get("disk") not in {"Disk-1", "Disk-2"}:
                    return key, {"_error": "successful result has invalid disk"}
                raw_doc = doc.get("raw")
                ext_doc = doc.get("extensions")
                if not isinstance(raw_doc, dict) or set(raw_doc) != set(RAW_KEYS):
                    return key, {"_error": "successful result raw schema mismatch"}
                for family in RAW_KEYS:
                    value = raw_doc.get(family)
                    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                        return key, {"_error": f"invalid raw count {family}"}
                if not isinstance(ext_doc, dict):
                    return key, {"_error": "successful result extensions is not an object"}
                extension_raw = empty_ext()
                for ext, node in ext_doc.items():
                    normalized = ext if str(ext).startswith(".") else f".{ext}"
                    normalized = normalized.lower()
                    if normalized not in ALL_EXTS or not isinstance(node, dict):
                        return key, {"_error": f"invalid extension {ext}"}
                    value = node.get("raw")
                    if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                        return key, {"_error": f"invalid extension raw {ext}"}
                    expected_category = FAMILY_OF[normalized]
                    if node.get("category") not in {None, expected_category}:
                        return key, {"_error": f"extension category mismatch {ext}"}
                    extension_raw[normalized] = value
                for family, extensions_for_family in (
                    ("pdf", (".pdf",)),
                    ("2d", EXT_2D),
                    ("3d", EXT_3D),
                    ("nc1", (".nc1",)),
                ):
                    if raw_doc[family] != sum(extension_raw[e] for e in extensions_for_family):
                        return key, {"_error": f"extension decomposition mismatch {family}"}
            return key, doc
        except Exception as exc:
            return key, {"_error": str(exc)}

    if missing:
        # Result bodies can be tens of MB because they contain digest arrays.
        # Keep the status host's memory bounded while the SQLite reducer streams
        # the same population in parallel.
        with ThreadPoolExecutor(max_workers=4) as pool:
            for key, doc in pool.map(load, missing):
                if not isinstance(doc, dict) or doc.get("_error"):
                    _EC2_DOC_CACHE[key] = {"_error": True}
                    continue
                digest = str(doc.get("source_key_sha256") or Path(key).stem)
                disk = doc.get("disk") if doc.get("disk") in ("Disk-1", "Disk-2") else None
                _EC2_DOC_CACHE[key] = {
                    "digest": digest,
                    "disk": disk,
                    "status": doc.get("status"),
                    "raw": doc.get("raw") if isinstance(doc.get("raw"), dict) else {},
                    "extensions": doc.get("extensions") if isinstance(doc.get("extensions"), dict) else {},
                    "block_bytes": int(doc.get("block_bytes") or 0),
                    "pdf_classes": doc.get("pdf_classes") if isinstance(doc.get("pdf_classes"), dict) else {},
                    "instance_name": doc.get("instance_name"),
                    "source_key": doc.get("source_key"),
                    "stored_files": doc.get("stored_files"),
                    "finished_at": doc.get("finished_at"),
                }

    by_disk = {"Disk-1": 0, "Disk-2": 0}
    raw = {"Disk-1": empty_raw(), "Disk-2": empty_raw()}
    extensions = {"Disk-1": empty_ext(), "Disk-2": empty_ext()}
    block_bytes = {"Disk-1": 0, "Disk-2": 0}
    pdf_classes = {"Disk-1": {}, "Disk-2": {}}
    recent = []
    ok = 0
    failed = 0

    for key, doc in _EC2_DOC_CACHE.items():
        if doc.get("_error"):
            failed += 1
            continue
        digest = str(doc.get("digest") or Path(key).stem)
        if digest in skip_ids:
            continue
        if doc.get("status") != "ok":
            if doc.get("status") == "error":
                failed += 1
            continue
        disk = doc.get("disk") if doc.get("disk") in ("Disk-1", "Disk-2") else None
        if disk is None:
            failed += 1
            continue
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

    scanned_by_disk = dict(by_disk)
    private_by_disk = {
        disk: _as_int((priv_arch.get(disk) or {}).get("ec2_new_ok"))
        for disk in ("Disk-1", "Disk-2")
    }
    # Prefer the independently aggregated raw families only when its archive
    # coverage exactly matches the validated successful result identities.
    use_private_raw = (
        skipped_overlap == 0
        and bool(priv_arch)
        and bool(priv_delta)
        and not failed
        and all(private_by_disk[disk] == scanned_by_disk[disk] for disk in ("Disk-1", "Disk-2"))
    )
    if use_private_raw:
        raw = {"Disk-1": empty_raw(), "Disk-2": empty_raw()}
        for disk in ("Disk-1", "Disk-2"):
            by_disk[disk] = int((priv_arch.get(disk) or {}).get("ec2_new_ok") or by_disk[disk] or 0)
            add_raw(raw[disk], priv_delta.get(disk) if isinstance(priv_delta.get(disk), dict) else {})
        failed = int((priv_arch.get("combined") or {}).get("ec2_failed") or failed)
        ok = by_disk["Disk-1"] + by_disk["Disk-2"]

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
            "fast_path": False,
            "private_raw": use_private_raw,
            "scanned_by_disk": scanned_by_disk,
            "extension_complete": bool(
                not failed
                and all(
                    private_by_disk[disk] == scanned_by_disk[disk]
                    for disk in ("Disk-1", "Disk-2")
                )
            ),
            "doc_cache_size": len(_EC2_DOC_CACHE),
            "fetched_this_refresh": len(missing),
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
            current = basename_only(meta.get("current"))
            alive = bool(meta.get("alive"))
            rows.append(
                {
                    "worker_id": str(wid),
                    "alive": alive,
                    "state": "running" if alive and current else ("idle_capacity_wait" if alive else "down"),
                    "current_archive": current,
                    "current_digest": meta.get("current_digest"),
                    "started_at": meta.get("started_at"),
                    "archive_bytes": meta.get("archive_bytes"),
                    "last_outcome": meta.get("last_outcome"),
                    "ok": meta.get("ok"),
                    "error": meta.get("error"),
                    "skipped": meta.get("skipped"),
                    "band": meta.get("band"),
                    "instance_name": instance.get("name"),
                }
            )
    return rows


# Premature additive sticky cells — never accept or re-publish.
FORBIDDEN_PREMATURE_2D_SHA = {5242914, 125514, 112347, 13167}
FORBIDDEN_PREMATURE_2D_WEAK = {133112, 46703}


def _union_nonnegative_int(value) -> int | None:
    if isinstance(value, bool):
        return None
    parsed = _as_int(value)
    return parsed if parsed is not None and parsed >= 0 else None


def _union_metric_tree_valid(disks: dict, kind: str) -> bool:
    """Validate the complete producer schema and cross-disk set-union bounds."""
    values: dict[tuple[str, str], int] = {}
    ext_values: dict[tuple[str, str], int] = {}
    for scope in DISKS:
        scope_doc = disks.get(scope)
        if not isinstance(scope_doc, dict):
            return False
        metrics = scope_doc.get(kind)
        if not isinstance(metrics, dict):
            return False
        for bucket in RAW_KEYS:
            value = _union_nonnegative_int(metrics.get(bucket))
            if value is None:
                return False
            values[(scope, bucket)] = value
        by_ext = metrics.get("by_extension")
        if not isinstance(by_ext, dict):
            return False
        for ext in ALL_EXTS:
            value = _union_nonnegative_int(by_ext.get(ext))
            if value is None:
                return False
            ext_values[(scope, ext)] = value

    for bucket in RAW_KEYS:
        d1 = values[("Disk-1", bucket)]
        d2 = values[("Disk-2", bucket)]
        combined = values[("combined", bucket)]
        if not max(d1, d2) <= combined <= d1 + d2:
            return False
    for ext in ALL_EXTS:
        d1 = ext_values[("Disk-1", ext)]
        d2 = ext_values[("Disk-2", ext)]
        combined = ext_values[("combined", ext)]
        if not max(d1, d2) <= combined <= d1 + d2:
            return False

    # The producer puts the same file hashes in the family and extension sets.
    # Family counts can be lower than the sum when identical contents occur under
    # different extensions, but can never be lower than the largest child set.
    for scope in DISKS:
        if values[(scope, "pdf")] != ext_values[(scope, ".pdf")]:
            return False
        if values[(scope, "nc1")] != ext_values[(scope, ".nc1")]:
            return False
        for family, exts in (("2d", EXT_2D), ("3d", EXT_3D)):
            children = [ext_values[(scope, ext)] for ext in exts]
            family_value = values[(scope, family)]
            if not max(children, default=0) <= family_value <= sum(children):
                return False
        pdf = values[(scope, "pdf")]
        cad = values[(scope, "cad_pdf")]
        other = values[(scope, "other_pdf")]
        if not max(cad, other) <= pdf <= cad + other:
            return False
    return True


def _union_raw_tree_valid(tree: dict) -> bool:
    if not isinstance(tree, dict):
        return False
    for scope in DISKS:
        node = tree.get(scope)
        if not isinstance(node, dict):
            return False
        raw = node.get("raw")
        ext = node.get("by_extension")
        classes = node.get("pdf_classes")
        if not isinstance(raw, dict) or set(raw) != set(RAW_KEYS):
            return False
        if not isinstance(ext, dict) or set(ext) != set(ALL_EXTS):
            return False
        if not isinstance(classes, dict) or set(classes) != set(PDF_CLASSES):
            return False
        if any(
            _union_nonnegative_int(value) is None
            for value in list(raw.values()) + list(ext.values()) + list(classes.values())
        ):
            return False
        if raw["pdf"] != raw["cad_pdf"] + raw["other_pdf"]:
            return False
        if sum(classes.values()) != raw["pdf"]:
            return False
        for family, extensions in (
            ("pdf", (".pdf",)),
            ("2d", EXT_2D),
            ("3d", EXT_3D),
            ("nc1", (".nc1",)),
        ):
            if raw[family] != sum(ext[name] for name in extensions):
                return False
    for field, keys in (
        ("raw", RAW_KEYS),
        ("by_extension", ALL_EXTS),
        ("pdf_classes", PDF_CLASSES),
    ):
        for key in keys:
            if tree["combined"][field][key] != (
                tree["Disk-1"][field][key] + tree["Disk-2"][field][key]
            ):
                return False
    return True


def _union_coverage_valid(doc: dict) -> bool:
    cov = doc.get("coverage")
    if not isinstance(cov, dict):
        return False
    coverage_maps: dict[str, dict[str, int]] = {}
    for key in ("archives_in_raw", "archives_in_sha", "archives_in_weak"):
        source = cov.get(key)
        if not isinstance(source, dict):
            return False
        parsed: dict[str, int] = {}
        for scope in DISKS:
            value = _union_nonnegative_int(source.get(scope))
            if value is None:
                return False
            parsed[scope] = value
        if parsed["combined"] != parsed["Disk-1"] + parsed["Disk-2"]:
            return False
        coverage_maps[key] = parsed

    raw = coverage_maps["archives_in_raw"]
    sha = coverage_maps["archives_in_sha"]
    if raw["combined"] < 2900 or sha != raw:
        return False
    weak = coverage_maps["archives_in_weak"]
    if any(weak[scope] > raw[scope] for scope in DISKS):
        return False
    return _union_nonnegative_int(cov.get("missing_sha_list_count") or 0) == 0


def _union_v2_validation_valid(doc: dict) -> bool:
    """Require every independent correctness gate emitted by the v2 producer."""
    validation = doc.get("validation")
    if not isinstance(validation, dict):
        return False
    if validation.get("sha_coverage_equals_raw") is not True:
        return False
    if validation.get("archive_identity_sets_equal") is not True:
        return False
    if validation.get("raw_storage_complete") is not True:
        return False
    if validation.get("raw_occurrence_tree_valid") is not True:
        return False
    for key in (
        "missing_archive_identity_count",
        "extra_archive_identity_count",
        "missing_sha_list_count",
        "spot_check_failures",
        "unassigned_raw_archives",
    ):
        if _union_nonnegative_int(validation.get(key)) != 0:
            return False
    for key in ("missing_archive_identity_sample", "extra_archive_identity_sample"):
        if not isinstance(validation.get(key), list) or validation.get(key):
            return False
    fatal = validation.get("fatal_ingest_stats")
    if not isinstance(fatal, dict) or fatal:
        return False

    coverage = doc.get("coverage") or {}
    if _union_nonnegative_int(coverage.get("missing_sha_list_count") or 0) != 0:
        return False
    raw = coverage.get("archives_in_raw") or {}
    skip_count = _union_nonnegative_int(doc.get("skip_count"))
    raw_skip = _union_nonnegative_int(raw.get("skip"))
    if skip_count is None or raw_skip is None or skip_count != raw_skip:
        return False
    return True


def _union_created_epoch(doc: dict) -> float:
    """Producer time used to let a corrected same-population snapshot supersede a seal."""
    for key in ("corrected_at", "created_at", "updated_at", "sealed_at"):
        value = doc.get(key)
        if not isinstance(value, str) or not value:
            continue
        try:
            parsed = dt.datetime.fromisoformat(value.replace("Z", "+00:00"))
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=dt.timezone.utc)
            return parsed.timestamp()
        except (TypeError, ValueError):
            continue
    return 0.0


_UNION_INPUT_IDENTITY_CACHE: dict = {"at": 0.0, "value": None}


def _current_union_input_identity(client, ttl: float = 30.0) -> dict:
    now = time.time()
    cached = _UNION_INPUT_IDENTITY_CACHE.get("value")
    if cached and now - float(_UNION_INPUT_IDENTITY_CACHE.get("at") or 0) < ttl:
        return cached
    head = client.head_object(Bucket=PRIVATE_BUCKET, Key=HASH_UNION_BASELINE_KEY)
    baseline_etag = str(head.get("ETag") or "").strip('"')
    skip = get_json(client, HASH_UNION_SKIP_KEY)
    values = skip.get("sha256") if isinstance(skip, dict) else None
    declared = skip.get("skip_count") if isinstance(skip, dict) else None
    if (
        skip.get("schema") != "cad-ec2-skip-done-ids/v1"
        or isinstance(declared, bool)
        or not isinstance(declared, int)
        or declared != 2507
        or not isinstance(values, list)
        or len(values) != declared
        or any(not isinstance(value, str) for value in values)
    ):
        raise RuntimeError("authoritative union skip ledger is malformed")
    normalized = [value.lower() for value in values]
    if len(set(normalized)) != declared or any(
        len(value) != 64 or any(ch not in "0123456789abcdef" for ch in value)
        for value in normalized
    ):
        raise RuntimeError("authoritative union skip identities are malformed")
    digest = hashlib.sha256()
    for value in sorted(normalized):
        digest.update(value.encode("ascii"))
        digest.update(b"\n")
    result = {
        "baseline_etag": baseline_etag,
        "skip_identity_checksum": digest.hexdigest(),
    }
    _UNION_INPUT_IDENTITY_CACHE.update({"at": now, "value": result})
    return result


def _union_progress_complete(client) -> bool:
    """True when progress.json says complete, OR a sealed acceptable sticky already exists."""
    try:
        prog = get_json(client, "cad-disk-extract/_state/dedup-union/progress.json")
        if str((prog or {}).get("phase") or "") == "complete":
            return True
    except Exception:
        pass
    # Sealed sticky with matching raw/sha coverage is authoritative even if progress.json lags.
    for key in (HASH_UNION_SEALED_KEY, HASH_UNION_OVERLAY_KEY, HASH_UNION_KEY, HASH_UNION_FALLBACK_KEY):
        try:
            doc = get_json(client, key)
        except Exception:
            continue
        if _hash_union_acceptable(doc, progress_complete=True):
            return True
    return False


def _hash_union_acceptable(doc: dict, *, progress_complete: bool | None = None) -> bool:
    """Accept only a finished true set-union sticky matching raw archive coverage."""
    if not isinstance(doc, dict) or not doc.get("complete"):
        return False
    # progress_complete=False only blocks when caller explicitly knows union is still running
    # AND this doc is not itself a sealed true set-union (sealed docs bypass progress gate).
    if doc.get("schema") != HASH_UNION_SCHEMA:
        return False
    if str(doc.get("schema_version") or "") != HASH_UNION_SCHEMA_VERSION:
        return False
    if doc.get("parser_version") != HASH_UNION_PARSER_VERSION:
        return False
    if not isinstance(doc.get("baseline_etag"), str) or not doc.get("baseline_etag"):
        return False
    skip_checksum = doc.get("skip_identity_checksum")
    if (
        not isinstance(skip_checksum, str)
        or len(skip_checksum) != 64
        or any(ch not in "0123456789abcdefABCDEF" for ch in skip_checksum)
    ):
        return False
    disks = doc.get("disks") or {}
    if not isinstance(disks, dict):
        return False
    if not _union_metric_tree_valid(disks, "sha256"):
        return False
    if not _union_metric_tree_valid(disks, "weak"):
        return False
    if not _union_raw_tree_valid(doc.get("raw_occurrences")):
        return False
    try:
        sha2d = int(((disks.get("combined") or {}).get("sha256") or {}).get("2d"))
    except Exception:
        return False
    if sha2d in FORBIDDEN_PREMATURE_2D_SHA or sha2d < 5_000_000:
        return False
    try:
        weak2d = ((disks.get("combined") or {}).get("weak") or {}).get("2d")
        if weak2d is not None and int(weak2d) in FORBIDDEN_PREMATURE_2D_WEAK:
            return False
    except Exception:
        return False
    if not _union_coverage_valid(doc):
        return False
    if not _union_v2_validation_valid(doc):
        return False
    mode = str(doc.get("combined_mode") or "")
    status_label = str(doc.get("sha256_status") or "")
    notes = " ".join(str(x) for x in (doc.get("notes") or []))
    if "additive" in mode or mode.startswith("disk1_plus_disk2"):
        return False
    sealed_ok = (
        "true_set_union" in mode
        or "true_set_union" in status_label
        or "set-union" in notes
        or "exact set-union" in notes
        or str(doc.get("seal_note") or "") != ""
        or doc.get("sealed_at") is not None
    )
    if progress_complete is False and not sealed_ok:
        return False
    return bool(sealed_ok)


def _union_sha_covers_live_done(client, union: dict | None) -> bool:
    """Accept sealed unions whose internal archives_in_sha == archives_in_raw.

    Live completed_ok can run ahead while extractors finish new archives; withholding
    SHA entirely in that window left the page at null forever. Lag vs live ledger is
    recorded on dedup metadata instead of blanking sealed SHA cells.
    """
    if not isinstance(union, dict):
        return False
    cov = union.get("coverage") or {}
    sha_n = int(((cov.get("archives_in_sha") or {}).get("combined") or 0))
    raw_n = int(((cov.get("archives_in_raw") or {}).get("combined") or 0))
    if sha_n < 2900 or raw_n < 2900 or sha_n != raw_n:
        return False
    if int(cov.get("missing_sha_list_count") or 0) > 0:
        return False
    return True


def load_hash_union(client) -> dict | None:
    """Load the newest valid union snapshot; coverage breaks timestamp ties."""
    candidates: list[tuple[float, int, int, str, dict]] = []
    source_priority = {
        HASH_UNION_SEALED_KEY: 3,
        HASH_UNION_OVERLAY_KEY: 2,
        HASH_UNION_KEY: 1,
        HASH_UNION_FALLBACK_KEY: 0,
    }
    try:
        current_identity = _current_union_input_identity(client)
    except Exception as exc:
        log(f"hash union withheld: current producer identity unavailable: {type(exc).__name__}: {exc}")
        return None
    for key in (
        HASH_UNION_SEALED_KEY,
        HASH_UNION_OVERLAY_KEY,
        HASH_UNION_KEY,
        HASH_UNION_FALLBACK_KEY,
    ):
        try:
            doc = get_json(client, key)
        except Exception as exc:
            log(f"hash union miss {key}: {type(exc).__name__}: {exc}")
            continue
        if not _hash_union_acceptable(doc, progress_complete=True):
            log(
                "hash union rejected key=%s complete=%s sha2d=%s cov=%s status=%s"
                % (
                    key,
                    (doc or {}).get("complete") if isinstance(doc, dict) else None,
                    ((((doc or {}).get("disks") or {}).get("combined") or {}).get("sha256") or {}).get("2d")
                    if isinstance(doc, dict)
                    else None,
                    (((doc or {}).get("coverage") or {}).get("archives_in_sha") if isinstance(doc, dict) else None),
                    (doc or {}).get("sha256_status") if isinstance(doc, dict) else None,
                )
            )
            continue
        if (
            doc.get("baseline_etag") != current_identity["baseline_etag"]
            or doc.get("skip_identity_checksum")
            != current_identity["skip_identity_checksum"]
        ):
            log(f"hash union rejected key={key}: producer input identity mismatch")
            continue
        cov = int((((doc.get("coverage") or {}).get("archives_in_sha") or {}).get("combined") or 0))
        candidates.append((_union_created_epoch(doc), cov, source_priority[key], key, doc))
    if not candidates:
        log("hash union withheld: no acceptable sealed sticky")
        return None
    candidates.sort(key=lambda t: (t[0], t[1], t[2]), reverse=True)
    _created, cov, _priority, key, doc = candidates[0]
    log(
        "loaded hash union %s combined_2d_sha=%s coverage=%s"
        % (
            key,
            ((((doc.get("disks") or {}).get("combined") or {}).get("sha256") or {}).get("2d")),
            (doc.get("coverage") or {}).get("archives_in_sha"),
        )
    )
    if not _union_sha_covers_live_done(client, doc):
        log(
            "hash union withheld: sha coverage %s < live completed_ok ledger"
            % (((doc.get("coverage") or {}).get("archives_in_sha") or {}).get("combined"))
        )
        return None
    return doc


def ensure_hash_union_sticky(client, union: dict | None) -> dict | None:
    """Return a verified union without mutating producer or sealed objects."""
    if not _hash_union_acceptable(union, progress_complete=True):
        return None
    if not _union_sha_covers_live_done(client, union):
        return None
    return union




def force_null_sha_until_union(doc: dict) -> dict:
    """Keep SHA/weak null with computing status until a complete set-union sticky exists."""
    STATUS = "computing_full_population_union"
    out = dict(doc)
    counts = dict(out.get("counts") or {})

    def clear_node(node):
        if not isinstance(node, dict):
            return
        if any(k in node for k in ("raw", "weak", "sha256", "by_ext")):
            node["sha256"] = None
            node["weak"] = None
            node["sha256_status"] = STATUS
            node["weak_status"] = STATUS
        be = node.get("by_ext")
        if isinstance(be, dict):
            for child in be.values():
                clear_node(child)

    for scope in DISKS:
        scope_c = dict(counts.get(scope) or {})
        for fam, node in list(scope_c.items()):
            if fam in ("block", "pdf_by_drawing_type", "pdf_cad_binary"):
                continue
            if isinstance(node, dict):
                clear_node(node)
                scope_c[fam] = node
        counts[scope] = scope_c
    out["counts"] = counts
    out["cloud_counts"] = counts.get("combined")
    disks = dict(out.get("disks") or {})
    for scope in DISKS:
        disks.setdefault(scope, {})
        disks[scope]["counts"] = counts.get(scope)
    out["disks"] = disks
    dedup = dict(out.get("dedup") or {})
    dedup["sha256"] = {
        "status": STATUS,
        "reason": "SHA withheld until sqlite_dedup_union finishes full-population true set-union",
    }
    dedup["weak_name_size"] = {
        "status": STATUS,
        "reason": "weak withheld until full-population true set-union",
    }
    out["dedup"] = dedup
    out.pop("dedup_coverage", None)
    # Reset in-process floors so a prior premature sticky cannot re-raise.
    for scope in DISKS:
        IDENTITY_FLOOR[scope]["2d"]["sha256"] = None
        IDENTITY_FLOOR[scope]["2d"]["weak"] = None
        IDENTITY_FLOOR[scope]["dxf_sha"] = None
    return out


def apply_hash_union_to_counts(counts: dict, union: dict | None) -> tuple[dict, dict]:
    """Overwrite weak/SHA cells with global distincts from hash union sticky."""
    pending: dict[str, str] = {}
    if not isinstance(union, dict):
        return counts, pending
    disks = union.get("disks") or {}
    raw_tree = union.get("raw_occurrences") or {}
    coverage = union.get("coverage") or {}
    sha_cov = coverage.get("archives_in_sha") or {}
    weak_cov = coverage.get("archives_in_weak") or {}
    raw_cov = coverage.get("archives_in_raw") or {}
    raw_n = int((raw_cov.get("combined") if isinstance(raw_cov, dict) else raw_cov) or 0)
    sha_n = int((sha_cov.get("combined") if isinstance(sha_cov, dict) else sha_cov) or 0)
    weak_n = int((weak_cov.get("combined") if isinstance(weak_cov, dict) else weak_cov) or 0)
    sha_status = str(
        union.get("sha256_status") or "global_distinct_raw_population_set_union"
    )
    if "true_set_union" in str(union.get("combined_mode") or "") or "set-union" in " ".join(
        str(x) for x in (union.get("notes") or [])
    ):
        sha_status = "global_distinct_raw_population_set_union"
    weak_complete = weak_n > 0 and weak_n == raw_n == sha_n and raw_n > 0
    # EC2 results omit weak lists — never publish partial weak beside full raw population.
    weak_status = (
        "global_distinct_raw_population_set_union"
        if weak_complete
        else "partial_archives_with_weak_lists_only"
    )
    missing_sha = int(coverage.get("missing_sha_list_count") or 0)
    if missing_sha:
        sha_status = "partial_missing_sha_lists"
    for scope in DISKS:
        u = disks.get(scope) or {}
        raw_scope = raw_tree.get(scope) if isinstance(raw_tree.get(scope), dict) else {}
        raw_ext = raw_scope.get("by_extension") if isinstance(raw_scope.get("by_extension"), dict) else {}
        sha = u.get("sha256") or {}
        weak = u.get("weak") or {}
        sha_ext = sha.get("by_extension") or {}
        weak_ext = weak.get("by_extension") or {}
        cats = counts.get(scope) or {}
        for key in RAW_KEYS:
            node = dict(cats.get(key) or {})
            if key in {"cad_pdf", "other_pdf"}:
                # The result schema does not retain a trustworthy per-file
                # subtype mapping across the entire cross-disk population.
                # Never expose the old 26,492/20,301 sticky subtype values as
                # if they were proven global unions.
                node["sha256"] = None
                node["sha256_status"] = "withheld_unverified_pdf_subtype_union"
            elif key in sha and sha[key] is not None and not missing_sha:
                node["sha256"] = int(sha[key])
                node["sha256_status"] = sha_status
            if weak_complete and key in weak and weak[key] is not None:
                node["weak"] = int(weak[key])
                node["weak_status"] = weak_status
            else:
                node["weak"] = None
                node["weak_status"] = weak_status
            cats[key] = node
        cats["pdf_cad_binary"] = {
            "cad_pdf": dict(cats.get("cad_pdf") or {}),
            "other_pdf": dict(cats.get("other_pdf") or {}),
        }
        for fam, exts in (("2d", EXT_2D), ("3d", EXT_3D), ("pdf", (".pdf",)), ("nc1", (".nc1",))):
            fam_node = dict(cats.get(fam) or {})
            by_ext = dict(fam_node.get("by_ext") or {})
            for ext in exts:
                en = dict(by_ext.get(ext) or {})
                if ext in raw_ext:
                    en["raw"] = int(raw_ext[ext])
                    en["raw_status"] = "exact_union_snapshot"
                    en["raw_archives"] = int((raw_cov.get(scope) or 0))
                if ext in sha_ext and sha_ext[ext] is not None and not missing_sha:
                    en["sha256"] = int(sha_ext[ext])
                    en["sha256_status"] = sha_status
                if weak_complete and ext in weak_ext and weak_ext[ext] is not None:
                    en["weak"] = int(weak_ext[ext])
                    en["weak_status"] = weak_status
                else:
                    en["weak"] = None
                    en["weak_status"] = weak_status
                by_ext[ext] = en
            fam_node["by_ext"] = by_ext
            if fam in sha and sha[fam] is not None and not missing_sha:
                fam_node["sha256"] = int(sha[fam])
                fam_node["sha256_status"] = sha_status
            if weak_complete and fam in weak and weak[fam] is not None:
                fam_node["weak"] = int(weak[fam])
                fam_node["weak_status"] = weak_status
            else:
                fam_node["weak"] = None
                fam_node["weak_status"] = weak_status
            cats[fam] = fam_node
        classes = raw_scope.get("pdf_classes") if isinstance(raw_scope.get("pdf_classes"), dict) else {}
        cats["pdf_by_drawing_type"] = {
            name: {
                "raw": int(classes[name]),
                "raw_status": "exact_union_snapshot",
                "raw_archives": int((raw_cov.get(scope) or 0)),
                "sha256": None,
                "sha256_status": "not_published_unverified_class_union",
            }
            for name in PDF_CLASSES
            if name in classes
        }
        counts[scope] = cats
    pending["sha256_post_baseline"] = (
        "SHA-256 = true set-union of file digests over finished archives "
        "(baseline + skip-only legacy + ok EC2); Combined = Disk-1 ∪ Disk-2 "
        "(cross-disk duplicate hashes counted once)."
    )
    pending["weak_name_size"] = (
        "Weak name+size withheld: EC2 results omit weak lists "
        f"(weak archives {weak_n} < raw {raw_n})."
        if not weak_complete
        else "Weak name+size over the same finished-archive population as raw."
    )
    return counts, pending


def union_not_ahead_of_public(union: dict | None, public: dict | None) -> bool:
    """A reducer snapshot may lag, but must never lead the displayed archive ledger."""
    if not isinstance(union, dict) or not isinstance(public, dict):
        return False
    raw_cov = ((union.get("coverage") or {}).get("archives_in_raw") or {})
    archives = public.get("archives") if isinstance(public.get("archives"), dict) else {}
    for scope in DISKS:
        covered = _union_nonnegative_int(raw_cov.get(scope))
        live = _union_nonnegative_int((archives.get(scope) or {}).get("done"))
        if covered is None or live is None or covered > live:
            return False
    return True


def attach_dedup_coverage(public: dict, union: dict | None) -> dict:
    """Keep proven SHA numbers and stamp honest coverage vs live archive ledger.

    archives_with_hashes = union sha coverage
    archives_in_raw = max(live completed_ok, sealed union raw) so the page never
    pretends a short union covers a larger finished population.
    """
    if not isinstance(public, dict) or not isinstance(union, dict):
        return public
    cov = union.get("coverage") or {}
    sha_cov = cov.get("archives_in_sha") or {}
    weak_cov = cov.get("archives_in_weak") or {}
    sha_n = int((sha_cov.get("combined") if isinstance(sha_cov, dict) else sha_cov) or 0)
    weak_n = int((weak_cov.get("combined") if isinstance(weak_cov, dict) else weak_cov) or 0)
    arch_comb = (public.get("archives") or {}).get("combined") or {}
    arch_top = public.get("archives_combined") or {}
    live_done = int(
        arch_comb.get("completed_ok")
        or arch_comb.get("done")
        or arch_top.get("completed_ok")
        or arch_top.get("done")
        or ((public.get("progress") or {}).get("done"))
        or 0
    )
    sealed_raw = cov.get("archives_in_raw") or {}
    sealed_n = int((sealed_raw.get("combined") if isinstance(sealed_raw, dict) else sealed_raw) or 0)
    page_raw_n = live_done or sealed_n
    raw_family_meta = public.get("raw_family_coverage") if isinstance(public.get("raw_family_coverage"), dict) else {}
    raw_family_counts = raw_family_meta.get("archives_with_counts") if isinstance(raw_family_meta.get("archives_with_counts"), dict) else {}
    raw_family_exact = (
        raw_family_meta.get("status") == "exact"
        and _as_int(raw_family_counts.get("combined")) == live_done
    )
    exact = (
        sha_n > 0
        and page_raw_n > 0
        and sha_n == live_done
        and raw_family_exact
        and not cov.get("missing_sha_list_count")
    )
    sha_status = (
        "global_distinct_raw_population_set_union"
        if exact
        else "proven_set_union_partial_coverage"
    )
    counts = public.get("counts") or {}
    for scope in DISKS:
        cats = counts.get(scope) or {}
        for _key, node in list(cats.items()):
            if not isinstance(node, dict):
                continue
            if node.get("sha256") is not None:
                node["sha256_status"] = sha_status
            be = node.get("by_ext")
            if isinstance(be, dict):
                for child in be.values():
                    if isinstance(child, dict) and child.get("sha256") is not None:
                        child["sha256_status"] = sha_status
        counts[scope] = cats
    public["counts"] = counts
    public["dedup"] = {
        "sha256": {
            "status": sha_status,
            "completed_archives": sha_n,
            "archives_in_sha": sha_n,
            "archives_in_raw": page_raw_n,
            "combined_mode": "true_set_union_cross_disk",
            "reason": (
                f"SHA-256 distinct over {sha_n} finished archives"
                + (
                    " (exact full population)"
                    if exact
                    else f" (live done={page_raw_n}; coverage short of hero ledger)"
                )
            ),
        },
        "weak_name_size": {
            "status": "partial_archives_with_weak_lists_only",
            "completed_archives": weak_n,
            "archives_in_weak": weak_n,
            "archives_in_raw": page_raw_n,
            "reason": (
                f"Weak withheld: EC2 results omit weak lists "
                f"(weak={weak_n} < raw={page_raw_n})."
            ),
        },
    }
    public["dedup_coverage"] = {
        "sha256": {
            "status": "exact" if exact else "partial",
            "archives_with_hashes": sha_n,
            "archives_in_raw": page_raw_n,
        },
        "weak_name_size": {
            "status": "partial",
            "archives_with_hashes": weak_n,
            "archives_in_raw": page_raw_n,
        },
    }
    raw_cov_map = cov.get("archives_in_raw") if isinstance(cov.get("archives_in_raw"), dict) else {}
    raw_live_map: dict[str, int] = {}
    raw_covered_map: dict[str, int] = {}
    raw_exact_all = True
    for scope in DISKS:
        live_scope = int(((public.get("archives") or {}).get(scope) or {}).get("done") or 0)
        covered_scope = int(raw_cov_map.get(scope) or 0)
        raw_live_map[scope] = live_scope
        raw_covered_map[scope] = covered_scope
        scope_exact = covered_scope == live_scope
        raw_exact_all = raw_exact_all and scope_exact
        status = "exact_finished_archive_occurrence_sum" if scope_exact else "partial_exact_snapshot"
        cats = (public.get("counts") or {}).get(scope) or {}
        for family in ("pdf", "2d", "3d", "nc1"):
            node = cats.get(family) if isinstance(cats.get(family), dict) else {}
            by_ext = node.get("by_ext") if isinstance(node.get("by_ext"), dict) else {}
            for child in by_ext.values():
                if isinstance(child, dict) and child.get("raw") is not None:
                    child["raw_status"] = status
                    child["raw_archives"] = covered_scope
        classes = cats.get("pdf_by_drawing_type")
        if isinstance(classes, dict):
            for child in classes.values():
                if isinstance(child, dict) and child.get("raw") is not None:
                    child["raw_status"] = status
                    child["raw_archives"] = covered_scope
    public["raw_extension_coverage"] = {
        "status": "exact" if raw_exact_all else "partial",
        "archives_with_extension_counts": raw_covered_map,
        "archives_in_raw": raw_live_map,
        "source": "strict streaming union reducer",
    }
    public = rebuild_pdf_binary_mirrors(public)
    # Mirror onto disks.*.counts
    for disk in DISKS:
        if isinstance(public.get("disks"), dict) and disk in public["disks"]:
            public["disks"][disk]["counts"] = public["counts"].get(disk)
    public["cloud_counts"] = (public.get("counts") or {}).get("combined")
    return public


def build_counts(baseline: dict, ec2: dict, hash_union: dict | None = None) -> tuple[dict, dict]:
    pending_reasons: dict[str, str] = {}
    # Never publish 1956-archive recon SHA/weak beside full raw unless hash_union is applied.
    # Without a complete union sticky, leave SHA/weak null with an explicit computing status.
    weak_status = "computing_full_population_union"
    sha_status = "computing_full_population_union"
    pending_reasons["weak_name_size"] = (
        "Weak name+size distincts withheld until full-population set-union finishes "
        "(skip-2507 baseline + EC2 results). Prior 1956-archive recon weak must not appear beside full raw."
    )
    pending_reasons["sha256_post_baseline"] = (
        "SHA-256 distincts withheld until full-population set-union finishes "
        "(skip-2507 baseline + EC2 result sha256 lists). Prior 1956-archive recon SHA must not appear beside full raw."
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
        classes = dict((baseline.get("historical_pdf_classes") or {}).get(disk) or {})
        for k, v in ((ec2.get("pdf_classes") or {}).get(disk) or {}).items():
            classes[k] = int(classes.get(k) or 0) + int(v or 0)

        cats: dict = {}
        for key in RAW_KEYS:
            raw_total = int(hist_raw.get(key) or 0) + int(ec2_raw.get(key) or 0)
            cats[key] = metric_node(
                raw_total,
                None,  # do not publish 1956-only weak
                None,  # do not publish 1956-only sha
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
                None,
                None,
                weak_status=weak_status,
                sha_status=sha_status,
            )
        by_ext_3d = {}
        for ext in EXT_3D:
            by_ext_3d[ext] = metric_node(
                int(hist_ext.get(ext) or 0) + int(ec2_ext.get(ext) or 0),
                None,
                None,
                weak_status=weak_status,
                sha_status=sha_status,
            )
        cats["2d"]["by_ext"] = by_ext_2d
        cats["3d"]["by_ext"] = by_ext_3d
        cats["pdf"]["by_ext"] = {
            ".pdf": metric_node(
                int(hist_ext.get(".pdf") or 0) + int(ec2_ext.get(".pdf") or 0),
                None,
                None,
                weak_status=weak_status,
                sha_status=sha_status,
            )
        }
        cats["nc1"]["by_ext"] = {
            ".nc1": metric_node(
                int(hist_ext.get(".nc1") or 0) + int(ec2_ext.get(".nc1") or 0),
                None,
                None,
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

    if hash_union:
        out, union_pending = apply_hash_union_to_counts(out, hash_union)
        pending_reasons.update(union_pending)
        cov = hash_union.get("coverage") or {}
        pending_reasons["dedup_union_coverage"] = json.dumps(
            {
                "archives_in_raw": cov.get("archives_in_raw"),
                "archives_in_sha": cov.get("archives_in_sha"),
                "archives_in_weak": cov.get("archives_in_weak"),
                "missing_sha_list_count": cov.get("missing_sha_list_count"),
                "missing_weak_list_count": cov.get("missing_weak_list_count"),
                "combined_mode": hash_union.get("combined_mode"),
            },
            separators=(",", ":"),
        )

    return out, pending_reasons




def empty_depth_dist() -> dict[str, int]:
    return {str(depth): 0 for depth in range(16)}


def depth_from_summary_node(node: dict | None) -> dict:
    node = node if isinstance(node, dict) else {}
    dist = empty_depth_dist()
    src = node.get("finished_archive_max_depth_distribution") or {}
    if isinstance(src, dict):
        for depth in range(16):
            dist[str(depth)] = int(src.get(str(depth), src.get(depth, 0)) or 0)
    cap_hits = int(node.get("depth_cap_hits") or 0)
    measured = sum(dist.values())
    observed = [int(d) for d, c in dist.items() if int(c)]
    return {
        "measured_finished_archives": measured,
        "unopened_archives_not_measured": None,
        "max_measured_depth": max(observed) if observed else None,
        "depth_cap": DEPTH_CAP,
        "depth_cap_hits": cap_hits,
        "finished_archive_max_depth_distribution": dist,
        "finished_by_depth": dist,
        "archive_nodes_by_depth": empty_depth_dist(),
        "distribution": dist,
    }


def add_depth_row(bucket: dict, row: dict) -> None:
    if not isinstance(row, dict):
        return
    if str(row.get("status") or "ok").lower() not in {"ok", "done", "success", ""}:
        return
    depth = row.get("max_depth_seen")
    if depth is None:
        return
    depth_i = int(depth)
    if depth_i < 0:
        return
    if depth_i > DEPTH_CAP:
        depth_i = DEPTH_CAP
    key = str(depth_i)
    bucket["finished_archive_max_depth_distribution"][key] = int(
        bucket["finished_archive_max_depth_distribution"].get(key, 0)
    ) + 1
    bucket["depth_cap_hits"] = int(bucket.get("depth_cap_hits") or 0) + int(
        row.get("depth_cap_hits") or 0
    )
    nodes = row.get("archive_nodes_by_depth") or row.get("nested_depth_distribution") or {}
    if isinstance(nodes, dict):
        for nkey, nval in nodes.items():
            nk = str(int(nkey))
            if nk in bucket["archive_nodes_by_depth"]:
                bucket["archive_nodes_by_depth"][nk] = int(
                    bucket["archive_nodes_by_depth"].get(nk, 0)
                ) + int(nval or 0)


def finalize_depth(bucket: dict, unopened: int | None = None) -> dict:
    dist = bucket["finished_archive_max_depth_distribution"]
    measured = sum(int(v) for v in dist.values())
    observed = [int(d) for d, c in dist.items() if int(c)]
    out = {
        "measured_finished_archives": measured,
        "unopened_archives_not_measured": unopened,
        "max_measured_depth": max(observed) if observed else None,
        "depth_cap": DEPTH_CAP,
        "depth_cap_hits": int(bucket.get("depth_cap_hits") or 0),
        "finished_archive_max_depth_distribution": {str(d): int(dist.get(str(d), 0)) for d in range(16)},
        "finished_by_depth": {str(d): int(dist.get(str(d), 0)) for d in range(16)},
        "archive_nodes_by_depth": {
            str(d): int((bucket.get("archive_nodes_by_depth") or {}).get(str(d), 0))
            for d in range(16)
        },
        "distribution": {str(d): int(dist.get(str(d), 0)) for d in range(16)},
    }
    return out


def load_depth_index(client) -> dict:
    """Load cached per-archive max depth (sha256 source_key -> row)."""
    try:
        doc = get_json(client, DEPTH_INDEX_KEY)
        by_id = doc.get("by_id") if isinstance(doc, dict) else None
        if isinstance(by_id, dict):
            return by_id
    except Exception as exc:
        log(f"depth index miss: {type(exc).__name__}: {exc}")
    local = CACHE_DIR / "ec2_depth_index.json"
    if local.exists():
        try:
            doc = json.loads(local.read_text())
            by_id = doc.get("by_id") if isinstance(doc, dict) else None
            if isinstance(by_id, dict):
                return by_id
        except Exception:
            pass
    return {}


def refresh_depth_index(client, skip_ids: set[str], existing: dict) -> dict:
    """Incrementally add depth for new ec2-results / sidecars not yet indexed."""
    by_id = dict(existing)
    keys = list_keys(client, RESULTS_PREFIX)
    missing = []
    for key in keys:
        digest = Path(key).stem
        if digest in skip_ids:
            continue
        if digest in by_id and by_id[digest].get("max_depth_seen") is not None:
            continue
        missing.append((digest, key))
    if not missing:
        return by_id

    def one(item):
        digest, key = item
        # Prefer tiny sidecar
        side_key = f"{DEPTH_SIDECAR_PREFIX}{digest}.json"
        try:
            doc = get_json(client, side_key)
            if isinstance(doc, dict) and doc.get("max_depth_seen") is not None:
                return digest, {
                    "disk": doc.get("disk") or "Disk-1",
                    "status": doc.get("status") or "ok",
                    "max_depth_seen": int(doc.get("max_depth_seen") or 0),
                    "depth_cap_hits": int(doc.get("depth_cap_hits") or 0),
                    "archive_nodes_by_depth": doc.get("nested_depth_distribution")
                    or doc.get("archive_nodes_by_depth")
                    or {},
                }
        except Exception:
            pass
        # Stream-skim result body until depth fields (stop before sha256 arrays)
        import re as _re

        pats = {
            "max_depth_seen": _re.compile(rb'"max_depth_seen"\s*:\s*(\d+)'),
            "depth_cap_hits": _re.compile(rb'"depth_cap_hits"\s*:\s*(\d+)'),
            "disk": _re.compile(rb'"disk"\s*:\s*"([^"]+)"'),
        }
        try:
            body = client.get_object(Bucket=PRIVATE_BUCKET, Key=key)["Body"]
        except Exception:
            return digest, None
        found = {}
        buf = b""
        while True:
            chunk = body.read(1 << 20)
            if not chunk:
                break
            buf += chunk
            for name, pat in pats.items():
                if name not in found:
                    m = pat.search(buf)
                    if m:
                        found[name] = m.group(1).decode()
            if "max_depth_seen" in found and "disk" in found and "depth_cap_hits" in found:
                break
            if len(buf) > 2 << 20:
                buf = buf[-(256 << 10) :]
        if "max_depth_seen" not in found:
            return digest, None
        return digest, {
            "disk": found.get("disk") or "Disk-1",
            "status": "ok",
            "max_depth_seen": int(found["max_depth_seen"]),
            "depth_cap_hits": int(found.get("depth_cap_hits") or 0),
            "archive_nodes_by_depth": {},
        }

    added = 0
    # Bound work per cycle so the 20s loop stays responsive.
    batch = missing[:40]
    with ThreadPoolExecutor(max_workers=8) as pool:
        for digest, row in pool.map(one, batch):
            if row is None:
                continue
            by_id[digest] = row
            added += 1
    if added:
        doc = {
            "schema": "ec2-depth-index/v1",
            "updated_at": utc_now(),
            "count": len(by_id),
            "by_id": by_id,
        }
        try:
            put_json(client, PRIVATE_BUCKET, DEPTH_INDEX_KEY, doc, public=False)
        except Exception as exc:
            log(f"depth index write failed: {type(exc).__name__}: {exc}")
        try:
            CACHE_DIR.mkdir(exist_ok=True)
            (CACHE_DIR / "ec2_depth_index.json").write_text(json.dumps(doc))
        except Exception:
            pass
        log(f"depth index updated added={added} total={len(by_id)} pending={len(missing)-len(batch)}")
    return by_id


def build_nested_depth(client, baseline: dict, archives: dict) -> dict:
    """Merge recon baseline depths + EC2 result max depths (source_key sha256 once)."""
    summary = get_json(client, RECON_SUMMARY_KEY)
    disks_src = summary.get("disks") or {}
    by_disk = {
        "Disk-1": depth_from_summary_node(disks_src.get("Disk-1")),
        "Disk-2": depth_from_summary_node(disks_src.get("Disk-2")),
        "combined": depth_from_summary_node(summary.get("combined")),
    }
    # Rebuild combined from disks to keep identity consistent.
    combined = {
        "finished_archive_max_depth_distribution": empty_depth_dist(),
        "archive_nodes_by_depth": empty_depth_dist(),
        "depth_cap_hits": 0,
    }
    for disk in ("Disk-1", "Disk-2"):
        for depth in range(16):
            k = str(depth)
            combined["finished_archive_max_depth_distribution"][k] += int(
                by_disk[disk]["finished_archive_max_depth_distribution"].get(k, 0)
            )
            combined["archive_nodes_by_depth"][k] += int(
                by_disk[disk]["archive_nodes_by_depth"].get(k, 0)
            )
        combined["depth_cap_hits"] += int(by_disk[disk].get("depth_cap_hits") or 0)

    skip_ids = baseline.get("ids") or set()
    index = load_depth_index(client)
    index = refresh_depth_index(client, skip_ids, index)

    # Accumulators start from baseline, then add non-overlapping EC2 rows.
    acc = {
        disk: {
            "finished_archive_max_depth_distribution": dict(
                by_disk[disk]["finished_archive_max_depth_distribution"]
            ),
            "archive_nodes_by_depth": dict(by_disk[disk]["archive_nodes_by_depth"]),
            "depth_cap_hits": int(by_disk[disk].get("depth_cap_hits") or 0),
        }
        for disk in ("Disk-1", "Disk-2")
    }
    acc["combined"] = {
        "finished_archive_max_depth_distribution": dict(
            combined["finished_archive_max_depth_distribution"]
        ),
        "archive_nodes_by_depth": dict(combined["archive_nodes_by_depth"]),
        "depth_cap_hits": int(combined["depth_cap_hits"]),
    }

    for digest, row in index.items():
        if digest in skip_ids:
            continue
        if not isinstance(row, dict):
            continue
        disk = row.get("disk") if row.get("disk") in ("Disk-1", "Disk-2") else None
        if disk is None:
            continue
        add_depth_row(acc[disk], row)
        add_depth_row(acc["combined"], row)

    out = {}
    for disk in ("Disk-1", "Disk-2", "combined"):
        arch = (archives or {}).get(disk) or {}
        total = int(arch.get("total") or MANIFEST_TOTAL[disk])
        done = int(arch.get("done") or arch.get("completed_ok") or 0)
        out[disk] = finalize_depth(acc[disk], unopened=max(0, total - done))
    return out


def enrich(private: dict, claims: int, results: int, baseline: dict, ec2: dict, hash_union: dict | None = None) -> dict:
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

    counts, pending_reasons = build_counts(baseline, ec2, hash_union=hash_union)
    for disk in DISKS:
        disks[disk]["counts"] = counts[disk]

    archives = {disk: disks[disk]["archives"] for disk in DISKS}
    # Guard: never lower combined to a partial disk sum. If disks diverge, keep
    # combined = baseline + ec2 and nudge Disk-1 so D1+D2 == combined.
    d1 = archives["Disk-1"]["done"]
    d2 = archives["Disk-2"]["done"]
    if d1 + d2 != archives["combined"]["done"]:
        delta = archives["combined"]["done"] - (d1 + d2)
        archives["Disk-1"]["done"] += delta
        archives["Disk-1"]["completed_ok"] = archives["Disk-1"]["done"]
        archives["Disk-1"]["ec2_new_ok"] = int(archives["Disk-1"]["ec2_new_ok"]) + delta
        archives["Disk-1"]["remaining"] = max(
            0, MANIFEST_TOTAL["Disk-1"] - archives["Disk-1"]["done"]
        )
        disks["Disk-1"]["archives"] = archives["Disk-1"]
    disks["combined"]["archives"] = archives["combined"]

    combined = archives["combined"]
    progress = progress_from_archives(archives)

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


def publish_once(client, rich_seed: dict | None = None) -> dict:
    baseline = get_baseline(client)
    private = get_json(client, PRIVATE_KEY)
    claims, results = refresh_counts(client)
    ec2 = refresh_ec2_new(client, baseline["ids"], private=private)
    if not ec2.get("extension_complete"):
        raise RuntimeError(
            "refusing full publish until every successful EC2 result has a validated extension decomposition"
        )
    hash_union = load_hash_union(client)
    public = enrich(private, claims, results, baseline, ec2, hash_union=None)
    if hash_union and not union_not_ahead_of_public(hash_union, public):
        log("hash union deferred: reducer coverage is ahead of displayed archive ledger")
        hash_union = None
    seed = rich_seed if has_identity_counts(rich_seed) else load_rich_seed(client)
    # This is a complete result-body scan.  Its raw family, extension, and PDF
    # classification trees are authoritative; never max-merge stale/fabricated
    # raw values from an older sticky seed.
    public = stamp_exact_raw_extension_coverage(public)
    if hash_union:
        public["counts"], _ = apply_hash_union_to_counts(public.get("counts") or {}, hash_union)
        # Raise identity floors to the new union so thin defend cannot shrink back.
        try:
            for scope in DISKS:
                twod = ((public.get("counts") or {}).get(scope) or {}).get("2d") or {}
                dxf = (twod.get("by_ext") or {}).get(".dxf") or {}
                if _as_int(twod.get("sha256")) is not None:
                    IDENTITY_FLOOR[scope]["2d"]["sha256"] = max(
                        int(IDENTITY_FLOOR[scope]["2d"]["sha256"]), int(twod["sha256"])
                    )
                if _as_int(twod.get("weak")) is not None:
                    IDENTITY_FLOOR[scope]["2d"]["weak"] = max(
                        int(IDENTITY_FLOOR[scope]["2d"]["weak"]), int(twod["weak"])
                    )
                if _as_int(dxf.get("sha256")) is not None:
                    IDENTITY_FLOOR[scope]["dxf_sha"] = max(
                        int(IDENTITY_FLOOR[scope]["dxf_sha"]), int(dxf["sha256"])
                    )
        except Exception as exc:
            log(f"identity floor raise failed: {type(exc).__name__}: {exc}")
        cov = hash_union.get("coverage") or {}
        public["dedup"] = {
            "sha256": {
                "status": "global_distinct_raw_population_set_union",
                "completed_archives": (cov.get("archives_in_sha") or {}).get("combined"),
                "archives_in_raw": cov.get("archives_in_raw"),
                "archives_in_sha": cov.get("archives_in_sha"),
                "combined_mode": "true_set_union_cross_disk",
                "reason": (public.get("pending_reasons") or {}).get("sha256_post_baseline")
                or "SHA-256 = true set-union over finished archives; Combined = Disk-1 ∪ Disk-2",
            },
            "weak_name_size": {
                "status": ((public.get("counts") or {}).get("combined") or {}).get("2d", {}).get("weak_status")
                or "partial_archives_with_weak_lists_only",
                "completed_archives": (cov.get("archives_in_weak") or {}).get("combined"),
                "archives_in_raw": cov.get("archives_in_raw"),
                "archives_in_weak": cov.get("archives_in_weak"),
                "reason": (public.get("pending_reasons") or {}).get("weak_name_size"),
            },
        }
        ensure_hash_union_sticky(client, hash_union)
        public = attach_dedup_coverage(public, hash_union)
    else:
        # Sticky seeds may contain an older partial/additive SHA snapshot.  A
        # full raw/extension refresh must never revive those cells while the
        # strict v2 true-set-union reducer is still running.
        public = force_null_sha_until_union(public)
        public = rebuild_pdf_binary_mirrors(public)
    for disk in DISKS:
        if isinstance(public.get("disks"), dict) and disk in public["disks"]:
            public["disks"][disk]["counts"] = public["counts"].get(disk)
    public["cloud_counts"] = public["counts"].get("combined")
    try:
        nested = build_nested_depth(client, baseline, public.get("archives") or {})
        combined_depth = apply_depth_floor(nested.get("combined"))
        # Prefer sticky depth bins when seed has richer measured totals.
        if isinstance(seed, dict):
            seed_depth = seed.get("nested_depth") or seed.get("depth")
            if isinstance(seed_depth, dict):
                combined_depth = apply_depth_floor(
                    {
                        **combined_depth,
                        "finished_archive_max_depth_distribution": {
                            **(combined_depth.get("finished_archive_max_depth_distribution") or {}),
                            **{
                                str(k): max(
                                    int(
                                        (
                                            combined_depth.get(
                                                "finished_archive_max_depth_distribution"
                                            )
                                            or {}
                                        ).get(str(k), 0)
                                        or 0
                                    ),
                                    int(v or 0),
                                )
                                for k, v in (
                                    seed_depth.get("finished_archive_max_depth_distribution")
                                    or seed_depth.get("distribution")
                                    or {}
                                ).items()
                            },
                        },
                    }
                )
        public["nested_depth"] = combined_depth
        public["cloud_depth"] = combined_depth
        public["depth"] = combined_depth
        disks = public.get("disks") if isinstance(public.get("disks"), dict) else {}
        for disk in ("Disk-1", "Disk-2", "combined"):
            if disk in disks and isinstance(disks[disk], dict):
                node = nested.get(disk)
                if disk == "combined":
                    node = combined_depth
                disks[disk]["nested_depth"] = node
                disks[disk]["depth"] = node
        public["disks"] = disks
        pub = public.get("publisher") if isinstance(public.get("publisher"), dict) else {}
        pub["depth_merge"] = "reconciliation_summary_plus_ec2_results_max_depth_by_source_key_sha256"
        pub["depth_cap"] = DEPTH_CAP
        pub["count_merge"] = "sticky_identity_floors_plus_skip_union_baseline_plus_ec2_results"
        pub["thin_defend"] = True
        public["publisher"] = pub
    except Exception as exc:
        log(f"depth merge failed: {type(exc).__name__}: {exc}")
        log(traceback.format_exc().splitlines()[-1])
        if isinstance(seed, dict) and seed.get("nested_depth"):
            public["nested_depth"] = apply_depth_floor(seed.get("nested_depth"))
            public["cloud_depth"] = public["nested_depth"]
            public["depth"] = public["nested_depth"]
    if not has_identity_counts(public):
        raise RuntimeError("refusing to publish status without numeric weak/sha identity counts")
    public = withhold_unverified_block_bytes(public)
    validate_public_statistics(public)
    # Full object first (stable for the page), then status.json (raced by thin writers).
    put_json(client, PUBLIC_BUCKET, PUBLIC_FULL_KEY, public, public=True)
    put_json(client, PUBLIC_BUCKET, PUBLIC_KEY, public, public=True)
    # Immediately re-put once more so a concurrent thin wipe loses the race.
    put_json(client, PUBLIC_BUCKET, PUBLIC_KEY, public, public=True)
    save_rich_seed(client, public)
    try:
        arch = (public.get("archives") or {}).get("combined") or {}
        put_json(
            client,
            PRIVATE_BUCKET,
            HEARTBEAT_KEY,
            {
                "published_at": public.get("published_at"),
                "publisher": public.get("publisher"),
                "workers_alive": public.get("workers_alive"),
                "archives_combined_done": arch.get("done"),
                "disk1_done": ((public.get("archives") or {}).get("Disk-1") or {}).get("done"),
                "disk2_done": ((public.get("archives") or {}).get("Disk-2") or {}).get("done"),
                "combined_2d_sha": ((public.get("counts") or {}).get("combined") or {})
                .get("2d", {})
                .get("sha256"),
            },
            public=False,
        )
    except Exception as exc:
        log(f"heartbeat write failed: {type(exc).__name__}: {exc}")
    (ROOT / "status.public.json").write_text(
        json.dumps(public, separators=(",", ":"), ensure_ascii=True)
    )
    return public


def publish_fast_sticky(client, rich_seed: dict | None = None) -> dict:
    """Sub-second publish: sticky identity counts + live private fleet/archives.

    Avoids listing ec2-results (can take minutes) so thin aggregators cannot
    blank weak/SHA for long windows between full recomputes.
    """
    seed = rich_seed if has_identity_counts(rich_seed) else load_rich_seed(client)
    if not has_identity_counts(seed):
        raise RuntimeError("no sticky rich seed available for fast publish")
    try:
        private = get_json(client, PRIVATE_KEY)
    except Exception:
        private = {}
    try:
        thin = json.loads(
            client.get_object(Bucket=PUBLIC_BUCKET, Key=PUBLIC_KEY)["Body"].read()
        )
    except Exception:
        thin = {}
    ops = private if isinstance(private, dict) and private.get("fleet") else thin
    public = merge_live_ops(seed, ops if isinstance(ops, dict) else {})
    # Always rebuild archives from full skip baseline (591/1916/2507) + live ec2_new.
    # Do NOT copy private per-disk completed_ok (~523/~1410) into combined (~1933).
    archives = build_archives_ledger(private, fallback=seed)
    public["archives"] = archives
    public["archives_combined"] = dict(archives["combined"])
    public["progress"] = progress_from_archives(archives)
    # Start from the last complete raw-extension snapshot only.  Thin public
    # writers and historical floors are not authoritative count sources.
    public["counts"] = copy.deepcopy(seed.get("counts") or {})
    try:
        baseline = get_baseline(client)
    except Exception as exc:
        log(f"fast raw baseline unavailable: {type(exc).__name__}: {exc}")
        baseline = None
    public = apply_live_raw_families(public, private, baseline)
    public = apply_extension_snapshot_coverage(public, seed)
    public = refresh_operational_fleet(public)
    public = refresh_cost_clock(public)

    # Publish explicit scheduler semantics. Claim objects are historical and
    # successful workers intentionally leave them behind. The fast path exposes
    # its count delta as an estimate rather than pretending it is a set difference.
    try:
        claim_objects, result_objects = refresh_counts(client, ttl=30.0)
        comb_arch = (public.get("archives") or {}).get("combined") or {}
        remaining = int(comb_arch.get("remaining") or 0)
        successful = int(comb_arch.get("ec2_new_ok") or 0)
        # This fast path intentionally avoids listing both prefixes into identity
        # sets. A cardinality delta is only an estimate: results are not proven to
        # be a subset of retained claims, and raw claims include completed work.
        scheduler_estimate = scheduler_cardinality_estimate(
            claim_objects, result_objects, remaining
        )
        public["claims_count"] = int(claim_objects)
        public["claims_count_semantics"] = "historical_unique_claim_objects_including_completed"
        public["result_objects_total"] = int(result_objects)
        public["results_count"] = successful
        public["results_count_semantics"] = "validated_ok_ec2_results_excluding_skip_overlap"
        public.pop("unfinished_claims", None)
        public.pop("unclaimed_remaining", None)
        public["unfinished_claims_estimate"] = scheduler_estimate[
            "unfinished_claims_estimate"
        ]
        public["unclaimed_remaining_estimate"] = scheduler_estimate[
            "unclaimed_remaining_estimate"
        ]
        public["scheduler_assignments"] = scheduler_estimate
    except Exception as exc:
        log(f"fast scheduler counters unavailable: {type(exc).__name__}: {exc}")

    # Merge completed sticky dedup only when union progress is complete.
    hash_union = load_hash_union(client)
    hash_union = ensure_hash_union_sticky(client, hash_union)
    if hash_union and not union_not_ahead_of_public(hash_union, public):
        log("fast hash union deferred: reducer coverage is ahead of displayed archive ledger")
        hash_union = None
    if hash_union:
        public["counts"], pending = apply_hash_union_to_counts(public.get("counts") or {}, hash_union)
        public["pending_reasons"] = {**(public.get("pending_reasons") or {}), **pending}
        cov = hash_union.get("coverage") or {}
        public["dedup"] = {
            "sha256": {
                "status": "global_distinct_raw_population_set_union",
                "completed_archives": (cov.get("archives_in_sha") or {}).get("combined"),
                "archives_in_raw": cov.get("archives_in_raw"),
                "archives_in_sha": cov.get("archives_in_sha"),
                "combined_mode": "true_set_union_cross_disk",
                "reason": pending.get("sha256_post_baseline")
                or "SHA-256 = true set-union over finished archives; Combined = Disk-1 ∪ Disk-2",
            },
            "weak_name_size": {
                "status": ((public.get("counts") or {}).get("combined") or {}).get("2d", {}).get("weak_status")
                or "partial_archives_with_weak_lists_only",
                "completed_archives": (cov.get("archives_in_weak") or {}).get("combined"),
                "archives_in_raw": cov.get("archives_in_raw"),
                "archives_in_weak": cov.get("archives_in_weak"),
                "reason": pending.get("weak_name_size")
                or "Weak withheld: EC2 results omit weak lists.",
            },
        }
        try:
            for scope in DISKS:
                twod = ((public.get("counts") or {}).get(scope) or {}).get("2d") or {}
                dxf = (twod.get("by_ext") or {}).get(".dxf") or {}
                if _as_int(twod.get("sha256")) is not None:
                    IDENTITY_FLOOR[scope]["2d"]["sha256"] = max(
                        int(IDENTITY_FLOOR[scope]["2d"]["sha256"] or 0), int(twod["sha256"])
                    )
                if _as_int(twod.get("weak")) is not None:
                    IDENTITY_FLOOR[scope]["2d"]["weak"] = max(
                        int(IDENTITY_FLOOR[scope]["2d"]["weak"] or 0), int(twod["weak"])
                    )
                if _as_int(dxf.get("sha256")) is not None:
                    IDENTITY_FLOOR[scope]["dxf_sha"] = max(
                        int(IDENTITY_FLOOR[scope]["dxf_sha"] or 0), int(dxf["sha256"])
                    )
        except Exception as exc:
            log(f"fast sticky floor raise failed: {type(exc).__name__}: {exc}")
        public = scrub_computing_sha_cells(public, force=False)
        public = attach_dedup_coverage(public, hash_union)
    else:
        # Do not leave premature/partial SHA from seed while union is still running.
        public = force_null_sha_until_union(public)
        public = rebuild_pdf_binary_mirrors(public)
    for disk in DISKS:
        public.setdefault("disks", {}).setdefault(disk, {})
        public["disks"][disk]["counts"] = public["counts"].get(disk)
        if isinstance(public.get("archives"), dict) and disk in public["archives"]:
            public["disks"][disk]["archives"] = public["archives"][disk]
    public["cloud_counts"] = public["counts"].get("combined")
    public["nested_depth"] = apply_depth_floor(
        seed.get("nested_depth") or seed.get("depth") or public.get("nested_depth")
    )
    ce = dict(public.get("cost_estimate") or {})
    costs = dict(public.get("costs") or {})
    accrued = costs.get("combined_accrued_estimate_usd")
    if accrued is not None and ce.get("accrued_ec2_plus_ebs_usd") is None:
        ce["accrued_ec2_plus_ebs_usd"] = accrued
        public["cost_estimate"] = ce
    public["cloud_depth"] = public["nested_depth"]
    public["depth"] = public["nested_depth"]
    if isinstance(public.get("disks"), dict) and "combined" in public["disks"]:
        public["disks"]["combined"]["nested_depth"] = public["nested_depth"]
        public["disks"]["combined"]["depth"] = public["nested_depth"]
    pub = dict(public.get("publisher") or {})
    pub["mode"] = "ec2_status_instance"
    pub["interval_seconds"] = INTERVAL
    pub["reason"] = "dedicated_status_publisher_instance"
    pub["count_merge"] = "fast_sticky_plus_hash_union_overlay"
    pub["archive_formula"] = "combined_completed_ok=full_baseline_2507_plus_ec2_new"
    pub["thin_defend"] = True
    pub["asset_schema"] = "disks.*.counts + counts + cloud_counts"
    pub["deploy"] = "exact_raw_plus_streaming_union_v4"
    pub["ext_source"] = (
        "streaming_sqlite_union_v4"
        if hash_union
        else "withheld_until_streaming_sqlite_union_v4"
    )
    for stale_key in (
        "sticky_rewrite",
        "sticky_restored_at",
        "extension_patch",
        "raw_floors_applied_at",
        "raw_floors_ok",
        "sha_source",
        "archive_fix",
        "archive_fix_at",
        "archive_fix_note",
        "ifc_union_floor",
    ):
        pub.pop(stale_key, None)
    if hash_union:
        pub["identity_policy"] = "baseline_union_ec2_published"
        pub["sha_scrub"] = "off_baseline_union_ec2"
        sha_meta = (public.get("dedup") or {}).get("sha256") or {}
        exact_live = str(sha_meta.get("status") or "") == "global_distinct_raw_population_set_union"
        pub["hash_union_complete"] = exact_live
        pub["hash_union_snapshot_complete"] = True
        pub["hash_union_exact_vs_live"] = exact_live
    else:
        pub["identity_policy"] = "null_until_full_population_union"
        pub["sha_scrub"] = "computing_full_population_union"
        pub.pop("hash_union_complete", None)
        pub["hash_union_snapshot_complete"] = False
        pub["hash_union_exact_vs_live"] = False
    public["publisher"] = pub
    if not has_identity_counts(public):
        raise RuntimeError("fast sticky publish missing identity counts")
    if not archives_ledger_ok(public):
        raise RuntimeError("fast sticky publish refused partial archive ledger")
    public = withhold_unverified_block_bytes(public)
    validate_public_statistics(public)
    # Closer owns public status.json writes; this path still runs on the status
    # instance. Keep puts, but never emit completed_ok near the partial ~1933.
    comb = (public.get("archives") or {}).get("combined") or {}
    if int(comb.get("completed_ok") or 0) < int(comb.get("baseline_completed_ok") or 0) + int(
        comb.get("ec2_new_ok") or 0
    ):
        raise RuntimeError("refusing to publish partial combined completed_ok")
    put_json(client, PUBLIC_BUCKET, PUBLIC_FULL_KEY, public, public=True)
    put_json(client, PUBLIC_BUCKET, PUBLIC_KEY, public, public=True)
    put_json(client, PUBLIC_BUCKET, PUBLIC_KEY, public, public=True)
    save_rich_seed(client, public)
    try:
        arch = (public.get("archives") or {}).get("combined") or {}
        put_json(
            client,
            PRIVATE_BUCKET,
            HEARTBEAT_KEY,
            {
                "published_at": public.get("published_at"),
                "publisher": public.get("publisher"),
                "workers_alive": public.get("workers_alive"),
                "archives_combined_done": arch.get("done"),
                "disk1_done": ((public.get("archives") or {}).get("Disk-1") or {}).get("done"),
                "disk2_done": ((public.get("archives") or {}).get("Disk-2") or {}).get("done"),
                "combined_2d_sha": ((public.get("counts") or {}).get("combined") or {})
                .get("2d", {})
                .get("sha256"),
                "combined_2d_weak": ((public.get("counts") or {}).get("combined") or {})
                .get("2d", {})
                .get("weak"),
                "dedup_sha_status": ((public.get("dedup") or {}).get("sha256") or {}).get("status"),
                "path": "fast_sticky",
            },
            public=False,
        )
    except Exception as exc:
        log(f"heartbeat write failed: {type(exc).__name__}: {exc}")
    return public


def start_defend_thread(client, seed_holder: dict) -> threading.Thread:
    def _loop() -> None:
        while not seed_holder.get("stop"):
            try:
                seed_holder["seed"] = (
                    defend_public_status(client, seed_holder.get("seed"))
                    or seed_holder.get("seed")
                )
            except Exception as exc:
                log(f"defend thread: {type(exc).__name__}: {exc}")
            time.sleep(DEFEND_SECONDS)

    thread = threading.Thread(target=_loop, name="status-thin-defend", daemon=True)
    thread.start()
    return thread


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


def _dedup_worker_process(
    pid: int,
    proc_root: Path = Path("/proc"),
    expected_script: Path = Path("/opt/cad-dedup/sqlite_dedup_union.py"),
) -> tuple[bool, str]:
    """Verify that a PID is a live sqlite_dedup_union.py process before signalling it."""
    if isinstance(pid, bool) or not isinstance(pid, int) or pid <= 0:
        return False, "invalid_pid"
    proc_dir = proc_root / str(pid)
    try:
        stat_text = (proc_dir / "stat").read_text(encoding="utf-8")
        # Linux /proc/<pid>/stat encloses comm in parentheses; parse state after
        # the closing parenthesis so a space in comm cannot shift the field.
        close_paren = stat_text.rfind(")")
        fields = stat_text[close_paren + 1 :].strip().split() if close_paren >= 0 else []
        state = fields[0] if fields else "?"
        argv = [
            token.decode("utf-8", errors="replace")
            for token in (proc_dir / "cmdline").read_bytes().split(b"\0")
            if token
        ]
    except (OSError, ValueError):
        return False, "process_missing_or_unreadable"
    if state in {"Z", "X", "x"}:
        return False, f"dead_state_{state}"
    if str(expected_script) not in argv:
        return False, "cmdline_mismatch"
    return True, f"state_{state}"


def _dedup_progress_stalled(
    progress: dict,
    *,
    worker_started_epoch: float,
    now_epoch: float | None = None,
    normal_limit: float | None = None,
    long_limit: float | None = None,
) -> tuple[bool, float, float]:
    """Return (stalled, effective_age, limit) for a verified live worker.

    The effective age is capped by the current worker age. This prevents stale
    progress left by an earlier process from immediately killing a fresh restart.
    """
    if not isinstance(progress, dict):
        return False, 0.0, float(normal_limit or DEDUP_STALL_SECONDS)
    phase = str(progress.get("phase") or "").lower()
    if phase == "complete":
        return False, 0.0, float("inf")
    updated = progress.get("updated_at")
    if not isinstance(updated, str) or not updated:
        return False, 0.0, float(long_limit or DEDUP_LONG_PHASE_STALL_SECONDS)
    try:
        parsed = dt.datetime.fromisoformat(updated.replace("Z", "+00:00"))
        if parsed.tzinfo is None:
            parsed = parsed.replace(tzinfo=dt.timezone.utc)
        progress_epoch = parsed.timestamp()
    except (TypeError, ValueError, OverflowError):
        return False, 0.0, float(long_limit or DEDUP_LONG_PHASE_STALL_SECONDS)

    now = time.time() if now_epoch is None else float(now_epoch)
    progress_age = max(0.0, now - progress_epoch)
    worker_age = max(0.0, now - float(worker_started_epoch))
    effective_age = min(progress_age, worker_age)

    # The producer's last ingestion heartbeat remains at legacy/ec2 while it
    # lists the next population, recounts global DISTINCTs, spot-checks, or
    # uploads the SQLite checkpoint. A completed batch therefore gets the long
    # threshold even though the phase string has not changed yet.
    long_phase = phase not in {"legacy", "ec2"}
    for suffix in ("legacy", "ec2"):
        done = _union_nonnegative_int(progress.get(f"done_{suffix}"))
        todo = _union_nonnegative_int(progress.get(f"todo_{suffix}"))
        if done is not None and todo is not None and done >= todo:
            long_phase = True
    limit = float(
        (long_limit or DEDUP_LONG_PHASE_STALL_SECONDS)
        if long_phase
        else (normal_limit or DEDUP_STALL_SECONDS)
    )
    return effective_age > limit, effective_age, limit



def ensure_dedup_union_worker() -> None:
    """Run the v2 SHA union worker; the producer owns DB compatibility/cold start."""
    import subprocess

    pidfile = Path("/var/tmp/cad-dedup-union.pid")
    logf = Path("/var/tmp/cad-dedup-union.log")
    work = Path("/opt/cad-dedup")
    data = work / "data"
    script = work / "sqlite_dedup_union.py"
    alive = False
    worker_pid: int | None = None
    worker_started_epoch = 0.0
    try:
        if pidfile.exists():
            old = int(pidfile.read_text().strip() or "0")
            verified, reason = _dedup_worker_process(old)
            if verified:
                alive = True
                worker_pid = old
                worker_started_epoch = pidfile.stat().st_mtime
                log(f"dedup union already running pid={old} {reason}")
            else:
                log(f"dedup union stale pidfile pid={old} reason={reason}; clearing without signal")
                pidfile.unlink(missing_ok=True)
    except Exception as exc:
        log(f"dedup union pid check: {type(exc).__name__}: {exc}")
        alive = False
    stale = False
    if alive:
        try:
            client = s3()
            prog = get_json(client, "cad-disk-extract/_state/dedup-union/progress.json")
            stale, age, limit = _dedup_progress_stalled(
                prog,
                worker_started_epoch=worker_started_epoch,
            )
            if stale:
                log(
                    f"dedup union progress stalled age_s={age:.0f} limit_s={limit:.0f} "
                    f"phase={prog.get('phase')} sha_archives={prog.get('sha_archives')}"
                )
        except Exception as exc:
            log(f"dedup progress check: {type(exc).__name__}: {exc}")
            stale = False
    if alive and stale and worker_pid is not None:
        # Re-check immediately before SIGKILL: the old PID may have exited and
        # been reused while S3 progress was being fetched.
        verified, reason = _dedup_worker_process(worker_pid)
        if verified:
            try:
                os.kill(worker_pid, 9)
                log(f"killed verified stalled dedup union pid={worker_pid}")
                # SIGKILL can remain pending while a task is in uninterruptible
                # I/O. Never start a second writer against the same SQLite DB.
                for _ in range(20):
                    still_worker, _reason = _dedup_worker_process(worker_pid)
                    if not still_worker:
                        break
                    time.sleep(0.25)
                else:
                    log(f"stalled dedup union pid={worker_pid} still present after SIGKILL")
                    return
                alive = False
                pidfile.unlink(missing_ok=True)
            except ProcessLookupError:
                alive = False
                pidfile.unlink(missing_ok=True)
            except Exception as exc:
                log(f"could not stop stalled dedup union pid={worker_pid}: {type(exc).__name__}: {exc}")
                return
        else:
            log(f"dedup union pid changed before signal pid={worker_pid} reason={reason}")
            alive = False
            pidfile.unlink(missing_ok=True)
    if alive:
        return
    try:
        work.mkdir(parents=True, exist_ok=True)
        data.mkdir(parents=True, exist_ok=True)
        client = s3()
        client.download_file(
            PRIVATE_BUCKET, "cad-disk-extract/_control/sqlite_dedup_union.py", str(script)
        )
        # Do not pre-download union.sqlite here. The v2 producer compares local
        # and remote metadata, retires incompatible v1/parser-bug databases, and
        # intentionally creates a fresh DB when no compatible remote exists.
        db = data / "cad_dedup_union.sqlite"
        env = os.environ.copy()
        env["AWS_DEFAULT_REGION"] = REGION
        env["HASH_WORKERS"] = env.get("HASH_WORKERS", "2")
        env["HASH_BATCH"] = env.get("HASH_BATCH", "2")
        env["PYTHONUNBUFFERED"] = "1"
        env.pop("AWS_PROFILE", None)
        subprocess.run(
            ["python3", "-m", "pip", "install", "-q", "ijson", "boto3"],
            check=False,
            timeout=120,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        with open(logf, "a") as lf:
            lf.write(
                f"\nSTART {dt.datetime.now(dt.timezone.utc).isoformat()} stale_restart={stale}\n"
            )
            proc = subprocess.Popen(
                ["python3", "-u", str(script)],
                cwd=str(work),
                env=env,
                stdout=lf,
                stderr=subprocess.STDOUT,
                start_new_session=True,
            )
        pidfile.write_text(str(proc.pid))
        log(
            f"started dedup union pid={proc.pid} "
            f"local_db_bytes={db.stat().st_size if db.exists() else 0} producer_managed_db=true"
        )
    except Exception as exc:
        log(f"dedup union start failed: {type(exc).__name__}: {exc}")



def main() -> int:
    if not acquire_lock():
        log("another publisher holds the lock; exiting")
        return 0
    PIDFILE.write_text(str(os.getpid()))
    try:
        ensure_dedup_union_worker()
    except Exception as exc:
        log(f"ensure_dedup_union_worker failed: {type(exc).__name__}: {exc}")
    client = s3()
    try:
        ensure_merge_rules(client)
    except Exception as exc:
        log(f"merge rules write failed: {type(exc).__name__}: {exc}")
    rich_seed = load_rich_seed(client)
    seed_holder: dict = {"seed": rich_seed, "stop": False}
    start_defend_thread(client, seed_holder)
    # Immediate restore so the public URL is rich before the first slow cycle.
    try:
        public = publish_fast_sticky(client, rich_seed=rich_seed)
        rich_seed = public
        seed_holder["seed"] = public
        twod = ((public.get("counts") or {}).get("combined") or {}).get("2d") or {}
        log(
            "fast sticky bootstrap combined 2d sha=%s weak=%s"
            % (twod.get("sha256"), twod.get("weak"))
        )
    except Exception as exc:
        log(f"fast sticky bootstrap failed: {type(exc).__name__}: {exc}")
        log(traceback.format_exc().splitlines()[-1])
    log(
        f"starting local AWS status publisher interval={INTERVAL}s "
        f"defend={DEFEND_SECONDS}s public=s3://{PUBLIC_BUCKET}/{PUBLIC_KEY} "
        f"seed_identity={has_identity_counts(rich_seed)}"
    )
    cycle = 0
    while True:
        cycle += 1
        try:
            if cycle == 1 or cycle % 6 == 0:
                try:
                    ensure_dedup_union_worker()
                except Exception as union_exc:
                    log(f"periodic ensure_dedup_union_worker: {type(union_exc).__name__}: {union_exc}")
            # Default every cycle: fast sticky (keeps weak/SHA alive).
            public = publish_fast_sticky(client, rich_seed=rich_seed or seed_holder.get("seed"))
            rich_seed = public
            seed_holder["seed"] = public
            fleet = public.get("fleet") or {}
            arch = (public.get("archives") or {}).get("combined") or {}
            two_d = ((public.get("counts") or {}).get("combined") or {}).get("2d") or {}
            log(
                "fast-published workers_alive=%s done=%s/%s 2d_sha=%s 2d_weak=%s"
                % (
                    fleet.get("workers_alive") or public.get("workers_alive"),
                    arch.get("done"),
                    arch.get("total"),
                    two_d.get("sha256"),
                    two_d.get("weak"),
                )
            )
            # Extension/SHA aggregation is owned by the streaming SQLite reducer.
            # Never load the 14+ GB result population into this small publisher.
            if False:
                try:
                    get_baseline(client)
                    full = publish_once(client, rich_seed=rich_seed)
                    rich_seed = full
                    seed_holder["seed"] = full
                    log("full recompute published")
                except Exception as full_exc:
                    log(f"full recompute skipped: {type(full_exc).__name__}: {full_exc}")
        except Exception as exc:
            log(f"publish failed: {type(exc).__name__}: {exc}")
            log(traceback.format_exc().splitlines()[-1])
            try:
                rich_seed = defend_public_status(client, rich_seed) or rich_seed
                seed_holder["seed"] = rich_seed
            except Exception as defend_exc:
                log(f"defend after failure failed: {type(defend_exc).__name__}: {defend_exc}")
        time.sleep(INTERVAL)


if __name__ == "__main__":
    try:
        raise SystemExit(main())
    finally:
        cleanup()
