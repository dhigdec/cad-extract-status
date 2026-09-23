#!/usr/bin/env python3
"""Low-memory SHA/weak global distinct union via SQLite (exact set-union).

Population once by sha256(source_key):
  baseline completed ids (seeded hash lists) + skip-only legacy results + new EC2 ok results.

Combined = true cross-disk set-union. Checkpoints under
  s3://annotationprod/cad-disk-extract/_state/dedup-union/
"""
from __future__ import annotations

import io
import hashlib
import json
import os
import shutil
import sqlite3
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

import boto3
import ijson
from botocore.config import Config

PROFILE = os.environ.get("AWS_PROFILE", "annotationprod-publish")
REGION = "ap-south-1"
PRIVATE = "annotationprod"
BASELINE_KEY = "cad-disk-extract/_state/reconciliation/baseline_per_disk.json"
SKIP_KEY = "cad-disk-extract/_control/ec2-skip-done-ids.json"
EC2_PREFIX = "cad-disk-extract/_state/ec2-results/"
LEGACY_PREFIX = "cad-disk-extract/_state/results/"
OUT_KEY = "cad-disk-extract/_control/hash_union_counts.json"
STICKY_KEY = "cad-disk-extract/_state/dedup-union/sticky_dedup_counts.json"
PROGRESS_KEY = "cad-disk-extract/_state/dedup-union/progress.json"
COVERAGE_KEY = "cad-disk-extract/_state/dedup-union/coverage.json"
SPOT_KEY = "cad-disk-extract/_state/dedup-union/spot_checks.json"
DONE_KEY = "cad-disk-extract/_state/dedup-union/done_keys.json"
DB_KEY = "cad-disk-extract/_state/dedup-union/union.sqlite"
DB_META_KEY = "cad-disk-extract/_state/dedup-union/union.sqlite.meta.json"
DATA_DIR = Path("/opt/cad-dedup/data")
LOCAL_BASELINE = DATA_DIR / "baseline_per_disk.json"
# Root disk, not /tmp tmpfs — union.sqlite (~731MB+) will not fit on a ~1G RAM tmpfs.
LOCAL_DB = DATA_DIR / "cad_dedup_union.sqlite"
PARALLEL_CKPT = Path("/Users/dhiren/Library/Caches/cad-dedup-union-parallel/dedup_union_ckpt.pkl")
LOCAL_OUT = Path("/tmp/hash_union_counts.json")
WORKERS = int(os.environ.get("HASH_WORKERS", "2"))
BATCH = int(os.environ.get("HASH_BATCH", "2"))
SCHEMA_VERSION = "2"
PARSER_VERSION = "4-complete-bucket-raw-coverage"
EXPECTED_SKIP_COUNT = 2507

RAW_KEYS = ("pdf", "cad_pdf", "other_pdf", "2d", "3d", "nc1")
EXT_2D = (".dxf", ".dwg", ".dg", ".dpm")
EXT_3D = (".stp", ".step", ".ifc", ".db1", ".sat", ".obj", ".stl", ".gltf", ".glb")
ALL_EXTS = (".pdf",) + EXT_2D + EXT_3D + (".nc1",)
PDF_CLASSES = ("abm", "approval", "construction", "detail", "erection", "gather", "inputs", "other", "shop")
EXT_TO_CAT = {
    ".pdf": "pdf", ".dxf": "2d", ".dwg": "2d", ".dg": "2d", ".dpm": "2d",
    ".stp": "3d", ".step": "3d", ".ifc": "3d", ".db1": "3d", ".sat": "3d",
    ".obj": "3d", ".stl": "3d", ".gltf": "3d", ".glb": "3d", ".nc1": "nc1",
}


def clear_proxy():
    for k in list(os.environ):
        if "proxy" in k.lower():
            os.environ.pop(k, None)
    os.environ["NO_PROXY"] = "*"


def s3():
    cfg = Config(proxies={}, read_timeout=1200, connect_timeout=60, retries={"max_attempts": 10})
    try:
        sess = boto3.Session(profile_name=PROFILE, region_name=REGION)
        if sess.get_credentials() is None:
            raise RuntimeError("no profile creds")
        return sess.client("s3", config=cfg)
    except Exception:
        return boto3.Session(region_name=REGION).client("s3", config=cfg)


def download_if_changed(client, key: str, path: Path) -> str:
    """Keep a disk-backed input synchronized to the exact S3 object ETag."""
    path.parent.mkdir(parents=True, exist_ok=True)
    head = client.head_object(Bucket=PRIVATE, Key=key)
    etag = str(head.get("ETag") or "").strip('"')
    etag_path = path.with_name(path.name + ".etag")
    cached = etag_path.read_text().strip() if etag_path.exists() else ""
    if not path.exists() or cached != etag:
        tmp = path.with_name(path.name + ".download")
        client.download_file(PRIVATE, key, str(tmp))
        os.replace(tmp, path)
        etag_path.write_text(etag + "\n")
    return etag


def identity_checksum(values) -> str:
    h = hashlib.sha256()
    for value in sorted(str(v).lower() for v in values):
        h.update(value.encode("ascii"))
        h.update(b"\n")
    return h.hexdigest()


def db_meta(path: Path, *, immutable: bool = False) -> dict:
    if not path.exists():
        return {}
    try:
        suffix = "&immutable=1" if immutable else ""
        conn = sqlite3.connect(f"file:{path}?mode=ro{suffix}", uri=True)
        try:
            return {str(k): str(v) for k, v in conn.execute("SELECT key,value FROM meta")}
        finally:
            conn.close()
    except Exception:
        return {}


def db_identity_matches(meta: dict, expected: dict) -> bool:
    return all(str(meta.get(k) or "") == str(v) for k, v in expected.items())


def retire_incompatible_db(path: Path) -> None:
    """Move an old/parser-bug database aside; never mix its digest rows into v2."""
    if not path.exists():
        return
    stamp = time.strftime("%Y%m%dT%H%M%SZ", time.gmtime())
    for suffix in ("", "-wal", "-shm"):
        src = Path(str(path) + suffix)
        if src.exists():
            dst = Path(str(path) + f".pre-v2-{stamp}{suffix}")
            os.replace(src, dst)
            print(f"retired incompatible sqlite {src} -> {dst}", flush=True)


def prepare_db(client, expected: dict) -> sqlite3.Connection:
    DATA_DIR.mkdir(parents=True, exist_ok=True)
    local_meta = db_meta(LOCAL_DB)
    if LOCAL_DB.exists() and not db_identity_matches(local_meta, expected):
        retire_incompatible_db(LOCAL_DB)

    if not LOCAL_DB.exists():
        remote_meta = {}
        try:
            remote_meta = json.loads(client.get_object(Bucket=PRIVATE, Key=DB_META_KEY)["Body"].read())
        except Exception:
            pass
        if db_identity_matches(remote_meta, expected):
            tmp = LOCAL_DB.with_name(LOCAL_DB.name + ".download")
            client.download_file(PRIVATE, DB_KEY, str(tmp))
            downloaded_meta = db_meta(tmp, immutable=True)
            if db_identity_matches(downloaded_meta, expected):
                os.replace(tmp, LOCAL_DB)
                print("downloaded compatible sqlite v2 checkpoint", flush=True)
            else:
                tmp.unlink(missing_ok=True)
                print("rejected sqlite checkpoint: sidecar/internal identity mismatch", flush=True)
        else:
            print("fresh sqlite v2 (old checkpoints intentionally ignored)", flush=True)

    conn = open_db()
    for key, value in expected.items():
        conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES(?,?)", (key, str(value)))
    conn.commit()
    return conn


def open_db() -> sqlite3.Connection:
    conn = sqlite3.connect(str(LOCAL_DB))
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS digests(
            disk TEXT NOT NULL,
            kind TEXT NOT NULL,
            bucket TEXT NOT NULL,
            digest BLOB NOT NULL,
            PRIMARY KEY(disk, kind, bucket, digest)
        ) WITHOUT ROWID"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS archives(
            digest TEXT PRIMARY KEY,
            disk TEXT NOT NULL,
            source TEXT NOT NULL,
            has_sha INTEGER NOT NULL,
            has_weak INTEGER NOT NULL
        ) WITHOUT ROWID"""
    )
    conn.execute("CREATE TABLE IF NOT EXISTS meta(key TEXT PRIMARY KEY, value TEXT)")
    conn.execute("CREATE TABLE IF NOT EXISTS done(key TEXT PRIMARY KEY)")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS baseline_raw(
            disk TEXT NOT NULL,
            bucket TEXT NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY(disk,bucket)
        ) WITHOUT ROWID"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS archive_raw(
            digest TEXT NOT NULL,
            bucket TEXT NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY(digest,bucket)
        ) WITHOUT ROWID"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS baseline_pdf_classes(
            disk TEXT NOT NULL,
            class_name TEXT NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY(disk,class_name)
        ) WITHOUT ROWID"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS archive_pdf_classes(
            digest TEXT NOT NULL,
            class_name TEXT NOT NULL,
            value INTEGER NOT NULL,
            PRIMARY KEY(digest,class_name)
        ) WITHOUT ROWID"""
    )
    conn.commit()
    return conn


def digest_bytes(hexdig: str) -> bytes | None:
    if not isinstance(hexdig, str):
        return None
    d = hexdig.lower()
    if len(d) != 64 or any(c not in "0123456789abcdef" for c in d):
        return None
    return bytes.fromhex(d)


def add_digest(conn, disk: str, kind: str, bucket: str, hexdig: str, buf: list) -> None:
    b = digest_bytes(hexdig)
    if b is None or bucket is None:
        return
    buf.append((disk, kind, bucket, b))
    if bucket in EXT_TO_CAT and kind == "sha":
        # also already category via caller
        pass


def flush(conn, buf: list) -> None:
    if not buf:
        return
    conn.executemany("INSERT OR IGNORE INTO digests(disk,kind,bucket,digest) VALUES(?,?,?,?)", buf)
    conn.commit()
    buf.clear()


def validate_baseline(baseline: dict) -> None:
    """Reject a malformed aggregate seed before any archive is marked covered."""
    if not isinstance(baseline, dict):
        raise RuntimeError("baseline is not an object")
    if baseline.get("schema") != 3:
        raise RuntimeError(f"unexpected baseline schema {baseline.get('schema')!r}")
    if digest_bytes(baseline.get("baseline_id")) is None:
        raise RuntimeError("baseline_id is not an exact SHA-256 string")
    conflict_ids = baseline.get("conflict_archive_ids")
    conflict_count = baseline.get("conflict_count")
    if not isinstance(conflict_ids, list) or not isinstance(conflict_count, int):
        raise RuntimeError("baseline conflict ledger is malformed")
    if len(conflict_ids) != conflict_count or any(digest_bytes(x) is None for x in conflict_ids):
        raise RuntimeError("baseline conflict ledger cardinality/identity mismatch")
    owner: dict[str, str] = {}
    errors: list[str] = []
    top_sha = ((baseline.get("dedup") or {}).get("sha256"))
    if not isinstance(top_sha, dict) or top_sha.get("status") != "exact":
        errors.append("dedup.sha256.status is not exact")
    for disk in ("Disk-1", "Disk-2"):
        disk_doc = (baseline.get("disks") or {}).get(disk) or {}
        ids = disk_doc.get("completed_archive_ids")
        if not isinstance(ids, list):
            errors.append(f"{disk}.completed_archive_ids missing/not-list")
            ids = []
        for value in ids:
            if not isinstance(value, str):
                errors.append(f"{disk} non-string archive identity")
                continue
            digest = value.lower()
            if digest_bytes(digest) is None:
                errors.append(f"{disk} invalid archive identity {digest[:24]!r}")
                continue
            prior = owner.get(digest)
            if prior and prior != disk:
                errors.append(f"archive identity appears in both disks {digest[:16]}")
            owner[digest] = disk

        dedup = disk_doc.get("dedup") if isinstance(disk_doc.get("dedup"), dict) else {}
        if ((dedup.get("sha256") or {}).get("status")) != "exact":
            errors.append(f"{disk}.dedup.sha256.status is not exact")
        sha_hashes = ((dedup.get("sha256") or {}).get("hashes"))
        if not isinstance(sha_hashes, dict):
            errors.append(f"{disk}.dedup.sha256.hashes missing/not-object")
            sha_hashes = {}
        recognized_sha = 0
        for kind_name in ("sha256", "weak_name_size"):
            hashes = ((dedup.get(kind_name) or {}).get("hashes"))
            if hashes is None and kind_name == "weak_name_size":
                continue
            if not isinstance(hashes, dict):
                errors.append(f"{disk}.dedup.{kind_name}.hashes not-object")
                continue
            for key, values in hashes.items():
                key_l = str(key).lower()
                if key_l not in RAW_KEYS and key_l not in EXT_TO_CAT:
                    continue
                if not isinstance(values, list):
                    errors.append(f"{disk}.{kind_name}.{key_l} not-list")
                    continue
                for value in values:
                    if digest_bytes(value) is None:
                        errors.append(f"{disk}.{kind_name}.{key_l} invalid digest")
                    elif kind_name == "sha256":
                        recognized_sha += 1
        if ids and recognized_sha == 0:
            errors.append(f"{disk} has covered archives but zero recognized SHA digests")

        raw_doc = disk_doc.get("raw")
        ext_doc = disk_doc.get("extensions")
        if not isinstance(raw_doc, dict) or set(raw_doc) != set(RAW_KEYS):
            errors.append(f"{disk}.raw keys do not match authoritative families")
            raw_doc = {}
        if not isinstance(ext_doc, dict) or set(ext_doc) != set(ALL_EXTS):
            errors.append(f"{disk}.extensions keys do not match authoritative extensions")
            ext_doc = {}
        for path, values in (("raw", raw_doc), ("extensions", ext_doc)):
            for key, value in values.items():
                if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                    errors.append(f"{disk}.{path}.{key} is not a nonnegative integer")
        if raw_doc and ext_doc:
            for family, extensions in (
                ("pdf", (".pdf",)),
                ("2d", EXT_2D),
                ("3d", EXT_3D),
                ("nc1", (".nc1",)),
            ):
                if raw_doc[family] != sum(ext_doc[ext] for ext in extensions):
                    errors.append(f"{disk}.{family} raw/extension decomposition mismatch")
            if raw_doc["pdf"] != raw_doc["cad_pdf"] + raw_doc["other_pdf"]:
                errors.append(f"{disk}.pdf CAD/non-CAD decomposition mismatch")
        classes = disk_doc.get("pdf_classes")
        if not isinstance(classes, dict) or set(classes) != set(PDF_CLASSES) or any(
            not isinstance(name, str)
            or not name
            or isinstance(value, bool)
            or not isinstance(value, int)
            or value < 0
            for name, value in (classes.items() if isinstance(classes, dict) else [])
        ):
            errors.append(f"{disk}.pdf_classes is malformed")
        elif raw_doc and sum(classes.values()) != raw_doc["pdf"]:
            errors.append(f"{disk}.pdf_classes does not decompose PDF raw")
    completed = top_sha.get("completed_archives") if isinstance(top_sha, dict) else None
    covered = top_sha.get("covered_archives") if isinstance(top_sha, dict) else None
    if (
        isinstance(completed, bool)
        or not isinstance(completed, int)
        or isinstance(covered, bool)
        or not isinstance(covered, int)
        or completed != len(owner)
        or covered != len(owner)
    ):
        errors.append(
            "dedup.sha256 completed/covered archives do not equal completed identity population"
        )
    if errors:
        raise RuntimeError(
            f"baseline validation failed ({len(errors)} errors): " + "; ".join(errors[:10])
        )
    if not set(x.lower() for x in conflict_ids).issubset(owner):
        raise RuntimeError("baseline conflict IDs are not all represented in completed archives")
    combined_doc = baseline.get("combined")
    if not isinstance(combined_doc, dict):
        raise RuntimeError("baseline combined raw tree is missing")
    for field, keys in (("raw", RAW_KEYS), ("extensions", ALL_EXTS)):
        combined_values = combined_doc.get(field)
        if not isinstance(combined_values, dict) or set(combined_values) != set(keys):
            raise RuntimeError(f"baseline combined {field} tree is malformed")
        for key in keys:
            value = combined_values.get(key)
            if isinstance(value, bool) or not isinstance(value, int) or value < 0:
                raise RuntimeError(f"baseline combined {field}.{key} is invalid")
            disk_sum = sum(
                int(((baseline.get("disks") or {}).get(disk) or {}).get(field, {}).get(key, -1))
                for disk in ("Disk-1", "Disk-2")
            )
            if value != disk_sum:
                raise RuntimeError(f"baseline combined {field}.{key} is not the disk sum")
    combined_classes = combined_doc.get("pdf_classes")
    if not isinstance(combined_classes, dict) or set(combined_classes) != set(PDF_CLASSES):
        raise RuntimeError("baseline combined pdf_classes tree is malformed")
    for name in PDF_CLASSES:
        value = combined_classes.get(name)
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            raise RuntimeError(f"baseline combined pdf_classes.{name} is invalid")
        disk_sum = sum(
            int((((baseline.get("disks") or {}).get(disk) or {}).get("pdf_classes") or {}).get(name, -1))
            for disk in ("Disk-1", "Disk-2")
        )
        if value != disk_sum:
            raise RuntimeError(f"baseline combined pdf_classes.{name} is not the disk sum")


def validate_seeded_baseline_counts(conn, baseline: dict) -> None:
    """Prove seeded digest rows equal every authoritative declared SHA count."""
    declared = ((baseline.get("dedup") or {}).get("sha256") or {})
    by_disk = declared.get("by_disk")
    combined = declared.get("combined")
    if not isinstance(by_disk, dict) or not isinstance(combined, dict):
        raise RuntimeError("baseline declared SHA count tree is malformed")

    actual = counts(conn)
    errors: list[str] = []

    def strict_count(value, path: str) -> int | None:
        if isinstance(value, bool) or not isinstance(value, int) or value < 0:
            errors.append(f"{path} is not a nonnegative integer")
            return None
        return value

    for scope in ("Disk-1", "Disk-2", "combined"):
        expected = combined if scope == "combined" else by_disk.get(scope)
        if not isinstance(expected, dict):
            errors.append(f"dedup.sha256.{scope} is not an object")
            continue
        expected_ext = expected.get("by_extension")
        if not isinstance(expected_ext, dict):
            errors.append(f"dedup.sha256.{scope}.by_extension is not an object")
            expected_ext = {}
        for bucket in RAW_KEYS:
            want = strict_count(
                expected.get(bucket), f"dedup.sha256.{scope}.{bucket}"
            )
            got = int(actual[scope]["sha256"][bucket])
            if want is not None and got != want:
                errors.append(f"{scope}.{bucket} seeded={got} declared={want}")
        for ext in ALL_EXTS:
            want = strict_count(
                expected_ext.get(ext),
                f"dedup.sha256.{scope}.by_extension.{ext}",
            )
            got = int(actual[scope]["sha256"]["by_extension"][ext])
            if want is not None and got != want:
                errors.append(f"{scope}.{ext} seeded={got} declared={want}")
    if errors:
        raise RuntimeError(
            f"baseline seeded SHA count validation failed ({len(errors)} errors): "
            + "; ".join(errors[:12])
        )


def seed_baseline(conn, baseline: dict) -> int:
    row = conn.execute("SELECT value FROM meta WHERE key='baseline_seeded'").fetchone()
    if row and row[0] == "1":
        return int(conn.execute("SELECT COUNT(*) FROM archives WHERE source='baseline_seed'").fetchone()[0])
    buf: list = []
    n_arch = 0
    for disk in ("Disk-1", "Disk-2"):
        disk_doc = (baseline.get("disks") or {}).get(disk) or {}
        ids = [x.lower() for x in (disk_doc.get("completed_archive_ids") or [])]
        for dig in ids:
            conn.execute(
                "INSERT OR IGNORE INTO archives(digest,disk,source,has_sha,has_weak) VALUES(?,?,?,?,?)",
                (dig, disk, "baseline_seed", 1, 1),
            )
            n_arch += 1
        dedup = disk_doc.get("dedup") or {}
        for kind_name, kind in (("sha256", "sha"), ("weak_name_size", "weak")):
            hashes = ((dedup.get(kind_name) or {}).get("hashes")) or {}
            for key, values in hashes.items():
                if not isinstance(values, list):
                    continue
                key_l = str(key).lower()
                buckets = []
                if key_l in RAW_KEYS:
                    buckets.append(key_l)
                    if key_l in ("pdf", "cad_pdf", "other_pdf"):
                        buckets.append(".pdf")
                elif key_l in EXT_TO_CAT:
                    buckets.append(key_l)
                    buckets.append(EXT_TO_CAT[key_l])
                else:
                    continue
                for dig in values:
                    b = digest_bytes(dig)
                    if not b:
                        continue
                    for buck in buckets:
                        buf.append((disk, kind, buck, b))
                if len(buf) >= 20000:
                    flush(conn, buf)
        for bucket in RAW_KEYS:
            conn.execute(
                "INSERT OR REPLACE INTO baseline_raw(disk,bucket,value) VALUES(?,?,?)",
                (disk, bucket, int((disk_doc.get("raw") or {}).get(bucket) or 0)),
            )
        for ext in ALL_EXTS:
            conn.execute(
                "INSERT OR REPLACE INTO baseline_raw(disk,bucket,value) VALUES(?,?,?)",
                (disk, ext, int((disk_doc.get("extensions") or {}).get(ext) or 0)),
            )
        for class_name, value in (disk_doc.get("pdf_classes") or {}).items():
            conn.execute(
                "INSERT OR REPLACE INTO baseline_pdf_classes(disk,class_name,value) VALUES(?,?,?)",
                (disk, str(class_name), int(value)),
            )
    flush(conn, buf)
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('baseline_seeded','1')")
    conn.commit()
    return n_arch


def split_extension_path(prefix: str) -> tuple[str | None, str | None]:
    """Return normalized extension and relative field from an ijson prefix."""
    marker = "extensions."
    if not prefix.startswith(marker):
        return None, None
    rest = prefix[len(marker) :]
    if rest.startswith("."):
        rest = rest[1:]
    token, sep, field = rest.partition(".")
    if not token:
        return None, None
    return "." + token.lower(), field if sep else ""


def stream_result(data) -> dict:
    out = {
        "status": None,
        "disk": None,
        "source_key_sha256": None,
        "sha256": {},
        "extensions": {},
        "weak": {},
        "raw": {},
        "pdf_classes": {},
        "has_sha_list": False,
        "has_weak_list": False,
        "seen_sha256_object": False,
        "seen_weak_object": False,
        "invalid_sha_digest_count": 0,
        "invalid_weak_digest_count": 0,
        "invalid_schema_count": 0,
        "invalid_schema_sample": [],
        "seen_raw_observation": False,
        "seen_extension_raw": set(),
        "seen_pdf_classes_object": False,
    }

    def schema_error(prefix: str, event: str) -> None:
        out["invalid_schema_count"] += 1
        if len(out["invalid_schema_sample"]) < 10:
            out["invalid_schema_sample"].append(f"{prefix}:{event}")

    fh = data if hasattr(data, "read") else io.BytesIO(data)
    try:
        for prefix, event, value in ijson.parse(fh):
            if prefix in {"status", "disk", "source_key_sha256"} and event in {
                "number", "boolean", "null", "start_map", "start_array"
            }:
                schema_error(prefix, event)
            if prefix == "sha256" and event in {"start_map", "map_key"}:
                out["seen_sha256_object"] = True
            if prefix == "weak" and event in {"start_map", "map_key"}:
                out["seen_weak_object"] = True
            if prefix == "pdf_classes" and event in {"start_map", "map_key"}:
                out["seen_pdf_classes_object"] = True
            value_events = {"string", "number", "boolean", "null"}
            # Enforce container shapes. Digest buckets are arrays; each known
            # extension is a map whose sha/weak members are arrays.
            if prefix in {"sha256", "weak", "raw", "extensions", "pdf_classes"} and (
                event in value_events or event == "start_array"
            ):
                schema_error(prefix, event)
                if prefix == "sha256":
                    out["invalid_sha_digest_count"] += 1
                elif prefix == "weak":
                    out["invalid_weak_digest_count"] += 1

            top_parts = prefix.split(".")
            if (
                len(top_parts) == 2
                and top_parts[0] in {"sha256", "weak"}
                and top_parts[1] in RAW_KEYS
                and (event in value_events or event == "start_map")
            ):
                schema_error(prefix, event)
                if top_parts[0] == "sha256":
                    out["invalid_sha_digest_count"] += 1
                else:
                    out["invalid_weak_digest_count"] += 1
            if (
                len(top_parts) == 2
                and top_parts[0] == "raw"
                and top_parts[1] in RAW_KEYS
                and event in {"start_map", "start_array"}
            ):
                schema_error(prefix, event)
            if (
                prefix.startswith("pdf_classes.")
                and prefix.count(".") == 1
                and event in {"start_map", "start_array"}
            ):
                schema_error(prefix, event)

            ext_path, ext_field = split_extension_path(prefix)
            if ext_path is not None:
                if ext_path not in ALL_EXTS:
                    if event in value_events or event in {"start_map", "start_array", "map_key"}:
                        schema_error(prefix, event)
                elif ext_field == "":
                    if event in value_events or event == "start_array":
                        schema_error(prefix, event)
                    elif event == "map_key" and str(value) not in {"raw", "category", "sha256", "weak"}:
                        schema_error(f"{prefix}.{value}", event)
                elif ext_field in {"sha256", "weak"} and (
                    event in value_events or event == "start_map"
                ):
                    schema_error(prefix, event)
                    if ext_field == "sha256":
                        out["invalid_sha_digest_count"] += 1
                    else:
                        out["invalid_weak_digest_count"] += 1
                elif ext_field == "raw" and event in {"start_map", "start_array"}:
                    schema_error(prefix, event)
            if event == "map_key":
                if prefix in {"sha256", "weak"} and str(value) not in RAW_KEYS:
                    schema_error(f"{prefix}.{value}", event)
                elif prefix == "raw" and str(value) not in RAW_KEYS:
                    schema_error(f"raw.{value}", event)
                elif prefix == "pdf_classes" and str(value) not in PDF_CLASSES:
                    schema_error(f"pdf_classes.{value}", event)
                elif prefix == "extensions":
                    ext_key = str(value).lower()
                    if not ext_key.startswith("."):
                        ext_key = "." + ext_key
                    if ext_key not in ALL_EXTS:
                        schema_error(f"extensions.{value}", event)
            if prefix.endswith(".item") and event in {"start_map", "start_array"}:
                if prefix.startswith("sha256.") or (
                    prefix.startswith("extensions.") and ".sha256.item" in prefix
                ):
                    out["invalid_sha_digest_count"] += 1
                    schema_error(prefix, event)
                elif prefix.startswith("weak.") or (
                    prefix.startswith("extensions.") and ".weak.item" in prefix
                ):
                    out["invalid_weak_digest_count"] += 1
                    schema_error(prefix, event)
            if event == "number" and prefix.startswith("raw.") and prefix.count(".") == 1:
                category = prefix.split(".", 1)[1]
                if category in RAW_KEYS and int(value) == value and int(value) >= 0:
                    out["raw"][category] = int(value)
                    out["seen_raw_observation"] = True
                else:
                    schema_error(prefix, event)
            elif event == "number" and prefix.startswith("extensions.") and prefix.endswith(".raw"):
                mid = prefix[len("extensions.") : -len(".raw")].strip("'\"")
                ext = mid if mid.startswith(".") else "." + mid
                if ext in ALL_EXTS and int(value) == value and int(value) >= 0:
                    out["extensions"].setdefault(
                        ext, {"sha256": [], "weak": [], "category": EXT_TO_CAT.get(ext), "raw": 0}
                    )
                    out["extensions"][ext]["raw"] = int(value)
                    out["seen_raw_observation"] = True
                    out["seen_extension_raw"].add(ext)
                else:
                    schema_error(prefix, event)
            elif event == "number" and prefix.startswith("pdf_classes.") and prefix.count(".") == 1:
                class_name = prefix.split(".", 1)[1]
                if class_name in PDF_CLASSES and int(value) == value and int(value) >= 0:
                    out["pdf_classes"][class_name] = int(value)
                else:
                    schema_error(prefix, event)
            elif event in {"string", "boolean", "null"} and (
                (prefix.startswith("raw.") and prefix.count(".") == 1)
                or (prefix.startswith("extensions.") and prefix.endswith(".raw"))
                or (prefix.startswith("pdf_classes.") and prefix.count(".") == 1)
            ):
                schema_error(prefix, event)
            # ijson reports non-string array members as number/null/boolean.
            # They are malformed digest entries and must invalidate coverage,
            # not disappear before the string-only branches below.
            if event in {"number", "null", "boolean"}:
                if prefix.startswith("sha256.") and prefix.endswith(".item"):
                    out["invalid_sha_digest_count"] += 1
                    out["seen_sha256_object"] = True
                elif prefix.startswith("weak.") and prefix.endswith(".item"):
                    out["invalid_weak_digest_count"] += 1
                    out["seen_weak_object"] = True
                elif prefix.startswith("extensions.") and ".sha256.item" in prefix:
                    out["invalid_sha_digest_count"] += 1
                    out["seen_sha256_object"] = True
                elif prefix.startswith("extensions.") and ".weak.item" in prefix:
                    out["invalid_weak_digest_count"] += 1
                    out["seen_weak_object"] = True
            if event != "string":
                continue
            if prefix == "status":
                out["status"] = value
            elif prefix == "disk":
                out["disk"] = value
            elif prefix == "source_key_sha256":
                out["source_key_sha256"] = value
            elif prefix.startswith("sha256."):
                parts = prefix.split(".")
                category = parts[1] if len(parts) >= 2 else ""
                exact_path = (
                    (len(parts) == 3 and parts[2] == "item")
                    and category in RAW_KEYS
                )
                if exact_path and digest_bytes(value):
                    out["sha256"].setdefault(category, []).append(value)
                    out["has_sha_list"] = True
                else:
                    out["invalid_sha_digest_count"] += 1
                    if not exact_path:
                        schema_error(prefix, event)
                out["seen_sha256_object"] = True
            elif prefix.startswith("weak."):
                parts = prefix.split(".")
                category = parts[1] if len(parts) >= 2 else ""
                exact_path = (
                    (len(parts) == 3 and parts[2] == "item")
                    and category in RAW_KEYS
                )
                if exact_path and digest_bytes(value):
                    out["weak"].setdefault(category, []).append(value)
                    out["has_weak_list"] = True
                else:
                    out["invalid_weak_digest_count"] += 1
                    if not exact_path:
                        schema_error(prefix, event)
                out["seen_weak_object"] = True
            elif prefix.startswith("extensions.") and prefix.endswith(".sha256.item"):
                mid = prefix[len("extensions.") : -len(".sha256.item")].strip("'\"")
                ext = mid if mid.startswith(".") else "." + mid
                if ext in ALL_EXTS:
                    out["extensions"].setdefault(ext, {"sha256": [], "weak": [], "category": EXT_TO_CAT.get(ext), "raw": 0})
                if ext in ALL_EXTS and digest_bytes(value):
                    out["extensions"][ext]["sha256"].append(value)
                    out["has_sha_list"] = True
                else:
                    out["invalid_sha_digest_count"] += 1
                    if ext not in ALL_EXTS:
                        schema_error(prefix, event)
                out["seen_sha256_object"] = True
            elif prefix.startswith("extensions.") and prefix.endswith(".weak.item"):
                mid = prefix[len("extensions.") : -len(".weak.item")].strip("'\"")
                ext = mid if mid.startswith(".") else "." + mid
                if ext in ALL_EXTS:
                    out["extensions"].setdefault(ext, {"sha256": [], "weak": [], "category": EXT_TO_CAT.get(ext), "raw": 0})
                if ext in ALL_EXTS and digest_bytes(value):
                    out["extensions"][ext]["weak"].append(value)
                    out["has_weak_list"] = True
                else:
                    out["invalid_weak_digest_count"] += 1
                    if ext not in ALL_EXTS:
                        schema_error(prefix, event)
                out["seen_weak_object"] = True
            elif prefix.startswith("extensions.") and prefix.endswith(".category"):
                mid = prefix[len("extensions.") : -len(".category")].strip("'\"")
                ext = mid if mid.startswith(".") else "." + mid
                if ext in ALL_EXTS and value == EXT_TO_CAT.get(ext):
                    out["extensions"].setdefault(ext, {"sha256": [], "weak": [], "category": value, "raw": 0})
                    out["extensions"][ext]["category"] = value
                else:
                    schema_error(prefix, event)
            elif prefix.startswith("extensions.") and (
                ".sha256" in prefix or ".weak" in prefix
            ):
                if ".sha256" in prefix:
                    out["invalid_sha_digest_count"] += 1
                if ".weak" in prefix:
                    out["invalid_weak_digest_count"] += 1
                schema_error(prefix, event)
    finally:
        try:
            fh.close()
        except Exception:
            pass
    # Coverage is only exact when every raw family is explicitly observed and
    # every positive family/extension has its corresponding digest list.  A
    # single global ``has_sha_list`` flag is insufficient: one populated PDF
    # list must not make a positive 2D bucket appear covered.
    for category in RAW_KEYS:
        if category not in out["raw"]:
            schema_error(f"raw.{category}", "missing")
            continue
        has_raw = int(out["raw"][category]) > 0
        has_hashes = bool(out["sha256"].get(category))
        if has_raw != has_hashes:
            schema_error(f"sha256.{category}", "raw_sha_coverage_mismatch")

    if set(out["raw"]) == set(RAW_KEYS) and int(out["raw"]["pdf"]) != (
        int(out["raw"]["cad_pdf"]) + int(out["raw"]["other_pdf"])
    ):
        schema_error("raw.pdf_subtypes", "decomposition_mismatch")

    for ext, stats in out["extensions"].items():
        if ext not in out["seen_extension_raw"]:
            schema_error(f"extensions.{ext}.raw", "missing")
            continue
        has_raw = int(stats.get("raw") or 0) > 0
        has_hashes = bool(stats.get("sha256"))
        if has_raw != has_hashes:
            schema_error(
                f"extensions.{ext}.sha256", "raw_sha_coverage_mismatch"
            )

    # Extension rows are the complete decomposition of the four publishable
    # file families.  Requiring both raw totals and digest-set equality catches
    # a silently omitted extension object as well as a partially emitted list.
    family_extensions = {
        "pdf": (".pdf",),
        "2d": EXT_2D,
        "3d": EXT_3D,
        "nc1": (".nc1",),
    }
    for category, extensions in family_extensions.items():
        extension_raw = sum(
            int((out["extensions"].get(ext) or {}).get("raw") or 0)
            for ext in extensions
        )
        if category in out["raw"] and extension_raw != int(out["raw"][category]):
            schema_error(
                f"extensions.{category}", "raw_family_decomposition_mismatch"
            )
        root_hashes = set(out["sha256"].get(category) or [])
        extension_hashes = {
            digest
            for ext in extensions
            for digest in ((out["extensions"].get(ext) or {}).get("sha256") or [])
        }
        if root_hashes != extension_hashes:
            schema_error(
                f"extensions.{category}", "sha_family_decomposition_mismatch"
            )

    if (
        not out["seen_pdf_classes_object"]
        or not set(out["pdf_classes"]).issubset(PDF_CLASSES)
        or sum(out["pdf_classes"].values()) != int(out["raw"].get("pdf") or 0)
    ):
        schema_error("pdf_classes", "pdf_class_decomposition_mismatch")

    # An empty hash object is valid coverage only for an archive with no wanted
    # files. Merely seeing an extensions map must never mark a non-empty archive
    # SHA-covered.
    extension_sha = any((v.get("sha256") or []) for v in out["extensions"].values())
    extension_weak = any((v.get("weak") or []) for v in out["extensions"].values())
    out["has_sha_list"] = bool(out["sha256"] or extension_sha)
    out["has_weak_list"] = bool(out["weak"] or extension_weak)
    raw_values = list(out["raw"].values()) + [
        int((stats or {}).get("raw") or 0) for stats in out["extensions"].values()
    ]
    raw_is_empty = (
        set(out["raw"]) == set(RAW_KEYS)
        and set(out["extensions"]).issubset(out["seen_extension_raw"])
        and all(int(v or 0) == 0 for v in raw_values)
    )
    if out["invalid_sha_digest_count"] or out["invalid_schema_count"]:
        out["has_sha_list"] = False
    if out["invalid_weak_digest_count"] or out["invalid_schema_count"]:
        out["has_weak_list"] = False
    if not out["has_sha_list"] and not out["invalid_sha_digest_count"] and not out["invalid_schema_count"] and out["seen_sha256_object"] and raw_is_empty:
        out["has_sha_list"] = True
    if not out["has_weak_list"] and not out["invalid_weak_digest_count"] and not out["invalid_schema_count"] and out["seen_weak_object"] and raw_is_empty:
        out["has_weak_list"] = True
    if not out["has_sha_list"] and not out["invalid_sha_digest_count"] and not out["invalid_schema_count"] and raw_is_empty:
        # ok empty extract with no sha256 key — still a finished archive with zero hashes
        out["has_sha_list"] = True
        if not out["invalid_weak_digest_count"]:
            out["has_weak_list"] = True
    return out


def ingest(conn, doc: dict, archive_id: str, source: str, missing: dict) -> str:
    if not isinstance(doc, dict):
        return "skip_bad"
    if doc.get("status") != "ok":
        return "skip_status"
    disk = doc.get("disk") if doc.get("disk") in ("Disk-1", "Disk-2") else None
    if not disk:
        return "skip_disk"
    digest = str(doc.get("source_key_sha256") or archive_id or "").lower()
    if digest_bytes(digest) is None:
        return "skip_digest"
    if archive_id and digest != str(archive_id).lower():
        return "skip_identity_mismatch"
    if not doc.get("has_sha_list"):
        if int(doc.get("invalid_schema_count") or 0):
            reason = "invalid_result_schema"
        elif int(doc.get("invalid_sha_digest_count") or 0):
            reason = "invalid_sha_digest"
        else:
            reason = "missing_sha_list"
        missing["sha"].append(
            {
                "digest": digest,
                "disk": disk,
                "source": source,
                "reason": reason,
                "invalid_digest_count": int(doc.get("invalid_sha_digest_count") or 0),
                "invalid_schema_count": int(doc.get("invalid_schema_count") or 0),
            }
        )
        return reason
    existing = conn.execute("SELECT 1 FROM archives WHERE digest=?", (digest,)).fetchone()
    if existing:
        return "skip_dup_archive"
    buf: list = []
    for cat, values in (doc.get("sha256") or {}).items():
        if cat not in RAW_KEYS or not isinstance(values, list):
            continue
        for v in values:
            b = digest_bytes(v)
            if b:
                buf.append((disk, "sha", cat, b))
    for ext, stats in (doc.get("extensions") or {}).items():
        if not isinstance(stats, dict):
            continue
        ext_l = str(ext).lower()
        if not ext_l.startswith("."):
            ext_l = "." + ext_l
        cat = stats.get("category") or EXT_TO_CAT.get(ext_l)
        for v in stats.get("sha256") or []:
            b = digest_bytes(v)
            if not b:
                continue
            buf.append((disk, "sha", ext_l, b))
            if cat in RAW_KEYS:
                buf.append((disk, "sha", cat, b))
        for v in stats.get("weak") or []:
            b = digest_bytes(v)
            if not b:
                continue
            buf.append((disk, "weak", ext_l, b))
            if cat in RAW_KEYS:
                buf.append((disk, "weak", cat, b))
            doc["has_weak_list"] = True
    if doc.get("has_weak_list"):
        for cat, values in (doc.get("weak") or {}).items():
            if cat not in RAW_KEYS or not isinstance(values, list):
                continue
            for v in values:
                b = digest_bytes(v)
                if b:
                    buf.append((disk, "weak", cat, b))
    else:
        missing["weak"].append({"digest": digest, "disk": disk, "source": source})
    flush(conn, buf)
    for bucket in RAW_KEYS:
        conn.execute(
            "INSERT OR REPLACE INTO archive_raw(digest,bucket,value) VALUES(?,?,?)",
            (digest, bucket, int((doc.get("raw") or {}).get(bucket) or 0)),
        )
    for ext in ALL_EXTS:
        conn.execute(
            "INSERT OR REPLACE INTO archive_raw(digest,bucket,value) VALUES(?,?,?)",
            (
                digest,
                ext,
                int(((doc.get("extensions") or {}).get(ext) or {}).get("raw") or 0),
            ),
        )
    for class_name in PDF_CLASSES:
        conn.execute(
            "INSERT OR REPLACE INTO archive_pdf_classes(digest,class_name,value) VALUES(?,?,?)",
            (digest, class_name, int((doc.get("pdf_classes") or {}).get(class_name) or 0)),
        )
    conn.execute(
        "INSERT OR IGNORE INTO archives(digest,disk,source,has_sha,has_weak) VALUES(?,?,?,?,?)",
        (digest, disk, source, 1, 1 if doc.get("has_weak_list") else 0),
    )
    conn.commit()
    return "ok"


def fetch(client, key: str):
    try:
        body = client.get_object(Bucket=PRIVATE, Key=key)["Body"]
        return key, stream_result(body), None
    except Exception as exc:
        return key, None, f"{type(exc).__name__}: {exc}"


def list_prefix(client, prefix: str):
    out = []
    token = None
    while True:
        kw = {"Bucket": PRIVATE, "Prefix": prefix, "MaxKeys": 1000}
        if token:
            kw["ContinuationToken"] = token
        resp = client.list_objects_v2(**kw)
        for it in resp.get("Contents") or []:
            if it["Key"].endswith(".json"):
                out.append((int(it["Size"]), it["Key"]))
        if not resp.get("IsTruncated"):
            return sorted(out)
        token = resp["NextContinuationToken"]


def put_json(client, key, obj):
    client.put_object(
        Bucket=PRIVATE,
        Key=key,
        Body=json.dumps(obj, separators=(",", ":"), ensure_ascii=True).encode(),
        ContentType="application/json",
        CacheControl="no-store",
    )


def counts(conn) -> dict:
    """Return exact per-disk and cross-disk set-union counts in two scans.

    The primary key starts with ``(disk, kind, bucket, digest)``. Repeating
    ``COUNT(DISTINCT digest)`` for every bucket forced SQLite to build large
    temporary B-trees dozens of times. Aggregate each disk once, then subtract
    the exact Disk-1/Disk-2 digest intersection. This is mathematically the same
    set union and uses the primary key for every intersection lookup.
    """
    buckets = tuple(RAW_KEYS) + tuple(ALL_EXTS)
    per_disk: dict[tuple[str, str, str], int] = {}
    for disk, kind, bucket, n in conn.execute(
        "SELECT disk,kind,bucket,COUNT(*) FROM digests GROUP BY disk,kind,bucket"
    ):
        per_disk[(str(disk), str(kind), str(bucket))] = int(n)

    intersections: dict[tuple[str, str], int] = {}
    for kind, bucket, n in conn.execute(
        """
        SELECT a.kind,a.bucket,COUNT(*)
        FROM digests AS a
        JOIN digests AS b
          ON b.disk='Disk-2'
         AND b.kind=a.kind
         AND b.bucket=a.bucket
         AND b.digest=a.digest
        WHERE a.disk='Disk-1'
        GROUP BY a.kind,a.bucket
        """
    ):
        intersections[(str(kind), str(bucket))] = int(n)

    def pack(disk: str | None, kind: str) -> dict:
        def value(bucket: str) -> int:
            d1 = per_disk.get(("Disk-1", kind, bucket), 0)
            d2 = per_disk.get(("Disk-2", kind, bucket), 0)
            if disk == "Disk-1":
                return d1
            if disk == "Disk-2":
                return d2
            return d1 + d2 - intersections.get((kind, bucket), 0)

        out = {cat: value(cat) for cat in RAW_KEYS}
        out["by_extension"] = {ext: value(ext) for ext in ALL_EXTS}
        return out

    disks = {
        disk: {"sha256": pack(disk, "sha"), "weak": pack(disk, "weak")}
        for disk in ("Disk-1", "Disk-2")
    }
    disks["combined"] = {"sha256": pack(None, "sha"), "weak": pack(None, "weak")}
    additive = {"sha256": {}, "weak": {}}
    for kind in ("sha256", "weak"):
        additive[kind] = {k: disks["Disk-1"][kind][k] + disks["Disk-2"][kind][k] for k in RAW_KEYS}
        additive[kind]["by_extension"] = {
            e: disks["Disk-1"][kind]["by_extension"][e] + disks["Disk-2"][kind]["by_extension"][e]
            for e in ALL_EXTS
        }
    disks["combined_additive_diag"] = additive
    return disks


def raw_occurrence_counts(conn) -> dict:
    """Exact raw family/extension/class sums for the SHA-covered population."""
    buckets = tuple(RAW_KEYS) + tuple(ALL_EXTS)
    out: dict[str, dict] = {}
    for disk in ("Disk-1", "Disk-2"):
        values = {bucket: 0 for bucket in buckets}
        for bucket, value in conn.execute(
            "SELECT bucket,value FROM baseline_raw WHERE disk=?", (disk,)
        ):
            if bucket in values:
                values[str(bucket)] += int(value)
        for bucket, value in conn.execute(
            """
            SELECT r.bucket,SUM(r.value)
            FROM archive_raw AS r
            JOIN archives AS a ON a.digest=r.digest
            WHERE a.disk=? AND a.source!='baseline_seed'
            GROUP BY r.bucket
            """,
            (disk,),
        ):
            if bucket in values:
                values[str(bucket)] += int(value or 0)
        classes: dict[str, int] = {name: 0 for name in PDF_CLASSES}
        for name, value in conn.execute(
            "SELECT class_name,value FROM baseline_pdf_classes WHERE disk=?", (disk,)
        ):
            if name in classes:
                classes[str(name)] += int(value)
        for name, value in conn.execute(
            """
            SELECT p.class_name,SUM(p.value)
            FROM archive_pdf_classes AS p
            JOIN archives AS a ON a.digest=p.digest
            WHERE a.disk=? AND a.source!='baseline_seed'
            GROUP BY p.class_name
            """,
            (disk,),
        ):
            if name in classes:
                classes[str(name)] += int(value or 0)
        out[disk] = {
            "raw": {key: values[key] for key in RAW_KEYS},
            "by_extension": {ext: values[ext] for ext in ALL_EXTS},
            "pdf_classes": classes,
        }
    out["combined"] = {
        "raw": {
            key: out["Disk-1"]["raw"][key] + out["Disk-2"]["raw"][key]
            for key in RAW_KEYS
        },
        "by_extension": {
            ext: out["Disk-1"]["by_extension"][ext]
            + out["Disk-2"]["by_extension"][ext]
            for ext in ALL_EXTS
        },
        "pdf_classes": {
            name: out["Disk-1"]["pdf_classes"][name]
            + out["Disk-2"]["pdf_classes"][name]
            for name in PDF_CLASSES
        },
    }
    return out


def raw_storage_complete(conn) -> tuple[bool, dict]:
    """Prove exact raw/class key sets and nonnegative values for every archive."""
    allowed_raw = tuple(RAW_KEYS) + tuple(ALL_EXTS)
    allowed_classes = tuple(PDF_CLASSES)

    def archive_group_violations(table: str, key_column: str, allowed: tuple) -> int:
        placeholders = ",".join("?" for _ in allowed)
        sql = f"""
            SELECT COUNT(*) FROM (
                SELECT a.digest,
                       COUNT(t.{key_column}) AS row_count,
                       SUM(CASE WHEN t.{key_column} IN ({placeholders}) THEN 1 ELSE 0 END)
                           AS allowed_count,
                       SUM(CASE WHEN t.value IS NULL OR t.value < 0 THEN 1 ELSE 0 END)
                           AS bad_value_count
                FROM archives AS a
                LEFT JOIN {table} AS t ON t.digest=a.digest
                WHERE a.source!='baseline_seed'
                GROUP BY a.digest
                HAVING row_count!=? OR allowed_count!=? OR bad_value_count!=0
            )
        """
        return int(conn.execute(sql, (*allowed, len(allowed), len(allowed))).fetchone()[0])

    def archive_row_violations(table: str, key_column: str, allowed: tuple) -> int:
        placeholders = ",".join("?" for _ in allowed)
        sql = f"""
            SELECT COUNT(*)
            FROM {table} AS t
            LEFT JOIN archives AS a ON a.digest=t.digest
            WHERE a.digest IS NULL
               OR a.source='baseline_seed'
               OR t.{key_column} NOT IN ({placeholders})
               OR t.value < 0
        """
        return int(conn.execute(sql, allowed).fetchone()[0])

    def baseline_row_violations(table: str, key_column: str, allowed: tuple) -> int:
        placeholders = ",".join("?" for _ in allowed)
        sql = f"""
            SELECT COUNT(*) FROM {table}
            WHERE disk NOT IN ('Disk-1','Disk-2')
               OR {key_column} NOT IN ({placeholders})
               OR value < 0
        """
        return int(conn.execute(sql, allowed).fetchone()[0])

    nonbaseline = int(
        conn.execute("SELECT COUNT(*) FROM archives WHERE source!='baseline_seed'").fetchone()[0]
    )
    raw_rows = int(conn.execute("SELECT COUNT(*) FROM archive_raw").fetchone()[0])
    class_rows = int(conn.execute("SELECT COUNT(*) FROM archive_pdf_classes").fetchone()[0])
    baseline_raw_rows = int(conn.execute("SELECT COUNT(*) FROM baseline_raw").fetchone()[0])
    baseline_class_rows = int(
        conn.execute("SELECT COUNT(*) FROM baseline_pdf_classes").fetchone()[0]
    )
    raw_group_violations = archive_group_violations(
        "archive_raw", "bucket", allowed_raw
    )
    class_group_violations = archive_group_violations(
        "archive_pdf_classes", "class_name", allowed_classes
    )
    raw_row_violations = archive_row_violations(
        "archive_raw", "bucket", allowed_raw
    )
    class_row_violations = archive_row_violations(
        "archive_pdf_classes", "class_name", allowed_classes
    )
    baseline_raw_violations = baseline_row_violations(
        "baseline_raw", "bucket", allowed_raw
    )
    baseline_class_violations = baseline_row_violations(
        "baseline_pdf_classes", "class_name", allowed_classes
    )
    detail = {
        "nonbaseline_archives": nonbaseline,
        "archive_raw_rows": raw_rows,
        "expected_archive_raw_rows": nonbaseline * (len(RAW_KEYS) + len(ALL_EXTS)),
        "archive_pdf_class_rows": class_rows,
        "expected_archive_pdf_class_rows": nonbaseline * len(PDF_CLASSES),
        "baseline_raw_rows": baseline_raw_rows,
        "expected_baseline_raw_rows": 2 * (len(RAW_KEYS) + len(ALL_EXTS)),
        "baseline_pdf_class_rows": baseline_class_rows,
        "expected_baseline_pdf_class_rows": 2 * len(PDF_CLASSES),
        "archive_raw_group_violations": raw_group_violations,
        "archive_pdf_class_group_violations": class_group_violations,
        "archive_raw_row_violations": raw_row_violations,
        "archive_pdf_class_row_violations": class_row_violations,
        "baseline_raw_row_violations": baseline_raw_violations,
        "baseline_pdf_class_row_violations": baseline_class_violations,
    }
    complete = (
        raw_rows == detail["expected_archive_raw_rows"]
        and class_rows == detail["expected_archive_pdf_class_rows"]
        and baseline_raw_rows == detail["expected_baseline_raw_rows"]
        and baseline_class_rows == detail["expected_baseline_pdf_class_rows"]
        and raw_group_violations == 0
        and class_group_violations == 0
        and raw_row_violations == 0
        and class_row_violations == 0
        and baseline_raw_violations == 0
        and baseline_class_violations == 0
    )
    return complete, detail


def raw_occurrence_tree_valid(tree: dict) -> bool:
    if not isinstance(tree, dict):
        return False
    for scope in ("Disk-1", "Disk-2", "combined"):
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
        values = list(raw.values()) + list(ext.values()) + list(classes.values())
        if any(isinstance(v, bool) or not isinstance(v, int) or v < 0 for v in values):
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
            if raw[family] != sum(ext[e] for e in extensions):
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


def coverage(conn, archives_in_raw: dict, missing: dict) -> dict:
    def n(where=""):
        return int(conn.execute(f"SELECT COUNT(*) FROM archives {where}").fetchone()[0])

    return {
        "archives_in_raw": archives_in_raw,
        "archives_in_sha": {
            "Disk-1": n("WHERE disk='Disk-1' AND has_sha=1"),
            "Disk-2": n("WHERE disk='Disk-2' AND has_sha=1"),
            "combined": n("WHERE has_sha=1"),
        },
        "archives_in_weak": {
            "Disk-1": n("WHERE disk='Disk-1' AND has_weak=1"),
            "Disk-2": n("WHERE disk='Disk-2' AND has_weak=1"),
            "combined": n("WHERE has_weak=1"),
        },
        "by_source": {
            r[0]: r[1]
            for r in conn.execute("SELECT source, COUNT(*) FROM archives GROUP BY source")
        },
        "missing_sha_list_count": len(missing["sha"]),
        "missing_weak_list_count": len(missing["weak"]),
        "missing_sha_list_sample": missing["sha"][:10],
        "missing_weak_list_sample": missing["weak"][:10],
    }


def spot_check(client, conn) -> list:
    rows = conn.execute(
        "SELECT digest,disk,source FROM archives WHERE source IN ('ec2','legacy') AND has_sha=1 ORDER BY RANDOM() LIMIT 3"
    ).fetchall()
    out = []
    for digest, disk, source in rows:
        key = f"{EC2_PREFIX if source=='ec2' else LEGACY_PREFIX}{digest}.json"
        _k, doc, err = fetch(client, key)
        row = {"digest": digest, "disk": disk, "source": source, "ok": False, "error": err}
        if err or not doc:
            out.append(row)
            continue
        file_set = set()
        for cat, values in (doc.get("sha256") or {}).items():
            for v in values or []:
                b = digest_bytes(v)
                if b:
                    file_set.add((cat, b))
        for ext, stats in (doc.get("extensions") or {}).items():
            if not isinstance(stats, dict):
                continue
            cat = stats.get("category") or EXT_TO_CAT.get(ext if str(ext).startswith(".") else "." + str(ext))
            for v in stats.get("sha256") or []:
                b = digest_bytes(v)
                if b and cat:
                    file_set.add((cat, b))
        missing = []
        for cat, b in file_set:
            hit = conn.execute(
                "SELECT 1 FROM digests WHERE disk=? AND kind='sha' AND bucket=? AND digest=?",
                (disk, cat, b),
            ).fetchone()
            if not hit:
                # fallback any-bucket containment
                hit2 = conn.execute(
                    "SELECT 1 FROM digests WHERE disk=? AND kind='sha' AND digest=?",
                    (disk, b),
                ).fetchone()
                if not hit2:
                    missing.append(b.hex()[:12])
        once = conn.execute("SELECT COUNT(*) FROM archives WHERE digest=?", (digest,)).fetchone()[0] == 1
        expected_raw = {
            **{key: int((doc.get("raw") or {}).get(key) or 0) for key in RAW_KEYS},
            **{
                ext: int(((doc.get("extensions") or {}).get(ext) or {}).get("raw") or 0)
                for ext in ALL_EXTS
            },
        }
        stored_raw = {
            str(bucket): int(value)
            for bucket, value in conn.execute(
                "SELECT bucket,value FROM archive_raw WHERE digest=?", (digest,)
            )
        }
        expected_classes = {
            name: int((doc.get("pdf_classes") or {}).get(name) or 0)
            for name in PDF_CLASSES
        }
        stored_classes = {
            str(name): int(value)
            for name, value in conn.execute(
                "SELECT class_name,value FROM archive_pdf_classes WHERE digest=?", (digest,)
            )
        }
        raw_ok = stored_raw == expected_raw
        classes_ok = stored_classes == expected_classes
        row.update({
            "ok": len(missing) == 0 and once and raw_ok and classes_ok,
            "file_hashes": len(file_set),
            "not_contained": missing[:5],
            "archive_counted_once": once,
            "raw_counters_match": raw_ok,
            "pdf_classes_match": classes_ok,
        })
        out.append(row)
    return out


def process_keys(client, conn, keys, source, stats, missing, observed_ok=None, done_mark=True):
    with ThreadPoolExecutor(max_workers=WORKERS) as pool:
        futs = {pool.submit(fetch, client, k): k for k in keys}
        for fut in as_completed(futs):
            key = futs[fut]
            key2, doc, err = fut.result()
            digest = Path(key2).stem.lower()
            if err or doc is None:
                stats["error"] = stats.get("error", 0) + 1
                print(f"error {digest[:16]}: {err}", flush=True)
                continue
            if not doc.get("source_key_sha256"):
                doc["source_key_sha256"] = digest
            code = ingest(conn, doc, digest, source, missing)
            stats[code] = stats.get(code, 0) + 1
            if observed_ok is not None:
                doc_digest = str(doc.get("source_key_sha256") or "").lower()
                if (
                    doc.get("status") == "ok"
                    and doc.get("disk") in {"Disk-1", "Disk-2"}
                    and digest_bytes(doc_digest) is not None
                    and doc_digest == digest
                ):
                    observed_ok[doc_digest] = str(doc.get("disk"))
            # A transient download/parse error must remain retryable. The old
            # order marked the key done before validation and permanently left
            # seven finished archives outside the SQLite union.
            if done_mark and code in {"ok", "skip_dup_archive"}:
                conn.execute("INSERT OR IGNORE INTO done(key) VALUES(?)", (key2,))
        conn.commit()


def upload_sqlite_checkpoint(client, conn, identity: dict) -> None:
    """Checkpoint WAL before uploading one self-contained SQLite file."""
    conn.commit()
    conn.execute("PRAGMA wal_checkpoint(TRUNCATE)")
    client.upload_file(str(LOCAL_DB), PRIVATE, DB_KEY)
    put_json(
        client,
        DB_META_KEY,
        {
            **identity,
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "archive_rows": int(conn.execute("SELECT COUNT(*) FROM archives").fetchone()[0]),
        },
    )


def import_pickle_stores_if_needed(conn) -> int:
    """One-shot import of prior in-memory checkpoint sets into sqlite."""
    row = conn.execute("SELECT value FROM meta WHERE key='pickle_imported'").fetchone()
    if row and row[0] == "1":
        return 0
    ckpt = PARALLEL_CKPT if PARALLEL_CKPT.exists() else Path("/tmp/dedup_union_ckpt.pkl")
    if not ckpt.exists():
        return 0
    import pickle

    print("importing prior pickle stores into sqlite…", flush=True)
    ck = pickle.loads(ckpt.read_bytes())
    stores = ck.get("stores") or {}
    buf: list = []
    n = 0
    for disk in ("Disk-1", "Disk-2"):
        for kind_name, kind in (("sha", "sha"), ("weak", "weak")):
            bucket_map = (stores.get(disk) or {}).get(kind_name) or {}
            for group in ("cat", "ext"):
                for buck, vals in (bucket_map.get(group) or {}).items():
                    for dig in vals:
                        b = digest_bytes(dig)
                        if not b:
                            continue
                        buf.append((disk, kind, buck, b))
                        n += 1
                        if len(buf) >= 50000:
                            flush(conn, buf)
                            print(f"  imported {n} digest rows…", flush=True)
    flush(conn, buf)
    for key in ck.get("done_keys") or []:
        conn.execute("INSERT OR IGNORE INTO done(key) VALUES(?)", (key,))
    conn.execute("INSERT OR REPLACE INTO meta(key,value) VALUES('pickle_imported','1')")
    conn.commit()
    print(f"pickle import done rows={n}", flush=True)
    del ck, stores
    # Force re-touch of EC2/legacy done keys missing archive rows (hashes already imported).
    cleared = 0
    for (key,) in list(conn.execute("SELECT key FROM done")):
        dig = Path(key).stem.lower()
        if len(dig) != 64:
            continue
        if conn.execute("SELECT 1 FROM archives WHERE digest=?", (dig,)).fetchone():
            continue
        if key.startswith(EC2_PREFIX) or key.startswith(LEGACY_PREFIX):
            conn.execute("DELETE FROM done WHERE key=?", (key,))
            cleared += 1
    conn.commit()
    print(f"cleared done without archive row={cleared}", flush=True)
    return n


def main() -> int:
    clear_proxy()
    client = s3()
    t0 = time.time()
    baseline_etag = download_if_changed(client, BASELINE_KEY, LOCAL_BASELINE)
    baseline = json.loads(LOCAL_BASELINE.read_text())
    validate_baseline(baseline)
    skip = json.loads(client.get_object(Bucket=PRIVATE, Key=SKIP_KEY)["Body"].read())
    if skip.get("schema") != "cad-ec2-skip-done-ids/v1":
        raise RuntimeError(f"unexpected skip-ledger schema {skip.get('schema')!r}")
    skip_values = skip.get("sha256")
    if not isinstance(skip_values, list):
        raise RuntimeError("skip ledger sha256 must be a list")
    declared_skip_count = skip.get("skip_count")
    if not isinstance(declared_skip_count, int):
        raise RuntimeError("skip ledger skip_count must be an integer")
    if declared_skip_count != EXPECTED_SKIP_COUNT:
        raise RuntimeError(
            f"skip ledger must contain authoritative {EXPECTED_SKIP_COUNT} identities; got {declared_skip_count}"
        )
    if any(not isinstance(x, str) for x in skip_values):
        raise RuntimeError("skip ledger identities must all be strings")
    normalized_skip_values = [x.lower() for x in skip_values]
    skip_ids = set(normalized_skip_values)
    if declared_skip_count != len(normalized_skip_values) or len(skip_ids) != len(normalized_skip_values):
        raise RuntimeError(
            "skip ledger cardinality mismatch "
            f"declared={declared_skip_count} list={len(normalized_skip_values)} unique={len(skip_ids)}"
        )
    invalid_skip_ids = sorted(x for x in skip_ids if digest_bytes(x) is None)
    if invalid_skip_ids:
        raise RuntimeError(f"skip ledger contains {len(invalid_skip_ids)} invalid identities")
    identity = {
        "schema_version": SCHEMA_VERSION,
        "parser_version": PARSER_VERSION,
        "baseline_etag": baseline_etag,
        "baseline_id": str(baseline.get("baseline_id") or ""),
        "skip_identity_checksum": identity_checksum(skip_ids),
    }
    conn = prepare_db(client, identity)
    base_ids = set()
    for disk in ("Disk-1", "Disk-2"):
        base_ids |= {x.lower() for x in ((baseline.get("disks") or {}).get(disk) or {}).get("completed_archive_ids") or []}
    if not base_ids.issubset(skip_ids):
        raise RuntimeError(
            f"baseline identities must be a subset of authoritative skip ledger; extras={len(base_ids - skip_ids)}"
        )
    skip_only = sorted(skip_ids - base_ids)
    print(f"skip={len(skip_ids)} baseline={len(base_ids)} skip_only={len(skip_only)}", flush=True)
    baseline_verified = conn.execute(
        "SELECT value FROM meta WHERE key='baseline_counts_verified'"
    ).fetchone()
    seeded = seed_baseline(conn, baseline)
    if not baseline_verified or baseline_verified[0] != "1":
        # Parser-version v3 forces a fresh DB on first use, so at this point the
        # database contains only the aggregate baseline seed.  Validate before
        # any legacy/EC2 row can affect the comparison, then persist the gate for
        # compatible checkpoint resumes.
        nonbaseline = int(
            conn.execute("SELECT COUNT(*) FROM archives WHERE source!='baseline_seed'").fetchone()[0]
        )
        if nonbaseline:
            raise RuntimeError(
                "unverified baseline checkpoint already contains non-baseline archives"
            )
        validate_seeded_baseline_counts(conn, baseline)
        conn.execute(
            "INSERT OR REPLACE INTO meta(key,value) VALUES('baseline_counts_verified','1')"
        )
        conn.commit()
    print(f"baseline_seed_archives={seeded}", flush=True)

    missing = {"sha": [], "weak": []}
    stats = {"ok": 0, "error": 0}
    observed_ok = {
        str(digest): str(disk)
        for digest, disk in conn.execute("SELECT digest,disk FROM archives WHERE source='ec2'")
    }

    # Legacy skip-only
    legacy_todo = []
    for dig in skip_only:
        if conn.execute("SELECT 1 FROM archives WHERE digest=?", (dig,)).fetchone():
            continue
        key = f"{LEGACY_PREFIX}{dig}.json"
        # Archive presence, not the historical done marker, is authoritative.
        # Older runs wrote done before a fetch completed and stranded retries.
        legacy_todo.append(key)
    print(f"legacy_todo={len(legacy_todo)}", flush=True)
    for i in range(0, len(legacy_todo), BATCH):
        batch = legacy_todo[i : i + BATCH]
        process_keys(client, conn, batch, "legacy", stats, missing, observed_ok=None)
        done_n = min(i + len(batch), len(legacy_todo))
        sha_arch = int(conn.execute("SELECT COUNT(*) FROM archives WHERE has_sha=1").fetchone()[0])
        # Light progress every batch (no full COUNT DISTINCT); heavy checkpoint rarer.
        put_json(
            client,
            PROGRESS_KEY,
            {
                "schema": "cad-dedup-union-progress/v1",
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "phase": "legacy",
                "done_legacy": done_n,
                "todo_legacy": len(legacy_todo),
                "sha_archives": sha_arch,
                "stats": stats,
                "elapsed_s": round(time.time() - t0, 1),
            },
        )
        print(f"legacy {done_n}/{len(legacy_todo)} sha_arch={sha_arch} stats={stats}", flush=True)
        if done_n == len(legacy_todo):
            print(f"legacy ingested {done_n}/{len(legacy_todo)}", flush=True)

    # EC2 new
    ec2_objs = list_prefix(client, EC2_PREFIX)
    ec2_todo = []
    for size, key in ec2_objs:
        dig = Path(key).stem.lower()
        if dig in skip_ids:
            conn.execute("INSERT OR IGNORE INTO done(key) VALUES(?)", (key,))
            continue
        if conn.execute("SELECT 1 FROM archives WHERE digest=?", (dig,)).fetchone():
            continue
        ec2_todo.append((size, key))
    ec2_todo.sort()
    print(f"ec2_todo={len(ec2_todo)} total={len(ec2_objs)}", flush=True)

    # If the database and already-published union cover the same current
    # identity population, exit cheaply. The publisher will launch another
    # pass after a new result object arrives.
    new_ec2 = set(observed_ok) - skip_ids
    expected_ids = base_ids | skip_ids | new_ec2
    actual_sha_ids = {
        str(row[0]) for row in conn.execute("SELECT digest FROM archives WHERE has_sha=1")
    }
    raw_population = len(expected_ids)
    sha_population = len(actual_sha_ids)
    if not legacy_todo and not ec2_todo and actual_sha_ids == expected_ids:
        try:
            prior = json.loads(client.get_object(Bucket=PRIVATE, Key=OUT_KEY)["Body"].read())
            prior_cov = prior.get("coverage") or {}
            prior_sha = int(((prior_cov.get("archives_in_sha") or {}).get("combined") or 0))
            prior_raw = int(((prior_cov.get("archives_in_raw") or {}).get("combined") or 0))
            if (
                prior.get("complete")
                and prior.get("schema") == "cad-hash-union-counts/v2"
                and prior.get("parser_version") == PARSER_VERSION
                and prior.get("baseline_etag") == baseline_etag
                and prior.get("skip_identity_checksum") == identity["skip_identity_checksum"]
                and prior_sha == prior_raw == raw_population
                and ((prior.get("validation") or {}).get("raw_storage_complete") is True)
                and ((prior.get("validation") or {}).get("raw_occurrence_tree_valid") is True)
            ):
                print(f"union already current archives={raw_population}; no recount needed", flush=True)
                return 0
        except Exception:
            pass
    for i in range(0, len(ec2_todo), BATCH):
        batch = [k for _, k in ec2_todo[i : i + BATCH]]
        process_keys(client, conn, batch, "ec2", stats, missing, observed_ok=observed_ok)
        done_n = min(i + len(batch), len(ec2_todo))
        sha_arch = int(conn.execute("SELECT COUNT(*) FROM archives WHERE has_sha=1").fetchone()[0])
        put_json(
            client,
            PROGRESS_KEY,
            {
                "schema": "cad-dedup-union-progress/v1",
                "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                "phase": "ec2",
                "done_ec2": done_n,
                "todo_ec2": len(ec2_todo),
                "sha_archives": sha_arch,
                "stats": stats,
                "elapsed_s": round(time.time() - t0, 1),
            },
        )
        print(
            f"ec2 {done_n}/{len(ec2_todo)} sha_arch={sha_arch} stats={stats} "
            f"elapsed={time.time()-t0:.0f}s",
            flush=True,
        )
        if done_n == len(ec2_todo):
            c = counts(conn)
            put_json(
                client,
                PROGRESS_KEY,
                {
                    "schema": "cad-dedup-union-progress/v1",
                    "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
                    "phase": "ec2",
                    "done_ec2": done_n,
                    "todo_ec2": len(ec2_todo),
                    "sha_archives": sha_arch,
                    "combined_2d_sha": c["combined"]["sha256"]["2d"],
                    "combined_dxf_sha": c["combined"]["sha256"]["by_extension"][".dxf"],
                    "stats": stats,
                    "elapsed_s": round(time.time() - t0, 1),
                    "sqlite_uploaded": False,
                },
            )
            print(
                f"ec2 checkpoint {done_n}/{len(ec2_todo)} "
                f"2d={c['combined']['sha256']['2d']} dxf={c['combined']['sha256']['by_extension']['.dxf']} "
                f"stats={stats} elapsed={time.time()-t0:.0f}s",
                flush=True,
            )

    new_ec2 = set(observed_ok) - skip_ids
    expected_ids = base_ids | skip_ids | new_ec2
    actual_sha_ids = {
        str(row[0]) for row in conn.execute("SELECT digest FROM archives WHERE has_sha=1")
    }
    missing_archive_ids = sorted(expected_ids - actual_sha_ids)
    extra_archive_ids = sorted(actual_sha_ids - expected_ids)
    missing_by_disk = {
        disk: {
            str(row.get("digest") or "")
            for row in missing["sha"]
            if row.get("disk") == disk
        }
        for disk in ("Disk-1", "Disk-2")
    }
    covered_by_disk = {
        disk: int(conn.execute("SELECT COUNT(*) FROM archives WHERE disk=?", (disk,)).fetchone()[0])
        for disk in ("Disk-1", "Disk-2")
    }
    archives_in_raw = {
        "combined": len(expected_ids),
        "skip": len(skip_ids),
        "new_ec2": len(new_ec2),
        "baseline": len(base_ids),
        "skip_only": len(skip_only),
        "Disk-1": covered_by_disk["Disk-1"] + len(missing_by_disk["Disk-1"]),
        "Disk-2": covered_by_disk["Disk-2"] + len(missing_by_disk["Disk-2"]),
    }
    archives_in_raw["unassigned_due_to_fetch_or_validation_error"] = max(
        0,
        int(archives_in_raw["combined"])
        - int(archives_in_raw["Disk-1"])
        - int(archives_in_raw["Disk-2"]),
    )
    spots = spot_check(client, conn)
    put_json(client, SPOT_KEY, {"created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()), "checks": spots})
    print("spot_checks", json.dumps(spots), flush=True)

    c = counts(conn)
    cov = coverage(conn, archives_in_raw, missing)
    raw_occurrences = raw_occurrence_counts(conn)
    raw_rows_ok, raw_storage = raw_storage_complete(conn)
    raw_tree_ok = raw_occurrence_tree_valid(raw_occurrences)
    out = {
        "schema": "cad-hash-union-counts/v2",
        "schema_version": SCHEMA_VERSION,
        "parser_version": PARSER_VERSION,
        "baseline_etag": baseline_etag,
        "skip_identity_checksum": identity["skip_identity_checksum"],
        "created_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "baseline_id": baseline.get("baseline_id"),
        "skip_count": len(skip_ids),
        "ingest_stats": stats,
        "complete": True,
        "combined_mode": "true_set_union_cross_disk",
        "notes": [
            "SHA-256 = exact set-union of file digests over baseline + skip-only legacy + new EC2",
            "Each archive once by sha256(source_key)",
            "Combined is true set-union (not Disk-1+Disk-2 sum)",
            "Weak lists exist for baseline+legacy; EC2 schema currently omits weak arrays",
        ],
        "coverage": cov,
        "disks": c,
        "raw_occurrences": raw_occurrences,
    }
    sha_cov = int((cov.get("archives_in_sha") or {}).get("combined") or 0)
    raw_cov = int((archives_in_raw.get("combined") or 0))
    fatal_stat_keys = {
        "error",
        "skip_bad",
        "skip_disk",
        "skip_digest",
        "skip_identity_mismatch",
        "invalid_sha_digest",
        "invalid_result_schema",
    }
    fatal_stats = {k: int(stats.get(k) or 0) for k in fatal_stat_keys if int(stats.get(k) or 0)}
    spot_failures = [row for row in spots if not row.get("ok")]
    exact = (
        sha_cov == raw_cov
        and actual_sha_ids == expected_ids
        and not missing["sha"]
        and not fatal_stats
        and not spot_failures
        and int(archives_in_raw.get("unassigned_due_to_fetch_or_validation_error") or 0) == 0
        and raw_rows_ok
        and raw_tree_ok
    )
    out["complete"] = bool(exact)
    out["validation"] = {
        "sha_coverage_equals_raw": sha_cov == raw_cov,
        "archive_identity_sets_equal": actual_sha_ids == expected_ids,
        "missing_archive_identity_count": len(missing_archive_ids),
        "extra_archive_identity_count": len(extra_archive_ids),
        "missing_archive_identity_sample": missing_archive_ids[:10],
        "extra_archive_identity_sample": extra_archive_ids[:10],
        "missing_sha_list_count": len(missing["sha"]),
        "fatal_ingest_stats": fatal_stats,
        "spot_check_failures": len(spot_failures),
        "unassigned_raw_archives": int(archives_in_raw.get("unassigned_due_to_fetch_or_validation_error") or 0),
        "raw_storage_complete": bool(raw_rows_ok),
        "raw_occurrence_tree_valid": bool(raw_tree_ok),
        "raw_storage": raw_storage,
    }
    # Only mark complete / publish sticky when every independent gate passes.
    if not exact:
        out["notes"] = list(out.get("notes") or []) + [
            f"incomplete validation sha_archives={sha_cov} raw_archives={raw_cov}; sticky not advanced"
        ]
        print(
            f"INCOMPLETE sha={sha_cov} raw={raw_cov} missing={len(missing['sha'])} "
            f"fatal={fatal_stats} spot_failures={len(spot_failures)}; sticky not advanced",
            flush=True,
        )
    body = json.dumps(out, separators=(",", ":"), ensure_ascii=True).encode()
    LOCAL_OUT.write_text(json.dumps(out, indent=2))
    put_json(client, COVERAGE_KEY, cov)
    put_json(
        client,
        DONE_KEY,
        {
            "schema": "cad-dedup-union-done/v1",
            "count": int(conn.execute("SELECT COUNT(*) FROM done").fetchone()[0]),
            "sha_archives": cov["archives_in_sha"]["combined"],
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        },
    )
    upload_sqlite_checkpoint(client, conn, identity)
    if out.get("complete"):
        client.put_object(Bucket=PRIVATE, Key=STICKY_KEY, Body=body, ContentType="application/json", CacheControl="no-store")
    add = c["combined_additive_diag"]["sha256"]["2d"]
    uni = c["combined"]["sha256"]["2d"]
    print("COMPLETE" if exact else "INCOMPLETE", flush=True)
    for scope in ("Disk-1", "Disk-2", "combined"):
        print(scope, "2d_sha", c[scope]["sha256"]["2d"], "2d_weak", c[scope]["weak"]["2d"], flush=True)
    print(f"combined_2d union={uni} additive={add} cross_disk_dups={add-uni}", flush=True)
    print("coverage", json.dumps(cov["archives_in_sha"]), "raw", json.dumps(archives_in_raw), flush=True)
    print(f"elapsed={time.time()-t0:.1f}s", flush=True)
    put_json(
        client,
        PROGRESS_KEY,
        {
            "schema": "cad-dedup-union-progress/v1",
            "updated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
            "phase": "complete" if exact else "incomplete",
            "coverage": cov,
            "counts_summary": {
                s: {"2d": c[s]["sha256"]["2d"], ".dxf": c[s]["sha256"]["by_extension"][".dxf"]}
                for s in ("Disk-1", "Disk-2", "combined")
            },
        },
    )
    # OUT_KEY is the commit marker. Publish it only after every checkpoint and
    # auxiliary artifact succeeds, so an early-exit can never strand a partial
    # finalization after a transient S3 failure.
    client.put_object(
        Bucket=PRIVATE,
        Key=OUT_KEY,
        Body=body,
        ContentType="application/json",
        CacheControl="no-store",
    )
    return 0 if exact else 2


if __name__ == "__main__":
    import traceback
    try:
        raise SystemExit(main())
    except SystemExit:
        raise
    except Exception:
        traceback.print_exc()
        raise
