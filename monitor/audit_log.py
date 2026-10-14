import os
import json
import hashlib
import uuid
from datetime import datetime
from copy import deepcopy

# Fixed 64-character hexadecimal zero string representing the genesis previous-hash.
# Documented convention: The first record in the chain has no predecessor, so it references this constant.
GENESIS_PREV_HASH = "0" * 64

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
AUDIT_LOG_PATH = os.path.join(BASE_DIR, "trojan", "data", "audit_log.json")
DEMO_LOG_PATH = os.path.join(BASE_DIR, "trojan", "data", "audit_log_demo.json")

def canonical_serialize(record_dict):
    """
    Produces a deterministic UTF-8 byte representation of a record for SHA-256 hashing.
    Crucial rules:
    1. 'record_hash' is strictly excluded from its own hash calculation.
    2. Dictionary keys are sorted alphabetically (sort_keys=True).
    3. Compact separators (',', ':') eliminate non-deterministic whitespace variations.
    4. ensure_ascii=True ensures uniform character encoding.
    """
    record_copy = {k: v for k, v in record_dict.items() if k != "record_hash"}
    serialized_str = json.dumps(record_copy, sort_keys=True, separators=(',', ':'), ensure_ascii=True)
    return serialized_str.encode("utf-8")

def compute_hash(record_dict):
    """Calculates SHA-256 hex digest for a record using canonical serialization."""
    canonical_bytes = canonical_serialize(record_dict)
    return hashlib.sha256(canonical_bytes).hexdigest()

def load_records(file_path=AUDIT_LOG_PATH):
    """Loads audit records from file in chronological order. Returns empty list if missing or empty."""
    if not os.path.exists(file_path):
        return []
    records = []
    try:
        with open(file_path, "r", encoding="utf-8") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        records.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        print(f"[AUDIT LOG] Error reading records from {file_path}: {e}")
    return records

def save_records(records, file_path=AUDIT_LOG_PATH):
    """Persists records line-by-line as JSON Lines."""
    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "w", encoding="utf-8") as f:
        for r in records:
            f.write(json.dumps(r) + "\n")

def append_record(event_data, file_path=AUDIT_LOG_PATH, custom_timestamp=None):
    """
    Appends a new tamper-evident audit record to the specified log file.
    Calculates previous hash and current record hash deterministically.
    """
    records = load_records(file_path)
    if records:
        prev_hash = records[-1]["record_hash"]
        rec_num = len(records) + 1
    else:
        prev_hash = GENESIS_PREV_HASH
        rec_num = 1

    record_id = f"AUD-{rec_num:05d}"
    timestamp = custom_timestamp or datetime.now().isoformat()

    new_record = {
        "record_id": record_id,
        "timestamp": timestamp,
        "event_data": event_data,
        "prev_hash": prev_hash
    }

    # Deterministically calculate current record's SHA-256 hash
    new_record["record_hash"] = compute_hash(new_record)

    os.makedirs(os.path.dirname(file_path), exist_ok=True)
    with open(file_path, "a", encoding="utf-8") as f:
        f.write(json.dumps(new_record) + "\n")

    return new_record

def record_security_event(event_type, file_path=None, status="SUCCESS", custom_timestamp=None, **kwargs):
    """
    Boundary integration: Converts an event into an audit log record once.
    Passes custom_timestamp to ensure identity with raw log timestamp.
    """
    event_data = {
        "event": event_type,
        "file": file_path,
        "status": status
    }
    if kwargs:
        event_data.update(kwargs)

    return append_record(event_data, AUDIT_LOG_PATH, custom_timestamp=custom_timestamp)

def verify_chain(records):
    """
    Cryptographically verifies an audit log chain.
    Recalculates every record's SHA-256 hash from its canonical contents and
    validates that each record's prev_hash points to the preceding record's calculated hash.

    Returns a structured dictionary:
    {
        "verified": bool,
        "total_records": int,
        "message": str,
        "error": str or None,
        "invalid_index": int or None,
        "invalid_record": dict or None
    }
    """
    if not isinstance(records, list):
        return {
            "verified": False,
            "total_records": 0,
            "message": "Malformed input: records must be a list.",
            "error": "Input is not a list",
            "invalid_index": None,
            "invalid_record": None
        }

    if len(records) == 0:
        return {
            "verified": True,
            "total_records": 0,
            "message": "Audit log is empty. Integrity intact (0 records).",
            "error": None,
            "invalid_index": None,
            "invalid_record": None
        }

    computed_hashes = []
    issues = []

    for i, record in enumerate(records):
        # 1. Check structural validity
        if not isinstance(record, dict):
            issue = {
                "index": i,
                "record_id": f"INDEX-{i}",
                "error_type": "Record is not a valid JSON dictionary",
                "details": f"Malformed record at index {i}: item is not an object.",
                "record": str(record)
            }
            issues.append(issue)
            continue

        required_keys = ["record_id", "timestamp", "event_data", "prev_hash", "record_hash"]
        missing_keys = [k for k in required_keys if k not in record]
        if missing_keys:
            issue = {
                "index": i,
                "record_id": record.get("record_id", f"INDEX-{i}"),
                "error_type": f"Missing keys: {missing_keys}",
                "details": f"Malformed record '{record.get('record_id', f'index {i}')}': missing required fields {missing_keys}.",
                "record": record
            }
            issues.append(issue)
            continue

        # 2. Check previous hash reference
        expected_prev_hash = GENESIS_PREV_HASH if i == 0 else (computed_hashes[i - 1] if len(computed_hashes) > i - 1 else records[i - 1].get("record_hash"))
        actual_prev_hash = record.get("prev_hash")

        if actual_prev_hash != expected_prev_hash:
            if i == 0:
                err_msg = (f"Genesis record '{record['record_id']}' has invalid prev_hash. "
                           f"Expected fixed genesis hash ({GENESIS_PREV_HASH[:12]}...), "
                           f"got ({str(actual_prev_hash)[:12]}...).")
            else:
                err_msg = (f"Broken chain link at index {i} (Record '{record['record_id']}'). "
                           f"Claims prev_hash {str(actual_prev_hash)[:16]}..., but preceding "
                           f"record '{records[i-1].get('record_id')}' calculated hash is {expected_prev_hash[:16]}... "
                           f"(indicates deleted or reordered records).")
            issues.append({
                "index": i,
                "record_id": record["record_id"],
                "error_type": "Previous hash link mismatch",
                "details": err_msg,
                "record": record
            })

        # 3. Recalculate current record hash deterministically
        try:
            recalculated_hash = compute_hash(record)
        except Exception as e:
            issues.append({
                "index": i,
                "record_id": record["record_id"],
                "error_type": "Serialization failure",
                "details": f"Serialization error at record '{record['record_id']}': {str(e)}",
                "record": record
            })
            computed_hashes.append(record.get("record_hash", ""))
            continue

        stored_hash = record.get("record_hash")
        if stored_hash != recalculated_hash:
            issues.append({
                "index": i,
                "record_id": record["record_id"],
                "error_type": "Record content hash mismatch",
                "details": (f"Hash mismatch at index {i} (Record '{record['record_id']}'). "
                            f"Stored hash: {str(stored_hash)[:16]}..., "
                            f"Recalculated hash: {recalculated_hash[:16]}... "
                            f"(indicates record payload or stored hash was modified)."),
                "record": record
            })

        computed_hashes.append(recalculated_hash)

    if issues:
        first = issues[0]
        summary_msg = f"{len(issues)} integrity threat(s) detected. " + first["details"]
        return {
            "verified": False,
            "total_records": len(records),
            "total_threats": len(issues),
            "issues": issues,
            "message": first["details"],
            "summary": summary_msg,
            "error": first["error_type"],
            "invalid_index": first["index"],
            "invalid_record": first["record"]
        }

    return {
        "verified": True,
        "total_records": len(records),
        "total_threats": 0,
        "issues": [],
        "message": f"Cryptographic audit chain fully verified! All {len(records)} SHA-256 hashes and chain links are intact.",
        "summary": "Cryptographic audit chain fully verified. Zero threats detected.",
        "error": None,
        "invalid_index": None,
        "invalid_record": None
    }

def sync_existing_raw_logs():
    """
    Backfills existing raw events from attack_log.json into the tamper-evident audit log.
    Ensures each raw log is recorded exactly once without duplicates upon restart.
    """
    from monitor import logs_reader
    raw_logs = logs_reader.read_logs()
    existing_records = load_records(AUDIT_LOG_PATH)

    # Build set of already recorded events based on timestamp + event + file
    recorded_signatures = set()
    for rec in existing_records:
        evt = rec.get("event_data", {})
        ts = rec.get("timestamp", "")
        sig = f"{ts}|{evt.get('event')}|{evt.get('file')}"
        recorded_signatures.add(sig)

    new_count = 0
    for raw in raw_logs:
        ts = raw.get("timestamp", "")
        evt_type = raw.get("event", "")
        fpath = raw.get("file", "")
        sig = f"{ts}|{evt_type}|{fpath}"

        if sig not in recorded_signatures:
            extra = {k: v for k, v in raw.items() if k not in ["timestamp", "event", "file", "status"]}
            append_record(
                event_data={
                    "event": evt_type,
                    "file": fpath,
                    "status": raw.get("status", "SUCCESS"),
                    **extra
                },
                file_path=AUDIT_LOG_PATH,
                custom_timestamp=ts
            )
            recorded_signatures.add(sig)
            new_count += 1

    return new_count

# ==============================================================================
# TAMPERING DEMONSTRATION ENGINE (ISOLATED SANDBOX)
# ==============================================================================

SAMPLE_DEMO_EVENTS = [
    {
        "event": "PROCESS_SPAWNED",
        "file": "/Applications/SystemCleanerPro.app",
        "status": "SUCCESS",
        "details": "User executed application binary"
    },
    {
        "event": "FILE_ENCRYPTED",
        "file": "/Users/victim/Documents/financial_q3.xlsx.enc",
        "status": "SUCCESS",
        "details": "AES-256 payload encrypted target file"
    },
    {
        "event": "FILE_ENCRYPTED",
        "file": "/Users/victim/Documents/passwords_backup.kdbx.enc",
        "status": "SUCCESS",
        "details": "AES-256 payload encrypted target file"
    },
    {
        "event": "FOLDER_RENAMED",
        "file": "/Users/victim/Documents_locked",
        "status": "SUCCESS",
        "details": "Target folder renamed with ransom note dropped"
    },
    {
        "event": "NETWORK_BEACON",
        "file": "198.51.100.42:8443",
        "status": "SUCCESS",
        "details": "Encrypted C2 telemetry beacon emitted"
    }
]

def reset_demo_chain():
    """
    Initializes a clean, completely valid demo audit chain in DEMO_LOG_PATH.
    Never modifies production AUDIT_LOG_PATH.
    """
    if os.path.exists(DEMO_LOG_PATH):
        try:
            os.remove(DEMO_LOG_PATH)
        except OSError:
            pass

    records = []
    base_time = "2026-10-13T10:00:00.000000"
    for i, evt in enumerate(SAMPLE_DEMO_EVENTS):
        simulated_ts = f"2026-10-13T10:00:0{i}.123456"
        prev_hash = records[-1]["record_hash"] if records else GENESIS_PREV_HASH
        rec = {
            "record_id": f"DEMO-{i+1:04d}",
            "timestamp": simulated_ts,
            "event_data": evt,
            "prev_hash": prev_hash
        }
        rec["record_hash"] = compute_hash(rec)
        records.append(rec)

    save_records(records, DEMO_LOG_PATH)
    return records

def get_demo_chain():
    """Returns the current demo chain, initializing it if not present."""
    records = load_records(DEMO_LOG_PATH)
    if not records:
        records = reset_demo_chain()
    return records

def tamper_demo_chain(tamper_type="modify_event", target_index=1):
    """
    Safely tampers with the isolated demo dataset to demonstrate verification failure.
    Supported tamper_type options:
    - 'modify_event': Alters event payload without updating hash.
    - 'modify_hash': Corrupts stored record_hash directly.
    - 'delete_record': Deletes an intermediate record creating a link gap.
    - 'reorder_records': Swaps two adjacent records.
    """
    records = get_demo_chain()
    if not records or len(records) < 3:
        records = reset_demo_chain()

    idx = max(0, min(target_index, len(records) - 1))
    tampered_description = ""

    if tamper_type == "modify_event":
        original_event = records[idx]["event_data"].get("event", "UNKNOWN")
        records[idx]["event_data"]["event"] = "AUTHORIZED_ADMIN_SCAN"
        records[idx]["event_data"]["file"] = "/System/Library/BenignService"
        records[idx]["event_data"]["tampered"] = True
        tampered_description = (f"Modified payload of Record #{idx+1} ({records[idx]['record_id']}) "
                                f"from '{original_event}' to 'AUTHORIZED_ADMIN_SCAN' without updating hash.")

    elif tamper_type == "modify_hash":
        corrupted_hash = "deadbeef" * 8
        records[idx]["record_hash"] = corrupted_hash
        tampered_description = (f"Overwrote stored hash of Record #{idx+1} ({records[idx]['record_id']}) "
                                f"with corrupted hash '{corrupted_hash[:16]}...'.")

    elif tamper_type == "delete_record":
        deleted_rec = records.pop(idx)
        tampered_description = (f"Deleted intermediate Record #{idx+1} ({deleted_rec['record_id']}) "
                                f"from the chain. Preceding link in next record is now broken.")

    elif tamper_type == "reorder_records":
        if idx >= len(records) - 1:
            idx = len(records) - 2
        records[idx], records[idx + 1] = records[idx + 1], records[idx]
        tampered_description = (f"Swapped positions of Record #{idx+1} and Record #{idx+2}. "
                                f"Sequence order is violated.")

    else:
        raise ValueError(f"Unknown tamper_type: {tamper_type}")

    save_records(records, DEMO_LOG_PATH)
    return {
        "tamper_type": tamper_type,
        "description": tampered_description,
        "records": records
    }
