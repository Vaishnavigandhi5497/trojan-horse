import os
import json
from datetime import datetime

BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

DEV_PATH = os.path.join(BASE_DIR, "trojan", "data", "attack_log.json")
PROD_PATH = os.path.expanduser("~/Desktop/cybersec_data/attack_log.json")

def _write_to_path(path, data_str):
    """Helper to write to a specific path, creating directories if needed."""
    try:
        os.makedirs(os.path.dirname(path), exist_ok=True)
        with open(path, "a") as f:
            f.write(data_str + "\n")
    except Exception as e:
        print(f"[LOGGER ERROR] Failed to write to {path}: {e}")

def log_event(event_type, file_path=None, status="SUCCESS", **kwargs):
    """
    Logs an event in structured JSON line format.
    Appends events line-by-line avoiding full file re-write.
    """
    try:
        now_ts = datetime.now().isoformat()
        log_entry = {
            "timestamp": now_ts,
            "event": event_type,
            "file": file_path,
            "status": status
        }
        
        if kwargs:
            log_entry.update(kwargs)
            
        data_str = json.dumps(log_entry)
        
        _write_to_path(DEV_PATH, data_str)
        _write_to_path(PROD_PATH, data_str)

        # Cryptographic Forensics: Record event into the tamper-evident audit chain
        try:
            import sys
            if BASE_DIR not in sys.path:
                sys.path.insert(0, BASE_DIR)
            from monitor import audit_log
            audit_log.record_security_event(
                event_type=event_type,
                file_path=file_path,
                status=status,
                custom_timestamp=now_ts,
                **kwargs
            )
        except Exception as audit_err:
            print(f"[AUDIT LOG WARNING] Could not append to audit chain: {audit_err}")
            
    except Exception as e:
        print(f"[LOGGER ERROR] Exception creating log entry: {str(e)}")
