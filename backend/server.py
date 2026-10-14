import sys
import os
from flask import Flask, jsonify, request
from flask_cors import CORS

current_dir = os.path.dirname(os.path.abspath(__file__))
parent_dir = os.path.dirname(current_dir)
if parent_dir not in sys.path:
    sys.path.insert(0, parent_dir)

try:
    from monitor import logs_reader
    from monitor import detector
    from monitor import audit_log
except ImportError as e:
    print(f"Failed to import monitor module safely. Error: {e}")
    sys.exit(1)

app = Flask(__name__)
CORS(app)

# Ensure existing telemetry events are backfilled into the audit log once on startup
try:
    audit_log.sync_existing_raw_logs()
except Exception as sync_err:
    print(f"[AUDIT LOG WARNING] Startup sync notice: {sync_err}")

@app.route('/logs', methods=['GET'])
def get_logs():
    """Returns the raw logs chronologically fetched directly from attack_log.json."""
    try:
        logs = logs_reader.read_logs()
        return jsonify(logs), 200
    except Exception as e:
        return jsonify([]), 500

@app.route('/analysis', methods=['GET'])
def get_analysis():
    """Channels logs into detector.py engine and serves deterministic threat results."""
    try:
        logs = logs_reader.read_logs()
        analysis = detector.analyze_logs(logs)
        return jsonify(analysis), 200
    except Exception as e:
        return jsonify({
            "total_files": 0,
            "time_taken": 0.0,
            "alert_level": "LOW",
            "risk_score": 0,
            "summary": "System offline or log read error.",
            "attack_detected": False
        }), 500

# ==============================================================================
# CRYPTOGRAPHIC FORENSICS & AUDIT LOG ENDPOINTS
# ==============================================================================

@app.route('/audit/records', methods=['GET'])
def get_audit_records():
    """
    Returns production audit records along with real-time chain verification status.
    Avoids duplicate entries by syncing only unrecorded events.
    """
    try:
        audit_log.sync_existing_raw_logs()
        records = audit_log.load_records()
        verification = audit_log.verify_chain(records)
        return jsonify({
            "records": records,
            "verification": verification,
            "count": len(records),
            "genesis_prev_hash": audit_log.GENESIS_PREV_HASH,
            "limitation": "Hash chaining provides tamper-evident audit logging. Note: It does not provide immutable storage or prove origin if an attacker can overwrite all records and rehash."
        }), 200
    except Exception as e:
        return jsonify({"error": str(e), "records": [], "count": 0}), 500

@app.route('/audit/verify', methods=['GET', 'POST'])
def verify_audit_records():
    """
    Independently recalculates every SHA-256 hash across the chain to verify integrity.
    """
    try:
        records = audit_log.load_records()
        verification = audit_log.verify_chain(records)
        return jsonify(verification), 200
    except Exception as e:
        return jsonify({
            "verified": False,
            "total_records": 0,
            "message": f"Verification failed due to error: {str(e)}",
            "error": str(e)
        }), 500

@app.route('/audit/demo', methods=['GET'])
def get_demo():
    """Returns the current isolated tampering demonstration chain."""
    try:
        records = audit_log.get_demo_chain()
        verification = audit_log.verify_chain(records)
        return jsonify({
            "records": records,
            "verification": verification,
            "count": len(records)
        }), 200
    except Exception as e:
        return jsonify({"error": str(e), "records": []}), 500

@app.route('/audit/demo/reset', methods=['POST'])
def reset_demo():
    """Resets the isolated demonstration chain to an authentic, valid state."""
    try:
        records = audit_log.reset_demo_chain()
        verification = audit_log.verify_chain(records)
        return jsonify({
            "message": "Demo audit log restored to untouched state.",
            "records": records,
            "verification": verification
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/audit/demo/tamper', methods=['POST'])
def tamper_demo():
    """
    Demonstrates tamper detection by mutating a test record in the isolated sandbox.
    Accepted JSON: { "tamper_type": "modify_event" | "modify_hash" | "delete_record" | "reorder_records", "target_index": int }
    """
    try:
        data = request.get_json(silent=True) or {}
        tamper_type = data.get("tamper_type", "modify_event")
        target_index = int(data.get("target_index", 1))
        tamper_result = audit_log.tamper_demo_chain(tamper_type=tamper_type, target_index=target_index)
        verification = audit_log.verify_chain(tamper_result["records"])
        return jsonify({
            "tamper_type": tamper_type,
            "description": tamper_result["description"],
            "records": tamper_result["records"],
            "verification": verification
        }), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

@app.route('/audit/demo/verify', methods=['GET', 'POST'])
def verify_demo():
    """Verifies the isolated demonstration chain."""
    try:
        records = audit_log.get_demo_chain()
        verification = audit_log.verify_chain(records)
        return jsonify(verification), 200
    except Exception as e:
        return jsonify({"error": str(e)}), 500

PORT = 3600

if __name__ == '__main__':
    app.run(host='0.0.0.0', port=PORT, debug=True)
