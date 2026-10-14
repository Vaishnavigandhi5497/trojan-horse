import unittest
import os
import sys
import tempfile
import json
from copy import deepcopy

# Add project root to sys.path
BASE_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from monitor import audit_log


class TestAuditLogForensics(unittest.TestCase):
    def setUp(self):
        """Create a temporary file for isolated test runs."""
        self.temp_file = tempfile.NamedTemporaryFile(delete=False, suffix=".json")
        self.temp_path = self.temp_file.name
        self.temp_file.close()

    def tearDown(self):
        """Clean up temporary test file."""
        if os.path.exists(self.temp_path):
            os.remove(self.temp_path)

    def test_1_newly_created_audit_chain_passes_verification(self):
        """Scenario 1: A newly created audit chain passes verification."""
        events = [
            {"event": "PROCESS_START", "file": "/usr/bin/test_service", "status": "SUCCESS"},
            {"event": "FILE_ENCRYPTED", "file": "/data/confidential.pdf", "status": "SUCCESS"},
            {"event": "FOLDER_RENAMED", "file": "/data_locked", "status": "SUCCESS", "count": 1}
        ]
        for evt in events:
            audit_log.append_record(evt, file_path=self.temp_path)

        records = audit_log.load_records(self.temp_path)
        self.assertEqual(len(records), 3)

        # Check genesis link
        self.assertEqual(records[0]["prev_hash"], audit_log.GENESIS_PREV_HASH)
        # Check chain link
        self.assertEqual(records[1]["prev_hash"], records[0]["record_hash"])
        self.assertEqual(records[2]["prev_hash"], records[1]["record_hash"])

        res = audit_log.verify_chain(records)
        self.assertTrue(res["verified"])
        self.assertIsNone(res["error"])
        self.assertEqual(res["total_records"], 3)

    def test_2_modifying_event_causes_verification_to_fail(self):
        """Scenario 2: Modifying an event payload causes verification to fail."""
        audit_log.append_record({"event": "FILE_READ", "file": "/etc/hosts"}, file_path=self.temp_path)
        audit_log.append_record({"event": "FILE_WRITE", "file": "/etc/passwd"}, file_path=self.temp_path)
        audit_log.append_record({"event": "NETWORK_OUT", "file": "10.0.0.1"}, file_path=self.temp_path)

        records = audit_log.load_records(self.temp_path)

        # Adversary alters the event payload in the second record without updating hash
        records[1]["event_data"]["file"] = "/etc/harmless_file"

        res = audit_log.verify_chain(records)
        self.assertFalse(res["verified"])
        self.assertEqual(res["invalid_index"], 1)
        self.assertEqual(res["error"], "Record content hash mismatch")
        self.assertIn("Hash mismatch at index 1", res["message"])

    def test_3_modifying_stored_hash_causes_verification_to_fail(self):
        """Scenario 3: Modifying a stored hash causes verification to fail."""
        audit_log.append_record({"event": "LOGIN", "status": "SUCCESS"}, file_path=self.temp_path)
        audit_log.append_record({"event": "LOGOUT", "status": "SUCCESS"}, file_path=self.temp_path)

        records = audit_log.load_records(self.temp_path)

        # Adversary corrupts the stored hash directly
        records[0]["record_hash"] = "deadbeef" * 8

        res = audit_log.verify_chain(records)
        self.assertFalse(res["verified"])
        self.assertEqual(res["invalid_index"], 0)
        self.assertEqual(res["error"], "Record content hash mismatch")

    def test_4_deleting_record_breaks_previous_hash_link(self):
        """Scenario 4: Deleting a record is detected as a broken link."""
        audit_log.append_record({"event": "STEP_1", "status": "SUCCESS"}, file_path=self.temp_path)
        audit_log.append_record({"event": "STEP_2", "status": "SUCCESS"}, file_path=self.temp_path)
        audit_log.append_record({"event": "STEP_3", "status": "SUCCESS"}, file_path=self.temp_path)

        records = audit_log.load_records(self.temp_path)
        # Delete STEP_2 (index 1)
        del records[1]

        res = audit_log.verify_chain(records)
        self.assertFalse(res["verified"])
        # Now records[1] is STEP_3 whose prev_hash pointed to STEP_2
        self.assertEqual(res["invalid_index"], 1)
        self.assertEqual(res["error"], "Previous hash link mismatch")
        self.assertIn("Broken chain link at index 1", res["message"])

    def test_5_reordering_records_is_detected(self):
        """Scenario 5: Reordering records violates hash links and is detected."""
        audit_log.append_record({"event": "OP_ALPHA", "seq": 1}, file_path=self.temp_path)
        audit_log.append_record({"event": "OP_BETA", "seq": 2}, file_path=self.temp_path)
        audit_log.append_record({"event": "OP_GAMMA", "seq": 3}, file_path=self.temp_path)

        records = audit_log.load_records(self.temp_path)
        # Swap OP_BETA and OP_GAMMA
        records[1], records[2] = records[2], records[1]

        res = audit_log.verify_chain(records)
        self.assertFalse(res["verified"])
        self.assertEqual(res["invalid_index"], 1)
        self.assertEqual(res["error"], "Previous hash link mismatch")

    def test_6_empty_audit_log_handled_correctly(self):
        """Scenario 6: An empty audit log is handled safely and reports integrity intact."""
        records = []
        res = audit_log.verify_chain(records)
        self.assertTrue(res["verified"])
        self.assertEqual(res["total_records"], 0)
        self.assertIsNone(res["error"])
        self.assertIn("empty", res["message"].lower())

    def test_7_malformed_input_does_not_crash_service(self):
        """Scenario 7: Malformed input does not crash or falsely report success."""
        # Case A: Input is not a list
        res_non_list = audit_log.verify_chain("not a list")
        self.assertFalse(res_non_list["verified"])
        self.assertIsNotNone(res_non_list["error"])

        # Case B: Record missing required fields
        malformed_records = [
            {"record_id": "REC-01", "prev_hash": audit_log.GENESIS_PREV_HASH}  # missing timestamp, event_data, record_hash
        ]
        res_missing = audit_log.verify_chain(malformed_records)
        self.assertFalse(res_missing["verified"])
        self.assertEqual(res_missing["invalid_index"], 0)
        self.assertIn("Missing keys", res_missing["error"])

        # Case C: Genesis record with invalid prev_hash
        bad_genesis = [
            {
                "record_id": "REC-01",
                "timestamp": "2026-10-13T00:00:00",
                "event_data": {"event": "TEST"},
                "prev_hash": "bad_genesis_hash",
                "record_hash": "abc"
            }
        ]
        res_bad_genesis = audit_log.verify_chain(bad_genesis)
        self.assertFalse(res_bad_genesis["verified"])
        self.assertEqual(res_bad_genesis["invalid_index"], 0)
        self.assertIn("genesis", res_bad_genesis["message"].lower())

    def test_8_demonstration_reset_and_clean_chain_passes(self):
        """Scenario 8: Demonstration dataset can be tampered, failed, reset, and passes again."""
        # 1. Start with clean demo chain
        clean_chain = audit_log.reset_demo_chain()
        res_clean = audit_log.verify_chain(clean_chain)
        self.assertTrue(res_clean["verified"])

        # 2. Tamper demo chain (modify event)
        tampered = audit_log.tamper_demo_chain("modify_event", target_index=1)
        res_tampered = audit_log.verify_chain(tampered["records"])
        self.assertFalse(res_tampered["verified"])

        # 3. Reset demo chain
        restored = audit_log.reset_demo_chain()
        res_restored = audit_log.verify_chain(restored)
        self.assertTrue(res_restored["verified"])
        self.assertEqual(len(restored), len(clean_chain))


if __name__ == "__main__":
    unittest.main()
