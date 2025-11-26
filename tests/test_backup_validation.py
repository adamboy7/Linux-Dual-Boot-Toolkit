import json
import tempfile
import unittest
from pathlib import Path

from libraries.backup_validation import (
    extract_macs_from_info_content,
    extract_macs_from_json_metadata,
    extract_macs_from_path,
    parse_backup_payload,
    validate_backup_matches,
)


class BackupValidationTests(unittest.TestCase):
    def test_extract_macs_from_path_with_colon_and_raw_segments(self):
        adapter, device = extract_macs_from_path(
            r"C:\\bt\\bt_key_backup_001a7dda710b\\aabbccddeeff.bak"
        )
        self.assertEqual(adapter, "00:1A:7D:DA:71:0B")
        self.assertEqual(device, "AA:BB:CC:DD:EE:FF")

    def test_extract_macs_from_info_content_reads_adapter_and_device(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            info_path = Path(tmpdir) / "info"
            info_path.write_text(
                """
[General]
Address=AA:BB:CC:DD:EE:FF
Adapter=11:22:33:44:55:66
"""
            )

            adapter, device = extract_macs_from_info_content(str(info_path))

        self.assertEqual(adapter, "11:22:33:44:55:66")
        self.assertEqual(device, "AA:BB:CC:DD:EE:FF")

    def test_extract_macs_from_json_metadata_prefers_source_path(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_path = Path(tmpdir) / "backup.json"
            payload = {
                "source_info_path": "/var/lib/bluetooth/11:22:33:44:55:66/AA:BB:CC:DD:EE:FF/info",
            }
            backup_path.write_text(json.dumps(payload))

            adapter, device = extract_macs_from_json_metadata(str(backup_path))

        self.assertEqual(adapter, "11:22:33:44:55:66")
        self.assertEqual(device, "AA:BB:CC:DD:EE:FF")

    def test_validate_backup_matches_blocks_mismatch_and_calls_callback(self):
        messages: list[str] = []

        def capture(message: str, title: str | None):
            messages.append(f"{title}: {message}")

        with tempfile.TemporaryDirectory() as tmpdir:
            backup_path = Path(tmpdir) / "backup.json"
            payload = {
                "adapter_mac": "00:11:22:33:44:55",
                "device_mac": "AA:BB:CC:DD:EE:FF",
            }
            backup_path.write_text(json.dumps(payload))

            matches = validate_backup_matches(
                "11:22:33:44:55:66",
                "FF:EE:DD:CC:BB:AA",
                str(backup_path),
                capture,
            )

        self.assertFalse(matches)
        self.assertTrue(messages)
        self.assertIn("Restore blocked", messages[0])

    def test_parse_backup_payload_valid_hex(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_path = Path(tmpdir) / "bt_key_backup.json"
            payload = {
                "key_path": r"SYSTEM\\CurrentControlSet\\Services\\BTHPORT\\Parameters\\Keys\\001a7dda710b",
                "value_name": "aabbccddeeff",
                "value_type": "3",
                "value_format": "hex",
                "value_data": "0A0B0C",
            }
            backup_path.write_text(json.dumps(payload))

            result = parse_backup_payload(str(backup_path))

        self.assertEqual(result.payload["reg_type"], 3)
        self.assertEqual(result.payload["reg_value"], bytes.fromhex("0A0B0C"))
        self.assertEqual(result.payload["value_format"], "hex")

    def test_parse_backup_payload_rejects_invalid_format(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            backup_path = Path(tmpdir) / "bt_key_backup.json"
            payload = {
                "key_path": "path",
                "value_name": "name",
                "value_type": "3",
                "value_format": "unknown",
                "value_data": "ignored",
            }
            backup_path.write_text(json.dumps(payload))

            with self.assertRaises(ValueError):
                parse_backup_payload(str(backup_path))


if __name__ == "__main__":
    unittest.main()
