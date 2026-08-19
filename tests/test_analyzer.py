import unittest

from pathlib import Path

from analyzer import (determine_severity, determine_status, parse_log_file)

class TestSeverityCalssification(unittest.TestCase):

    def test_low_severity(self):
        self.assertEqual(determine_severity(2), "LOW")

    def test_medium_severity(self):
        self.assertEqual(determine_severity(4), "MEDIUM")

    def test_high_severity(self):
        self.assertEqual(determine_severity(5), "HIGH")

    def test_brute_force_severity(self):
        self.assertEqual(determine_severity(10), "HIGH")


class TestStatusClassificatio(unittest.TestCase):

    def test_low_status(self):
        self.assertEqual(determine_status("LOW"), "Normal/low-risk activity")

    def test_medium_status(self):
        self.assertEqual(determine_status("MEDIUM"), "Suspicious login activity")

    def test_high_status(self):
        self.assertEqual(determine_status("HIGH"), "Possible brute-force attack detected")

class TestLogParser(unittest.TestCase):

    def setUp(self):
        self.log_file = Path("logs/sample_auth.log")

    def test_failed_login_counts(self):
        results = parse_log_file(self.log_file)

        self.assertEqual(results["192.168.1.50"]["attempts"], 4)

        self.assertEqual(results["192.168.1.60"]["attempts"], 2)

        self.assertEqual(results["192.168.1.75"]["attempts"], 5)

    def test_usernames(self):
        results = parse_log_file(self.log_file)

        self.assertEqual(results["192.168.1.50"]["username"], "admin")

        self.assertEqual(results["192.168.1.60"]["username"], "john")

        self.assertEqual(results["192.168.1.75"]["username"], "admin")

    def test_first_and_last_attempts(self):
        results = parse_log_file(self.log_file)

        self.assertEqual(results["192.168.1.50"]["first_attempt"], "2026-08-08 08:22:11")

        self.assertEqual(results["192.168.1.50"]["last_attempt"], "2026-08-08 08:22:24")

    def test_missing_log_file(self):
        missing_file = Path("logs/does_not_exist.log")

        with self.assertRaises(FileNotFoundError):
            parse_log_file(missing_file)

    def test_malformed_log_entry_is_skipped(self):
        test_file = Path("logs/test_malformed.log")

        test_file.write_text("2026-08-08 08:22:11 WARNING Failed login - User: admin\n""2026-08-08 08:22:15 WARNING Failed login - User: admin - IP: 192.168.1.80\n", encoding="utf-8")

        try:
            results = parse_log_file(test_file)

            self.assertEqual(len(results), 1)

            self.assertEqual(results["192.168.1.80"]["attempts"], 1)

        finally:
            test_file.unlink()
if __name__ == "__main__":
    unittest.main()
