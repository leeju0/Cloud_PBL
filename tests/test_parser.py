import json
import unittest

from detector.parser import parse_audit_jsonl


def audit_line(**overrides):
    event = {
        "requestReceivedTimestamp": "2026-10-20T01:00:00Z",
        "user": {"username": "system:serviceaccount:pbl-security:app"},
        "sourceIPs": ["10.0.0.7"],
        "verb": "list",
        "objectRef": {"resource": "pods", "namespace": "pbl-security"},
        "responseStatus": {"code": 200},
        "auditID": "audit-1",
    }
    event.update(overrides)
    return json.dumps(event)


class ParserTests(unittest.TestCase):
    def test_parses_valid_lines_and_counts_malformed_lines(self):
        events, stats = parse_audit_jsonl(
            [audit_line(), "not-json", audit_line(auditID="audit-2")]
        )

        self.assertEqual(len(events), 2)
        self.assertEqual(stats.total_lines, 3)
        self.assertEqual(stats.parsed_events, 2)
        self.assertEqual(stats.malformed_lines, 1)
        self.assertEqual(events[1].line_number, 3)

    def test_counts_incomplete_events_without_dropping_them(self):
        events, stats = parse_audit_jsonl([audit_line(responseStatus={})])

        self.assertEqual(len(events), 1)
        self.assertIn("response_code", events[0].parse_errors)
        self.assertEqual(stats.incomplete_events, 1)


if __name__ == "__main__":
    unittest.main()
