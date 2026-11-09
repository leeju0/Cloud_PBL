import json
import unittest

from detector.models import AuditEvent
from detector.rules import RuleConfig, build_windows, detect_events


def event(
    *,
    timestamp="2026-10-20T01:00:00Z",
    resource="pods",
    verb="list",
    code=200,
    subresource=None,
    source_ip="172.18.0.1",
):
    object_ref = {"resource": resource, "namespace": "pbl-security"}
    if subresource:
        object_ref["subresource"] = subresource
    raw = {
        "requestReceivedTimestamp": timestamp,
        "user": {"username": "system:serviceaccount:pbl-security:pbl-crypto-platform-app"},
        "sourceIPs": [source_ip],
        "userAgent": "kubectl/test",
        "verb": verb,
        "objectRef": object_ref,
        "responseStatus": {"code": code},
        "auditID": f"{resource}-{timestamp}-{code}",
    }
    return AuditEvent.from_dict(raw)


class RuleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.config = RuleConfig.from_file("detector/config.json")

    def test_allowed_read_is_normal(self):
        findings = detect_events([event()], self.config)

        self.assertEqual(findings[0].classification, "normal")
        self.assertIn("allowed_read", findings[0].rule_ids)
        self.assertEqual(findings[0].risk_score, 0)

    def test_secret_403_is_high_risk_with_distinct_rules(self):
        finding = detect_events(
            [event(resource="secrets", verb="list", code=403)], self.config
        )[0]

        self.assertEqual(finding.classification, "attack")
        self.assertIn("sensitive_secret_access", finding.rule_ids)
        self.assertIn("forbidden_sensitive_request", finding.rule_ids)
        self.assertGreaterEqual(finding.risk_score, 60)

    def test_pod_exec_attempt_has_its_own_evidence(self):
        finding = detect_events(
            [event(resource="pods", subresource="exec", verb="create", code=403)],
            self.config,
        )[0]

        self.assertIn("pod_exec_attempt", finding.rule_ids)
        self.assertTrue(any(item["rule_id"] == "pod_exec_attempt" for item in finding.evidence))

    def test_burst_requires_both_request_and_resource_thresholds(self):
        below_threshold = [
            event(timestamp=f"2026-10-20T01:00:0{i}Z", resource="pods")
            for i in range(4)
        ]
        above_threshold = below_threshold + [
            event(timestamp="2026-10-20T01:00:04Z", resource="services")
            for _ in range(4)
        ] + [event(timestamp="2026-10-20T01:00:05Z", resource="configmaps")]

        self.assertNotIn("enumeration_burst", detect_events(below_threshold, self.config)[0].rule_ids)
        self.assertIn("enumeration_burst", detect_events(above_threshold, self.config)[0].rule_ids)

    def test_events_are_grouped_into_five_minute_windows(self):
        events = [event(timestamp="2026-10-20T01:00:00Z"), event(timestamp="2026-10-20T01:06:00Z")]

        windows = build_windows(events, self.config)

        self.assertEqual(len(windows), 2)

    def test_incomplete_event_is_unknown_not_normal(self):
        incomplete = event()
        incomplete = AuditEvent(
            **{**incomplete.__dict__, "parse_errors": ("response_code",)}
        )

        finding = detect_events([incomplete], self.config)[0]

        self.assertEqual(finding.classification, "unknown")


if __name__ == "__main__":
    unittest.main()
