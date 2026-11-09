import json
import unittest

from detector.models import AuditEvent, Finding, LLMAnalysis, WindowEvidence


class AuditEventTests(unittest.TestCase):
    def test_from_dict_normalizes_nested_audit_fields(self):
        event = AuditEvent.from_dict(
            {
                "requestReceivedTimestamp": "2026-10-20T01:00:00Z",
                "user": {"username": "system:serviceaccount:pbl-security:app"},
                "sourceIPs": ["10.0.0.7"],
                "userAgent": "kubectl/test",
                "verb": "list",
                "objectRef": {
                    "resource": "pods",
                    "namespace": "pbl-security",
                    "apiVersion": "v1",
                },
                "responseStatus": {"code": 200},
                "auditID": "audit-123",
            },
            line_number=4,
        )

        self.assertEqual(event.timestamp, "2026-10-20T01:00:00Z")
        self.assertEqual(event.subject, "system:serviceaccount:pbl-security:app")
        self.assertEqual(event.source_ip, "10.0.0.7")
        self.assertEqual(event.resource, "pods")
        self.assertEqual(event.response_code, 200)
        self.assertEqual(event.audit_id, "audit-123")
        self.assertEqual(event.subresource, "unknown")
        self.assertEqual(event.line_number, 4)

    def test_from_dict_converts_wrong_scalar_types_to_unknown(self):
        event = AuditEvent.from_dict(
            {
                "userAgent": 4,
                "sourceIPs": [3],
                "verb": ["list"],
                "objectRef": {"resource": [], "namespace": 7},
                "responseStatus": {"code": None},
            }
        )

        self.assertEqual(event.user_agent, "unknown")
        self.assertEqual(event.source_ip, "unknown")
        self.assertEqual(event.verb, "unknown")
        self.assertEqual(event.resource, "unknown")
        self.assertEqual(event.namespace, "unknown")
        self.assertEqual(event.response_code, "unknown")


class FindingSerializationTests(unittest.TestCase):
    def test_finding_serializes_to_json_compatible_dictionary(self):
        finding = Finding(
            classification="attack",
            risk_score=85,
            severity="high",
            rule_ids=["sensitive_secret_access"],
            subject="system:serviceaccount:pbl-security:app",
            source_ip="10.0.0.7",
            window_start="2026-10-20T01:00:00Z",
            window_end="2026-10-20T01:05:00Z",
            evidence=[{"field": "objectRef.resource", "value": "secrets"}],
            event_count=1,
            thresholds={"attack_score": 60},
            llm=LLMAnalysis(
                status="mock",
                classification="attack",
                confidence=0.9,
                evidence=["sensitive_secret_access"],
                attack_hypothesis="secret enumeration",
                normal_explanation="",
                false_positive_conditions="operator break-glass",
                recommended_action="alert_only",
            ),
        )

        encoded = json.dumps(finding.to_dict(), ensure_ascii=False)
        decoded = json.loads(encoded)
        self.assertEqual(decoded["classification"], "attack")
        self.assertEqual(decoded["rule_classification"], "attack")
        self.assertEqual(decoded["llm_enriched_classification"], "attack")
        self.assertEqual(decoded["llm"]["status"], "mock")


class WindowEvidenceTests(unittest.TestCase):
    def test_window_evidence_has_stable_group_key(self):
        window = WindowEvidence(
            subject="system:serviceaccount:pbl-security:app",
            source_ip="10.0.0.7",
            start="2026-10-20T01:00:00Z",
            end="2026-10-20T01:05:00Z",
            events=[],
        )
        self.assertEqual(window.group_key, "system:serviceaccount:pbl-security:app|10.0.0.7")


if __name__ == "__main__":
    unittest.main()
