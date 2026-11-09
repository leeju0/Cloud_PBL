import json
import os
import unittest
from unittest.mock import patch

from detector.llm import LLMConfig, MockLLM, analyze_finding
from detector.models import Finding


def finding():
    return Finding(
        classification="attack",
        risk_score=85,
        severity="high",
        rule_ids=["sensitive_secret_access"],
        subject="system:serviceaccount:pbl-security:pbl-crypto-platform-app",
        source_ip="172.18.0.1",
        window_start="2026-10-20T01:00:00Z",
        window_end="2026-10-20T01:00:01Z",
        evidence=[
            {"rule_id": "sensitive_secret_access", "fields": {"resource": "secrets"}},
            {"fields": {"token": "do-not-send"}},
        ],
        event_count=1,
        thresholds={"attack_threshold": 60},
    )


class FakeResponse:
    def __init__(self, body):
        self.body = json.dumps(body).encode("utf-8")

    def __enter__(self):
        return self

    def __exit__(self, *_):
        return False

    def read(self):
        return self.body


class LLMTests(unittest.TestCase):
    def test_config_uses_local_gemma_and_gpu_two_defaults(self):
        with patch.dict(os.environ, {}, clear=True):
            config = LLMConfig.from_env()

        self.assertEqual(config.model_path, "/data/LLM_model/gemma4/gemma-4-12b-it-IQ4_NL.gguf")
        self.assertEqual(config.device, "2")
        self.assertEqual(config.endpoint, "http://127.0.0.1:8080/v1/chat/completions")

    def test_mock_preserves_rule_classification(self):
        analysis = MockLLM().analyze(finding())

        self.assertEqual(analysis.status, "mock")
        self.assertEqual(analysis.classification, "attack")
        self.assertIn("sensitive_secret_access", analysis.evidence)

    def test_mock_describes_suspicious_windows_as_attack_signals(self):
        suspicious = finding()
        suspicious.classification = "suspicious"

        analysis = MockLLM().analyze(suspicious)

        self.assertIn("민감 API", analysis.attack_hypothesis)
        self.assertEqual(analysis.normal_explanation, "")

    def test_normal_finding_skips_local_llm(self):
        normal = finding()
        normal.classification = "normal"
        config = LLMConfig(mode="local")
        with patch("detector.llm.urllib.request.urlopen", side_effect=AssertionError("must skip")):
            analysis = analyze_finding(normal, config)

        self.assertEqual(analysis.status, "skipped")
        self.assertEqual(analysis.classification, "normal")

    def test_local_adapter_sends_redacted_structured_payload(self):
        response = {
            "choices": [{"message": {"content": "```json\n{\"classification\": \"attack\", \"confidence\": 0.9, \"evidence\": [\"sensitive_secret_access\"], \"attack_hypothesis\": \"secret access\", \"normal_explanation\": \"\", \"false_positive_conditions\": \"break-glass\"}\n```"}}]
        }
        captured = {}

        def fake_urlopen(request, timeout):
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(response)

        config = LLMConfig(mode="local", endpoint="http://llm.test/v1/chat/completions")
        with patch("detector.llm.urllib.request.urlopen", side_effect=fake_urlopen):
            analysis = analyze_finding(finding(), config)

        self.assertEqual(analysis.status, "available")
        self.assertEqual(analysis.classification, "attack")
        self.assertNotIn("do-not-send", json.dumps(captured["payload"]))
        self.assertEqual(captured["payload"]["temperature"], 0)

    def test_local_adapter_accepts_gemma_channel_prefix_and_sends_schema(self):
        response = {
            "choices": [{
                "message": {
                    "content": (
                        "<|channel>thought\n<channel|>```json\n"
                        '{"classification":"suspicious","confidence":0.85,'
                        '"evidence":["pod_exec_attempt"],"attack_hypothesis":"exec",'
                        '"normal_explanation":"","false_positive_conditions":"break-glass",'
                        '"recommended_action":"alert_only"}\n```'
                    )
                }
            }]
        }
        captured = {}

        def fake_urlopen(request, timeout):
            captured["payload"] = json.loads(request.data.decode("utf-8"))
            return FakeResponse(response)

        config = LLMConfig(mode="local", endpoint="http://llm.test/v1/chat/completions")
        with patch("detector.llm.urllib.request.urlopen", side_effect=fake_urlopen):
            analysis = analyze_finding(finding(), config)

        self.assertEqual(analysis.status, "available")
        self.assertEqual(analysis.classification, "suspicious")
        self.assertEqual(captured["payload"]["response_format"]["type"], "json_schema")

    def test_invalid_json_and_http_failure_fall_back_without_changing_rule(self):
        invalid = {"choices": [{"message": {"content": "not json"}}]}
        config = LLMConfig(mode="local")
        with patch("detector.llm.urllib.request.urlopen", return_value=FakeResponse(invalid)):
            invalid_result = analyze_finding(finding(), config)
        with patch("detector.llm.urllib.request.urlopen", side_effect=OSError("offline")):
            failed_result = analyze_finding(finding(), config)

        self.assertEqual(invalid_result.status, "unavailable")
        self.assertEqual(invalid_result.classification, "attack")
        self.assertEqual(failed_result.status, "unavailable")
        self.assertEqual(failed_result.classification, "attack")

    def test_empty_or_low_confidence_model_output_falls_back(self):
        config = LLMConfig(mode="local")
        empty_choices = {"choices": []}
        low_confidence = {
            "choices": [{"message": {"content": '{"classification":"attack","confidence":0.01}'}}]
        }
        with patch("detector.llm.urllib.request.urlopen", return_value=FakeResponse(empty_choices)):
            empty_result = analyze_finding(finding(), config)
        with patch("detector.llm.urllib.request.urlopen", return_value=FakeResponse(low_confidence)):
            low_result = analyze_finding(finding(), config)

        self.assertEqual(empty_result.status, "unavailable")
        self.assertEqual(low_result.status, "unavailable")


if __name__ == "__main__":
    unittest.main()
