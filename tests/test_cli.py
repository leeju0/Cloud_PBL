import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from detector.evaluate import evaluate_event_findings, evaluate_findings, evaluate_scenario
from detector.models import Finding


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = ROOT / "tests" / "fixtures"


class CliTests(unittest.TestCase):
    def run_cli(self, input_path, label):
        output_dir = Path(tempfile.mkdtemp(prefix="pbl-detector-"))
        command = [
            sys.executable,
            "-m",
            "detector.cli",
            "--input",
            str(input_path),
            "--output-dir",
            str(output_dir),
            "--llm",
            "mock",
            "--label",
            label,
        ]
        result = subprocess.run(command, cwd=ROOT, capture_output=True, text=True)
        self.assertEqual(result.returncode, 0, result.stderr)
        return output_dir

    def test_normal_input_emits_explainable_report_and_tn_metric(self):
        output_dir = self.run_cli(FIXTURES / "audit_normal.jsonl", "normal")

        finding = json.loads((output_dir / "findings.jsonl").read_text().strip())
        metrics = json.loads((output_dir / "metrics.json").read_text())
        report = (output_dir / "report.md").read_text()

        self.assertEqual(finding["classification"], "normal")
        self.assertEqual(finding["llm"]["status"], "skipped")
        self.assertEqual(metrics["tn"], 1)
        self.assertIn("정상 행위와 공격 행위를 구분한 근거", report)
        self.assertIn("오탐", report)
        self.assertIn("미탐", report)
        self.assertIn("한계", report)

    def test_abnormal_input_emits_attack_and_tp_metric(self):
        output_dir = self.run_cli(FIXTURES / "audit_abnormal.jsonl", "attack")

        metrics = json.loads((output_dir / "metrics.json").read_text())
        finding = json.loads((output_dir / "findings.jsonl").read_text().strip())

        self.assertEqual(finding["classification"], "attack")
        self.assertEqual(finding["rule_classification"], "attack")
        self.assertEqual(finding["llm_enriched_classification"], "attack")
        self.assertGreaterEqual(metrics["tp"], 1)
        self.assertEqual(metrics["recall"], 1.0)

    def test_abnormal_filename_defaults_to_attack_label(self):
        output_dir = Path(tempfile.mkdtemp(prefix="pbl-detector-label-"))
        result = subprocess.run(
            [
                sys.executable,
                "-m",
                "detector.cli",
                "--input",
                str(FIXTURES / "audit_abnormal.jsonl"),
                "--output-dir",
                str(output_dir),
                "--llm",
                "mock",
            ],
            cwd=ROOT,
            capture_output=True,
            text=True,
        )
        self.assertEqual(result.returncode, 0, result.stderr)
        metrics = json.loads((output_dir / "metrics.json").read_text())
        self.assertEqual(metrics["tp"], 1)

    def test_empty_input_still_emits_zero_metrics(self):
        with tempfile.NamedTemporaryFile("w", suffix=".jsonl") as handle:
            output_dir = self.run_cli(handle.name, "attack")

        metrics = json.loads((output_dir / "metrics.json").read_text())
        self.assertEqual(metrics["total"], 0)
        self.assertEqual(metrics["precision"], 0.0)


class EvaluationTests(unittest.TestCase):
    def test_metrics_count_false_positive_and_false_negative(self):
        findings = [
            Finding("attack", 80, "high", [], "u", "ip", "s", "e", [], 1, {}),
            Finding("normal", 0, "info", [], "u", "ip", "s", "e", [], 1, {}),
        ]

        metrics = evaluate_findings(findings, ["normal", "attack"])

        self.assertEqual(metrics.fp, 1)
        self.assertEqual(metrics.fn, 1)
        self.assertEqual(metrics.precision, 0.0)
        self.assertEqual(metrics.recall, 0.0)

    def test_event_and_scenario_metrics_are_distinct(self):
        findings = [
            Finding("attack", 80, "high", [], "u", "ip", "s", "e", [], 3, {}),
        ]

        event_metrics = evaluate_event_findings(findings, ["attack"])
        scenario = evaluate_scenario(findings, "attack")

        self.assertEqual(event_metrics.total, 3)
        self.assertTrue(scenario["detected"])
        self.assertEqual(scenario["rule_only_classification"], "attack")


if __name__ == "__main__":
    unittest.main()
