from __future__ import annotations

import argparse
import json
from dataclasses import replace
from pathlib import Path

from .evaluate import evaluate_event_findings, evaluate_findings, evaluate_scenario
from .llm import LLMConfig, analyze_finding
from .parser import parse_audit_jsonl
from .report import render_markdown
from .rules import RuleConfig, detect_events


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Detect Kubernetes API/Credential abuse from Audit JSONL")
    parser.add_argument("--input", required=True, help="Audit Log JSONL path")
    parser.add_argument("--output-dir", required=True, help="Directory for findings and report")
    parser.add_argument("--llm", choices=("mock", "local"), default="mock")
    parser.add_argument("--llm-repeats", type=int, default=1)
    parser.add_argument("--label", choices=("normal", "attack"), default=None)
    parser.add_argument("--config", default=None, help="Rule configuration JSON path")
    return parser


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    input_path = Path(args.input)
    output_dir = Path(args.output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)
    label = args.label
    if label is None:
        exact_name = input_path.name.lower()
        if exact_name == "normal.log" or exact_name == "audit_normal.jsonl":
            label = "normal"
        elif exact_name in {"abnormal_1.log", "abnormal_2.log", "abnormal_3.log", "audit_abnormal.jsonl"}:
            label = "attack"
        else:
            _parser().error("--label is required for unknown input filenames")

    events, parse_stats = parse_audit_jsonl(input_path)
    rule_config = RuleConfig.from_file(args.config)
    findings = detect_events(events, rule_config)
    llm_config = replace(LLMConfig.from_env(), mode=args.llm)
    llm_classifications: list[str] = []
    for finding in findings:
        repeats = max(1, args.llm_repeats) if finding.classification in {"attack", "suspicious"} else 1
        analyses = [analyze_finding(finding, llm_config) for _ in range(repeats)]
        finding.llm = analyses[0]
        llm_classifications.extend(
            analysis.classification for analysis in analyses if analysis.status in {"available", "mock"}
        )
    labels = [label] * len(findings)
    metrics = evaluate_findings(findings, labels)
    event_metrics = evaluate_event_findings(findings, labels)
    scenario = evaluate_scenario(findings, label)
    consistency = {
        "runs": len(llm_classifications),
        "consistent": len(set(llm_classifications)) <= 1,
    }

    with (output_dir / "findings.jsonl").open("w", encoding="utf-8") as handle:
        for finding in findings:
            handle.write(json.dumps(finding.to_dict(), ensure_ascii=False) + "\n")
    metrics_payload = metrics.to_dict()
    metrics_payload.update(
        {
            "window_metrics": metrics.to_dict(),
            "event_metrics": event_metrics.to_dict(),
            "scenario": scenario,
            "llm_consistency": consistency,
        }
    )
    (output_dir / "metrics.json").write_text(
        json.dumps(metrics_payload, ensure_ascii=False, indent=2) + "\n", encoding="utf-8"
    )
    (output_dir / "report.md").write_text(
        render_markdown(findings, metrics, parse_stats, event_metrics, scenario, consistency), encoding="utf-8"
    )
    print(f"findings={len(findings)} output={output_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
