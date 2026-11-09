from __future__ import annotations

from dataclasses import asdict, dataclass
from typing import Iterable

from .models import Finding


@dataclass(frozen=True)
class Metrics:
    total: int
    tp: int
    tn: int
    fp: int
    fn: int
    precision: float
    recall: float
    f1: float

    def to_dict(self) -> dict[str, int | float]:
        return asdict(self)


def evaluate_findings(findings: Iterable[Finding], labels: Iterable[str]) -> Metrics:
    finding_list = list(findings)
    label_list = list(labels)
    if len(finding_list) != len(label_list):
        raise ValueError("one ground-truth label is required for each finding")
    tp = tn = fp = fn = 0
    for finding, label in zip(finding_list, label_list):
        predicted_attack = finding.classification in {"attack", "suspicious"}
        actual_attack = label in {"attack", "suspicious"}
        if predicted_attack and actual_attack:
            tp += 1
        elif not predicted_attack and not actual_attack:
            tn += 1
        elif predicted_attack:
            fp += 1
        else:
            fn += 1
    precision = tp / (tp + fp) if tp + fp else 0.0
    recall = tp / (tp + fn) if tp + fn else 0.0
    f1 = 2 * precision * recall / (precision + recall) if precision + recall else 0.0
    return Metrics(len(finding_list), tp, tn, fp, fn, precision, recall, f1)


def evaluate_event_findings(findings: Iterable[Finding], labels: Iterable[str]) -> Metrics:
    expanded_findings: list[Finding] = []
    expanded_labels: list[str] = []
    for finding, label in zip(findings, labels):
        count = max(0, finding.event_count)
        expanded_findings.extend([finding] * count)
        expanded_labels.extend([label] * count)
    return evaluate_findings(expanded_findings, expanded_labels)


def evaluate_scenario(findings: Iterable[Finding], label: str) -> dict[str, str | bool]:
    finding_list = list(findings)
    rule_detected = any(item.classification in {"attack", "suspicious"} for item in finding_list)
    enriched = [item.llm.classification for item in finding_list if item.llm is not None]
    enriched_detected = any(item in {"attack", "suspicious"} for item in enriched)
    return {
        "expected": label,
        "detected": rule_detected,
        "rule_only_classification": "attack" if rule_detected else "normal",
        "llm_enriched_classification": "attack" if enriched_detected else "normal",
    }
