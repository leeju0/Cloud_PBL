from __future__ import annotations

from typing import Any

from .evaluate import Metrics
from .models import Finding
from .parser import ParseStats


def render_markdown(
    findings: list[Finding],
    metrics: Metrics,
    parse_stats: ParseStats,
    event_metrics: Metrics | None = None,
    scenario: dict[str, Any] | None = None,
    llm_consistency: dict[str, Any] | None = None,
) -> str:
    lines = [
        "# API/Credential 악용 탐지 결과",
        "",
        "## 요약",
        "",
        f"- 전체 탐지 창: {metrics.total}",
        f"- TP/TN/FP/FN: {metrics.tp}/{metrics.tn}/{metrics.fp}/{metrics.fn}",
        f"- Precision/Recall/F1: {metrics.precision:.3f}/{metrics.recall:.3f}/{metrics.f1:.3f}",
        f"- 이벤트 단위 TP/TN/FP/FN: {event_metrics.tp}/{event_metrics.tn}/{event_metrics.fp}/{event_metrics.fn}" if event_metrics else "",
        f"- 시나리오 판정: {scenario}" if scenario else "",
        f"- LLM 반복 일관성: {llm_consistency}" if llm_consistency else "",
        f"- 파싱: 전체 {parse_stats.total_lines}, 성공 {parse_stats.parsed_events}, "
        f"오류 {parse_stats.malformed_lines}, 불완전 {parse_stats.incomplete_events}",
        "",
        "## 탐지 결과와 정상 행위와 공격 행위를 구분한 근거",
        "",
    ]
    if not findings:
        lines.append("입력 로그에서 분석할 이벤트가 없습니다.")
    for index, finding in enumerate(findings, start=1):
        lines.extend(
            [
                f"### {index}. {finding.classification.upper()} (risk={finding.risk_score})",
                "",
                f"- 주체: `{finding.subject}`",
                f"- source IP: `{finding.source_ip}`",
                f"- 규칙: `{', '.join(finding.rule_ids) or 'none'}`",
                f"- 시간창: `{finding.window_start}` ~ `{finding.window_end}`",
                "- 판정 근거:",
            ]
        )
        if finding.evidence:
            lines.extend(f"  - `{item.get('rule_id', 'unknown')}`: {item.get('reason', '')} — `{item.get('fields', {})}`" for item in finding.evidence)
        else:
            lines.append("  - 관찰된 고위험 규칙이 없어 정상 기준선으로 분류했습니다.")
        if finding.llm is not None:
            lines.extend(
                [
                    f"- LLM 상태: `{finding.llm.status}`, 분류 `{finding.llm.classification}`, 신뢰도 `{finding.llm.confidence:.2f}`",
                    f"- LLM 설명: {finding.llm.attack_hypothesis or finding.llm.normal_explanation or '없음'}",
                    f"- 오탐 가능성: {finding.llm.false_positive_conditions or '없음'}",
                ]
            )
        lines.append("")
    lines.extend(
        [
            "## 오탐 분석",
            "",
            "합법적인 운영자의 Secret 조회·`pods/exec`, CI/CD의 반복 API 호출, NAT/프록시 IP 변화, 재시도에 따른 403 증가가 오탐을 만들 수 있습니다. 운영 환경에서는 허가된 주체·시간대 allowlist를 별도로 검증해야 합니다.",
            "",
            "## 미탐 분석",
            "",
            "탈취 자격증명이 정상 IP·User-Agent와 정상 속도로 사용되거나, 허용된 API만 이용한 저강도 정찰은 미탐될 수 있습니다. 감사 정책의 필드 누락·파싱 오류·시간 동기화 문제도 미탐 요인입니다.",
            "",
            "## 한계",
            "",
            "본 결과는 단일 namespace와 제한된 ServiceAccount를 사용하는 소규모 테스트베드의 위험 신호입니다. Audit Log만으로 공격 의도를 확정할 수 없고, 임계값은 운영 환경에 일반화되지 않습니다. LLM은 규칙 결과를 보조할 뿐 차단이나 증거 수집을 수행하지 않습니다.",
        ]
    )
    return "\n".join(lines) + "\n"
