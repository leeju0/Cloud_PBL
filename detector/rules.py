from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from .models import AuditEvent, Finding, WindowEvidence


def _timestamp(value: str) -> datetime:
    if value == "unknown":
        return datetime.min.replace(tzinfo=timezone.utc)
    normalized = value.replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        return datetime.min.replace(tzinfo=timezone.utc)
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=timezone.utc)


@dataclass(frozen=True)
class RuleConfig:
    namespace: str
    service_account: str
    allowed_resources: tuple[str, ...]
    allowed_verbs: tuple[str, ...]
    sensitive_resources: tuple[str, ...]
    window_seconds: int = 300
    burst_request_threshold: int = 8
    burst_resource_threshold: int = 3
    attack_threshold: int = 60
    suspicious_threshold: int = 30
    weights: dict[str, int] = field(default_factory=dict)
    baseline_source_ips: tuple[str, ...] = ()
    baseline_user_agent_prefixes: tuple[str, ...] = ()

    @classmethod
    def from_file(cls, path: str | None = None) -> "RuleConfig":
        config_path = Path(path) if path else Path(__file__).with_name("config.json")
        data = json.loads(config_path.read_text(encoding="utf-8"))
        return cls(
            namespace=data["namespace"],
            service_account=data["service_account"],
            allowed_resources=tuple(data["allowed_resources"]),
            allowed_verbs=tuple(data["allowed_verbs"]),
            sensitive_resources=tuple(data["sensitive_resources"]),
            window_seconds=int(data.get("window_seconds", 300)),
            burst_request_threshold=int(data.get("burst_request_threshold", 8)),
            burst_resource_threshold=int(data.get("burst_resource_threshold", 3)),
            attack_threshold=int(data.get("attack_threshold", 60)),
            suspicious_threshold=int(data.get("suspicious_threshold", 30)),
            weights={key: int(value) for key, value in data.get("weights", {}).items()},
            baseline_source_ips=tuple(data.get("baseline_source_ips", [])),
            baseline_user_agent_prefixes=tuple(data.get("baseline_user_agent_prefixes", [])),
        )


def _allowed(event: AuditEvent, config: RuleConfig) -> bool:
    return (
        event.subject == config.service_account
        and event.namespace == config.namespace
        and event.resource in config.allowed_resources
        and event.verb in config.allowed_verbs
        and event.response_code == 200
        and event.subresource == "unknown"
    )


def _evidence(rule_id: str, event: AuditEvent, reason: str, **fields: Any) -> dict[str, Any]:
    return {
        "rule_id": rule_id,
        "reason": reason,
        "line_number": event.line_number,
        "audit_id": event.audit_id,
        "fields": fields,
    }


def build_windows(events: list[AuditEvent], config: RuleConfig) -> list[WindowEvidence]:
    grouped: dict[str, list[AuditEvent]] = {}
    for event in sorted(events, key=lambda item: _timestamp(item.timestamp)):
        grouped.setdefault(f"{event.subject}|{event.source_ip}", []).append(event)

    windows: list[WindowEvidence] = []
    for group_events in grouped.values():
        current: list[AuditEvent] = []
        start_time: datetime | None = None
        for event in group_events:
            event_time = _timestamp(event.timestamp)
            if current and start_time is not None and (event_time - start_time).total_seconds() > config.window_seconds:
                windows.append(_window(current))
                current = []
                start_time = None
            if not current:
                start_time = event_time
            current.append(event)
        if current:
            windows.append(_window(current))
    return sorted(windows, key=lambda window: _timestamp(window.start))


def _window(events: list[AuditEvent]) -> WindowEvidence:
    return WindowEvidence(
        subject=events[0].subject,
        source_ip=events[0].source_ip,
        start=events[0].timestamp,
        end=events[-1].timestamp,
        events=list(events),
    )


def score_window(window: WindowEvidence, config: RuleConfig) -> Finding:
    rule_ids: list[str] = []
    evidence: list[dict[str, Any]] = []
    score = 0

    def add_rule(rule_id: str) -> None:
        nonlocal score
        if rule_id not in rule_ids:
            rule_ids.append(rule_id)
            score += config.weights.get(rule_id, 0)

    for event in window.events:
        if _allowed(event, config):
            if "allowed_read" not in rule_ids:
                rule_ids.append("allowed_read")
            evidence.append(
                _evidence(
                    "allowed_read",
                    event,
                    "허용된 리소스의 성공적인 읽기 요청",
                    resource=event.resource,
                    verb=event.verb,
                    response_code=event.response_code,
                )
            )
        if event.resource in config.sensitive_resources and event.verb in {"get", "list"}:
            add_rule("sensitive_secret_access")
            evidence.append(
                _evidence(
                    "sensitive_secret_access",
                    event,
                    "민감 리소스 접근 시도",
                    resource=event.resource,
                    verb=event.verb,
                    response_code=event.response_code,
                )
            )
        if event.resource == "pods" and event.subresource == "exec" and event.verb == "create":
            add_rule("pod_exec_attempt")
            evidence.append(
                _evidence(
                    "pod_exec_attempt",
                    event,
                    "Pod 실행 subresource 호출",
                    resource=event.resource,
                    subresource=event.subresource,
                    verb=event.verb,
                    response_code=event.response_code,
                )
            )
        if (
            event.response_code == 403
            and (event.resource in config.sensitive_resources or event.subresource == "exec")
        ):
            add_rule("forbidden_sensitive_request")
            evidence.append(
                _evidence(
                    "forbidden_sensitive_request",
                    event,
                    "민감 요청이 RBAC에 의해 거부됨",
                    resource=event.resource,
                    subresource=event.subresource,
                    response_code=event.response_code,
                )
            )

    distinct_resources = {event.resource for event in window.events if event.resource != "unknown"}
    if (
        len(window.events) >= config.burst_request_threshold
        and len(distinct_resources) >= config.burst_resource_threshold
    ):
        add_rule("enumeration_burst")
        evidence.append(
            {
                "rule_id": "enumeration_burst",
                "reason": "짧은 시간에 여러 리소스를 반복 조회",
                "fields": {
                    "request_count": len(window.events),
                    "distinct_resources": sorted(distinct_resources),
                    "request_threshold": config.burst_request_threshold,
                    "resource_threshold": config.burst_resource_threshold,
                },
            }
        )

    if config.baseline_source_ips and window.source_ip not in config.baseline_source_ips:
        add_rule("identity_anomaly")
        evidence.append(
            {
                "rule_id": "identity_anomaly",
                "reason": "기준선에 없는 source IP",
                "fields": {"source_ip": window.source_ip, "baseline_source_ips": list(config.baseline_source_ips)},
            }
        )
    if config.baseline_user_agent_prefixes and any(
        not any(event.user_agent.startswith(prefix) for prefix in config.baseline_user_agent_prefixes)
        for event in window.events
    ):
        add_rule("identity_anomaly")
        evidence.append(
            {
                "rule_id": "identity_anomaly",
                "reason": "기준선에 없는 User-Agent",
                "fields": {"user_agents": sorted({event.user_agent for event in window.events})},
            }
        )

    has_incomplete_event = any(event.parse_errors for event in window.events)
    if has_incomplete_event:
        if "incomplete_event" not in rule_ids:
            rule_ids.append("incomplete_event")
        evidence.extend(
            {
                "rule_id": "incomplete_event",
                "reason": "판정에 필요한 감사 필드가 없거나 잘못된 형식임",
                "fields": {"parse_errors": list(event.parse_errors)},
            }
            for event in window.events
            if event.parse_errors
        )

    if score >= config.attack_threshold:
        classification, severity = "attack", "high"
    elif score >= config.suspicious_threshold:
        classification, severity = "suspicious", "medium"
    elif has_incomplete_event:
        classification, severity = "unknown", "medium"
    else:
        classification, severity = "normal", "info"

    return Finding(
        classification=classification,
        risk_score=score,
        severity=severity,
        rule_ids=rule_ids,
        subject=window.subject,
        source_ip=window.source_ip,
        window_start=window.start,
        window_end=window.end,
        evidence=evidence,
        event_count=len(window.events),
        thresholds={
            "window_seconds": config.window_seconds,
            "burst_request_threshold": config.burst_request_threshold,
            "burst_resource_threshold": config.burst_resource_threshold,
            "suspicious_threshold": config.suspicious_threshold,
            "attack_threshold": config.attack_threshold,
            "weights": dict(config.weights),
        },
    )


def detect_events(events: list[AuditEvent], config: RuleConfig) -> list[Finding]:
    return [score_window(window, config) for window in build_windows(events, config)]
