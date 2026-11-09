from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


UNKNOWN = "unknown"


def _nested(mapping: dict[str, Any], *keys: str, default: Any = UNKNOWN) -> Any:
    value: Any = mapping
    for key in keys:
        if not isinstance(value, dict) or key not in value:
            return default
        value = value[key]
    return value if value not in (None, "") else default


def _text(value: Any) -> str:
    return value if isinstance(value, str) and value else UNKNOWN


def _status_code(value: Any) -> int | str:
    if isinstance(value, int) and not isinstance(value, bool):
        return value
    if isinstance(value, str) and value.isdigit():
        return int(value)
    return UNKNOWN


@dataclass(frozen=True)
class AuditEvent:
    timestamp: str
    subject: str
    source_ip: str
    user_agent: str
    verb: str
    api_group: str
    resource: str
    subresource: str
    namespace: str
    name: str
    response_code: int | str
    stage: str
    audit_id: str
    line_number: int = 0
    parse_errors: tuple[str, ...] = ()

    @classmethod
    def from_dict(cls, raw: dict[str, Any], line_number: int = 0) -> "AuditEvent":
        source_ips = raw.get("sourceIPs", [])
        source_ip = _text(source_ips[0]) if isinstance(source_ips, list) and source_ips else UNKNOWN
        object_ref = raw.get("objectRef") if isinstance(raw.get("objectRef"), dict) else {}
        response_status = raw.get("responseStatus") if isinstance(raw.get("responseStatus"), dict) else {}
        timestamp = _text(_nested(raw, "requestReceivedTimestamp", default=UNKNOWN))
        if timestamp == UNKNOWN:
            timestamp = _text(_nested(raw, "stageTimestamp", default=UNKNOWN))
        subject = _text(_nested(raw, "user", "username", default=UNKNOWN))
        user_agent = _text(raw.get("userAgent"))
        verb = _text(raw.get("verb"))
        api_group = _text(object_ref.get("apiGroup"))
        resource = _text(object_ref.get("resource"))
        subresource = _text(object_ref.get("subresource"))
        namespace = _text(object_ref.get("namespace"))
        name = _text(object_ref.get("name"))
        response_code = _status_code(response_status.get("code"))
        stage = _text(raw.get("stage"))
        audit_id = _text(raw.get("auditID"))
        errors: list[str] = []
        required = {
            "timestamp": timestamp,
            "subject": subject,
            "source_ip": source_ip,
            "user_agent": user_agent,
            "verb": verb,
            "resource": resource,
            "namespace": namespace,
            "response_code": response_code,
        }
        for field_name, value in required.items():
            if value == UNKNOWN:
                errors.append(field_name)

        return cls(
            timestamp=timestamp,
            subject=subject,
            source_ip=source_ip,
            user_agent=user_agent,
            verb=verb,
            api_group=api_group,
            resource=resource,
            subresource=subresource,
            namespace=namespace,
            name=name,
            response_code=response_code,
            stage=stage,
            audit_id=audit_id,
            line_number=line_number,
            parse_errors=tuple(errors),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "timestamp": self.timestamp,
            "subject": self.subject,
            "source_ip": self.source_ip,
            "user_agent": self.user_agent,
            "verb": self.verb,
            "api_group": self.api_group,
            "resource": self.resource,
            "subresource": self.subresource,
            "namespace": self.namespace,
            "name": self.name,
            "response_code": self.response_code,
            "stage": self.stage,
            "audit_id": self.audit_id,
            "line_number": self.line_number,
            "parse_errors": list(self.parse_errors),
        }


@dataclass(frozen=True)
class LLMAnalysis:
    status: str
    classification: str
    confidence: float
    evidence: list[str] = field(default_factory=list)
    attack_hypothesis: str = ""
    normal_explanation: str = ""
    false_positive_conditions: str = ""
    recommended_action: str = "alert_only"

    def to_dict(self) -> dict[str, Any]:
        return {
            "status": self.status,
            "classification": self.classification,
            "confidence": self.confidence,
            "evidence": list(self.evidence),
            "attack_hypothesis": self.attack_hypothesis,
            "normal_explanation": self.normal_explanation,
            "false_positive_conditions": self.false_positive_conditions,
            "recommended_action": self.recommended_action,
        }


@dataclass
class WindowEvidence:
    subject: str
    source_ip: str
    start: str
    end: str
    events: list[AuditEvent]

    @property
    def group_key(self) -> str:
        return f"{self.subject}|{self.source_ip}"

    def to_dict(self) -> dict[str, Any]:
        return {
            "subject": self.subject,
            "source_ip": self.source_ip,
            "start": self.start,
            "end": self.end,
            "events": [event.to_dict() for event in self.events],
        }


@dataclass
class Finding:
    classification: str
    risk_score: int
    severity: str
    rule_ids: list[str]
    subject: str
    source_ip: str
    window_start: str
    window_end: str
    evidence: list[dict[str, Any]]
    event_count: int
    thresholds: dict[str, Any]
    llm: LLMAnalysis | None = None

    def to_dict(self) -> dict[str, Any]:
        result: dict[str, Any] = {
            "classification": self.classification,
            "rule_classification": self.classification,
            "llm_enriched_classification": self.llm.classification if self.llm is not None else None,
            "risk_score": self.risk_score,
            "severity": self.severity,
            "rule_ids": list(self.rule_ids),
            "subject": self.subject,
            "source_ip": self.source_ip,
            "window": {"start": self.window_start, "end": self.window_end},
            "evidence": list(self.evidence),
            "event_count": self.event_count,
            "thresholds": dict(self.thresholds),
        }
        if self.llm is not None:
            result["llm"] = self.llm.to_dict()
        return result
