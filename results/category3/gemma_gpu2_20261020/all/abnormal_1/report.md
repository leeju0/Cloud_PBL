# API/Credential 악용 탐지 결과

## 요약

- 전체 탐지 창: 1
- TP/TN/FP/FN: 1/0/0/0
- Precision/Recall/F1: 1.000/1.000/1.000
- 이벤트 단위 TP/TN/FP/FN: 1/0/0/0
- 시나리오 판정: {'expected': 'attack', 'detected': True, 'rule_only_classification': 'attack', 'llm_enriched_classification': 'attack'}
- LLM 반복 일관성: {'runs': 1, 'consistent': True}
- 파싱: 전체 1, 성공 1, 오류 0, 불완전 0

## 탐지 결과와 정상 행위와 공격 행위를 구분한 근거

### 1. ATTACK (risk=85)

- 주체: `system:serviceaccount:pbl-security:pbl-crypto-platform-app`
- source IP: `172.18.0.1`
- 규칙: `sensitive_secret_access, forbidden_sensitive_request`
- 시간창: `2026-10-10T13:03:07.554577Z` ~ `2026-10-10T13:03:07.554577Z`
- 판정 근거:
  - `sensitive_secret_access`: 민감 리소스 접근 시도 — `{'resource': 'secrets', 'verb': 'list', 'response_code': 403}`
  - `forbidden_sensitive_request`: 민감 요청이 RBAC에 의해 거부됨 — `{'resource': 'secrets', 'subresource': 'unknown', 'response_code': 403}`
- LLM 상태: `available`, 분류 `attack`, 신뢰도 `0.95`
- LLM 설명: An attacker or a compromised service account is attempting to perform reconnaissance or credential theft by enumerating all secrets within the cluster. The 403 Forbidden response indicates that the account does not have the necessary permissions, but the attempt itself suggests a malicious intent to discover sensitive information.
- 오탐 가능성: The activity could be a false positive if a legitimate deployment script or automated monitoring tool was misconfigured to request a list of all secrets instead of a specific secret by name.

## 오탐 분석

합법적인 운영자의 Secret 조회·`pods/exec`, CI/CD의 반복 API 호출, NAT/프록시 IP 변화, 재시도에 따른 403 증가가 오탐을 만들 수 있습니다. 운영 환경에서는 허가된 주체·시간대 allowlist를 별도로 검증해야 합니다.

## 미탐 분석

탈취 자격증명이 정상 IP·User-Agent와 정상 속도로 사용되거나, 허용된 API만 이용한 저강도 정찰은 미탐될 수 있습니다. 감사 정책의 필드 누락·파싱 오류·시간 동기화 문제도 미탐 요인입니다.

## 한계

본 결과는 단일 namespace와 제한된 ServiceAccount를 사용하는 소규모 테스트베드의 위험 신호입니다. Audit Log만으로 공격 의도를 확정할 수 없고, 임계값은 운영 환경에 일반화되지 않습니다. LLM은 규칙 결과를 보조할 뿐 차단이나 증거 수집을 수행하지 않습니다.
