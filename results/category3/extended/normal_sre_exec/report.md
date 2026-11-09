# API/Credential 악용 탐지 결과

## 요약

- 전체 탐지 창: 1
- TP/TN/FP/FN: 0/0/1/0
- Precision/Recall/F1: 0.000/0.000/0.000
- 이벤트 단위 TP/TN/FP/FN: 0/0/1/0
- 시나리오 판정: {'expected': 'normal', 'detected': True, 'rule_only_classification': 'attack', 'llm_enriched_classification': 'attack'}
- LLM 반복 일관성: {'runs': 1, 'consistent': True}
- 파싱: 전체 1, 성공 1, 오류 0, 불완전 0

## 탐지 결과와 정상 행위와 공격 행위를 구분한 근거

### 1. ATTACK (risk=60)

- 주체: `system:serviceaccount:pbl-security:pbl-crypto-platform-app`
- source IP: `172.18.0.1`
- 규칙: `pod_exec_attempt`
- 시간창: `2026-10-20T02:01:00Z` ~ `2026-10-20T02:01:00Z`
- 판정 근거:
  - `pod_exec_attempt`: Pod 실행 subresource 호출 — `{'resource': 'pods', 'subresource': 'exec', 'verb': 'create', 'response_code': 200}`
- LLM 상태: `mock`, 분류 `attack`, 신뢰도 `0.95`
- LLM 설명: 민감 API 또는 Credential 악용 패턴이 관찰됨
- 오탐 가능성: 승인된 운영자의 break-glass 작업 또는 자동화 도구일 수 있음

## 오탐 분석

합법적인 운영자의 Secret 조회·`pods/exec`, CI/CD의 반복 API 호출, NAT/프록시 IP 변화, 재시도에 따른 403 증가가 오탐을 만들 수 있습니다. 운영 환경에서는 허가된 주체·시간대 allowlist를 별도로 검증해야 합니다.

## 미탐 분석

탈취 자격증명이 정상 IP·User-Agent와 정상 속도로 사용되거나, 허용된 API만 이용한 저강도 정찰은 미탐될 수 있습니다. 감사 정책의 필드 누락·파싱 오류·시간 동기화 문제도 미탐 요인입니다.

## 한계

본 결과는 단일 namespace와 제한된 ServiceAccount를 사용하는 소규모 테스트베드의 위험 신호입니다. Audit Log만으로 공격 의도를 확정할 수 없고, 임계값은 운영 환경에 일반화되지 않습니다. LLM은 규칙 결과를 보조할 뿐 차단이나 증거 수집을 수행하지 않습니다.
