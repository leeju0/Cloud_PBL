# API/Credential 악용 탐지 최종 결과

## 1. 실행 조건

- 입력: `category3/logs/normal.log`, `abnormal_1.log`, `abnormal_2.log`, `abnormal_3.log`
- 탐지 방식: Kubernetes Audit Log 정규화 → 규칙 기반 탐지 → 5분 시간창 상관분석
- 기본 통합 평가: `mock` LLM 모드, 각 공격 시나리오 3회 반복
- 실제 모델: `/data/LLM_model/gemma4/gemma-4-12b-it-IQ4_NL.gguf`, `source activate SAVA`, 물리 GPU 2번
- 실제 Gemma4 평가: 정상 1개와 공격 3개를 `llama-server`로 분석했고 GPU 2번에서 모델 로드·추론·JSON 응답을 확인함. 결과는 `results/category3/gemma_gpu2_20261020/full_ctx4096/`에 저장

## 2. 탐지 결과

| 시나리오 | 입력 이벤트 | 탐지 결과 | 위험 점수 | 주요 규칙 | 판정 근거 |
| --- | ---: | --- | ---: | --- | --- |
| normal | 4 | 정상 | 0 | `allowed_read` | `pods/services/configmaps`의 허용된 `get/list`, 모두 HTTP 200 |
| abnormal_1 | 1 | 공격 | 85 | `sensitive_secret_access`, `forbidden_sensitive_request` | ServiceAccount가 `secrets list`를 호출했고 RBAC가 403으로 거부 |
| abnormal_2 | 1 | 공격 | 110 | `pod_exec_attempt`, `forbidden_sensitive_request`, `identity_anomaly` | `pods/exec create`, 403 응답, 기준선과 다른 `curl/8.5.0` User-Agent |
| abnormal_3 | 18 | 공격 | 115 | `sensitive_secret_access`, `forbidden_sensitive_request`, `enumeration_burst` | 18개 요청, 3종 리소스, 반복 Secret 열거 및 403 |

세부 JSON 증거는 각 디렉터리의 `findings.jsonl`, 사람이 읽는 결과는 각 디렉터리의 `report.md`에 저장되어 있습니다.

## 3. 평가 결과

시나리오 단위로는 정상 1건과 공격 3건을 모두 올바르게 분류했습니다.

- Window 기준: TP=3, TN=1, FP=0, FN=0
- Event 기준: TP=20, TN=4, FP=0, FN=0
- Precision=1.000, Recall=1.000, F1=1.000
- 공격 시나리오의 mock LLM 3회 반복 결과는 모두 일관되었습니다.

실제 Gemma4 평가에서도 정상 1건과 공격 3건을 모두 올바르게 분류했습니다. 공격 3개 모두 LLM 상태가 `available`, confidence=0.95였고, Secret 접근·Pod Exec·403 거부·열거 burst를 근거로 공격 가설과 오탐 조건을 생성했습니다. 정상 로그는 규칙 결과를 유지하고 LLM 호출을 건너뛰었습니다.

이 수치는 제공된 소규모 예시 로그에 대한 결과이며 운영 환경 성능을 의미하지 않습니다.

## 4. 정상 행위와 공격 행위를 구분한 근거

정상 행위는 기준 ServiceAccount가 `pbl-security` namespace에서 `pods`, `services`, `configmaps`에 `get/list`를 수행하고 HTTP 200을 받은 경우입니다. 정상 로그에서는 이 기준을 벗어나는 민감 리소스, 실행 subresource, 비정상 User-Agent, burst가 관찰되지 않았습니다.

공격 행위는 다음의 명시적 증거로 분류했습니다.

1. `secrets` 접근은 허용 기준에 없는 민감 리소스 요청입니다.
2. `pods/exec`의 `create`는 workload 내부 명령 실행을 시도하는 subresource 요청입니다.
3. 403은 현재 ServiceAccount 권한으로 거부된 악용 시도라는 보조 증거입니다.
4. 짧은 5분 창에서 8건 이상 요청하고 3종 이상 리소스를 조회하면 `enumeration_burst`로 분류합니다.
5. 기준선에 없는 source IP 또는 User-Agent는 `identity_anomaly` 점수를 추가합니다.

규칙 판정이 최종 분류의 근거이며, LLM은 근거 요약과 우선순위화를 보조합니다.

## 5. 오탐 분석

다음 정상 상황은 현재 규칙에서 공격으로 탐지될 수 있습니다.

- 승인된 운영자의 장애 대응용 Secret 조회 또는 `pods/exec`
- CI/CD·모니터링 도구의 짧은 시간 내 반복 API 조회
- NAT·프록시로 인해 정상 사용자의 source IP가 기준선과 달라지는 경우
- API 재시도 로직으로 403 또는 호출 빈도가 일시적으로 증가하는 경우

운영 환경에서는 허가된 주체·namespace·작업 시간대 allowlist를 추가하고, 적용 전후 FP 변화를 별도로 측정해야 합니다.

## 6. 미탐 분석

다음 공격은 현재 Audit Log 기준으로 놓칠 수 있습니다.

- 탈취한 자격증명을 정상 IP·User-Agent·정상 속도로 사용하는 저강도 공격
- 허용된 `pods/services/configmaps` API만 사용한 저빈도 정찰
- 감사 정책에 의해 요청 본문, stage 또는 일부 필드가 기록되지 않는 경우
- 로그 파싱 실패, 시간 동기화 오류, 여러 공격자가 하나의 NAT IP를 공유하는 경우

따라서 `normal` 또는 `attack`은 공격 의도의 확정이 아니라 관찰된 행위에 대한 위험 신호로 해석해야 합니다.

## 7. 한계

- 테스트베드는 단일 namespace와 제한된 ServiceAccount를 사용하는 소규모 환경입니다.
- 5분 창과 위험 점수는 예시 데이터에 맞춘 값이며 운영 환경에 일반화되지 않습니다.
- Audit Log만 사용하므로 네트워크 흐름·컨테이너 런타임·파일 접근 증거를 함께 확인하지 않습니다.
- LLM은 로컬 모델을 사용할 수 없을 때 mock/fallback으로 동작하며, 규칙 결과를 덮어쓰거나 자동 차단하지 않습니다.
- 실제 Gemma 응답은 모델 버전·프롬프트에 따라 형식이 흔들릴 수 있어 JSON schema 요청과 채널 접두사 정규화를 적용했습니다.

## 8. 확장 평가: 오탐·미탐을 포함한 현실적 조건

기본 예시만 사용하면 모든 행위가 명확하게 구분되어 성능이 과도하게 좋아 보일 수 있으므로, 다음 추가 시나리오를 별도로 실행했습니다.

| 추가 시나리오 | 정답 | 현재 결과 | 의미 |
| --- | --- | --- | --- |
| `normal_breakglass` | 정상 | 공격 | 정상 운영자의 Secret 조회가 오탐으로 탐지됨 |
| `normal_sre_exec` | 정상 | 공격 | 승인된 운영자의 정상 `pods/exec`가 오탐으로 탐지됨 |
| `attack_low_slow` | 공격 | 정상 | 5분 burst 기준 이하의 저속 정찰이 미탐됨 |

기본 4개 시나리오와 확장 3개를 합친 시나리오 단위 결과는 다음과 같습니다.

- TP=3, TN=1, FP=2, FN=1
- Precision=0.600, Recall=0.750, F1=0.667

이 결과가 실제 운영 환경에 더 가까운 평가입니다. 즉, 민감 API와 실행 subresource를 강하게 탐지하는 대신 승인된 운영 작업을 오탐할 수 있고, 허용된 API만 천천히 사용하는 공격은 놓칠 수 있습니다. 이 trade-off가 본 탐지 시스템의 핵심 한계입니다.

