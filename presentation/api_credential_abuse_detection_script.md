# API/Credential 악용 탐지 발표 대본

영문 PPT 발표용 한국어 대본이다. 발표 시간은 약 10~12분을 기준으로 작성했으며, 기본 시나리오와 오탐·미탐 확장 평가를 구분해 설명한다.

## 1. 표지 — API / Credential Abuse Detection

### 핵심 내용

- Kubernetes Audit Log 기반 API/Credential 악용 탐지
- 규칙 기반 탐지와 Local LLM(Gemma4) 분석 결합
- 수업: 실무클라우드보안
- 발표자: 이주영

### 대본

안녕하세요. 실무클라우드보안 수업에서 API와 Credential 악용 탐지 프로젝트를 수행한 이주영입니다. Kubernetes Audit Log를 이용해 정상적인 API 사용과 악용 행위를 구분하고, 규칙 기반 탐지 결과를 Gemma4 LLM으로 설명하는 파이프라인을 구현했습니다. 오늘은 탐지 근거와 실제 결과, 그리고 오탐·미탐을 포함한 한계를 설명드리겠습니다.

## 2. 목차 — Contents

### 핵심 내용

- 01 Project Overview
- 02 Detection Strategy
- 03 Methodology / LLM
- 04 Results / Limitations

### 대본

발표는 네 부분으로 구성했습니다. 먼저 문제와 테스트 환경, 시나리오를 설명합니다. 다음으로 정상 행위와 공격 행위를 구분하는 탐지 전략과 규칙을 보여드립니다. 세 번째로 증거가 위험 점수와 LLM 설명으로 연결되는 방법을 설명하고, 마지막으로 실제 탐지 결과와 오탐·미탐 확장 평가, 한계를 정리하겠습니다.

## 3. 문제 정의 및 프로젝트 목표

### 핵심 내용

- 탈취된 Credential은 정상 사용자와 동일한 Kubernetes API를 호출할 수 있음
- Secret 조회, Pod Exec, 리소스 열거는 민감한 행위
- 호출 주체, 리소스, 동작, 응답, 빈도, Identity를 함께 분석

### 대본

Kubernetes에서는 API 호출만으로 Secret 조회, Pod 내부 명령 실행, 클러스터 리소스 열거가 가능합니다. 특히 Credential이 탈취되면 공격자는 정상 사용자와 같은 API를 호출할 수 있기 때문에 단순한 인증 성공 여부만으로는 공격을 구분하기 어렵습니다. 그래서 누가, 무엇을, 얼마나 빠르게 호출했는지를 Audit Log에서 함께 분석하는 것을 목표로 했습니다.

## 4. 실습 환경 및 시나리오 개요

### 핵심 내용

- Namespace: `pbl-security`
- ServiceAccount: `pbl-crypto-platform-app`
- 정상 리소스: `pods`, `services`, `configmaps`
- 공격 리소스: `secrets`, `pods/exec`
- 실제 Credential 탈취가 아니라 악용 API 호출 패턴을 로그로 재현

### 대본

실습 환경은 Kubernetes 테스트 클러스터이며 `pbl-security` Namespace와 `pbl-crypto-platform-app` ServiceAccount를 사용했습니다. 정상 사용자는 Pod, Service, ConfigMap을 조회하고 HTTP 200 응답을 받습니다. 공격 시나리오는 같은 주체가 Secret을 조회하거나 Pod Exec을 시도하고, 짧은 시간 안에 여러 리소스를 반복해서 열거하는 상황입니다. 실제 Credential을 탈취한 것이 아니라, 탈취되었다고 가정한 API 악용 패턴을 Audit Log로 재현했습니다.

## 5. 정상 행위와 공격 행위의 흐름 비교

### 핵심 내용

- 정상: 허용 리소스 조회 → HTTP 200 → 정상
- 공격: Secret/Pod Exec/반복 열거 → 403 또는 비정상 패턴 → 위험 신호
- HTTP 403은 공격 성공이 아니라 공격 시도가 차단된 증거

### 대본

정상 운영에서는 허용된 리소스에 제한된 조회가 발생하고 대부분 HTTP 200 응답을 받습니다. 반면 공격 시나리오에서는 Secret 접근이나 `pods/exec`처럼 민감한 요청이 발생합니다. 요청이 403으로 차단되더라도 공격이 없었던 것이 아니라, 권한 없는 주체가 민감 API를 호출하려고 했다는 중요한 증거입니다. 따라서 성공한 공격뿐 아니라 차단된 공격 시도도 탐지 대상으로 포함했습니다.

## 6. 탐지 아키텍처

### 핵심 내용

```text
Audit Log → Normalize → Rule Engine → Redaction → Gemma4
```

- `findings.jsonl`: 이벤트별 탐지 근거
- `metrics.json`: TP/TN/FP/FN 및 평가 지표
- `report.md`: 설명·오탐·미탐·한계

### 대본

전체 흐름은 다섯 단계입니다. 먼저 Audit Log를 읽고 필드 타입을 정규화한 뒤 ServiceAccount와 source IP 기준으로 5분 시간창을 구성합니다. 이후 민감 API, 권한 거부, 반복 열거, Identity 이상을 규칙으로 탐지해 위험 점수를 계산합니다. LLM에 전달하기 전에는 Token, Password, 요청 Body와 같은 민감정보를 제거합니다. 마지막으로 Gemma4가 공격 가설, 관찰된 근거, 오탐 가능성, 권고를 생성합니다. 최종 분류는 규칙 기반으로 유지하고 LLM은 설명을 보조합니다.

## 7. 방법론 도식 — Evidence to Decision

### 핵심 내용

```text
Evidence 수집 → 정규화·Redaction → 규칙 위험 점수 → Gemma4 설명 → 검증·피드백
```

- 각 단계에서 원본 근거 보존
- 초기 분류는 규칙 점수로 결정
- LLM은 공격 가설·근거·오탐 조건을 설명
- 승인 티켓과 TP/TN/FP/FN 결과를 기준선 개선에 반영

### 대본

이 슬라이드는 구현된 탐지 방법론을 한 번에 보여줍니다. 먼저 Audit Log에서 행위자, HTTP verb, 리소스, 응답 코드, IP와 User-Agent를 수집합니다. 다음으로 Token이나 Password 같은 민감정보를 제거하고 안정적인 필드만 정규화한 뒤 5분 시간창을 만듭니다. 그다음 Secret 접근, Pod Exec, 403, 반복 열거, Identity 이상을 규칙 점수로 계산해 초기 분류를 결정합니다. 규칙에 걸린 이벤트만 Gemma4에 전달해 공격 가설과 근거, 오탐 조건을 설명하게 합니다. 마지막으로 분석가의 승인 정보와 TP·TN·FP·FN 결과를 반영해 allowlist와 threshold를 개선합니다. LLM은 규칙 판정을 몰래 덮어쓰지 않습니다.

## 8. 탐지 규칙과 위험 점수

### 핵심 내용

| 규칙 | 조건 | 점수 |
|---|---|---:|
| `sensitive_secret_access` | `secrets` 접근 | 60 |
| `pod_exec_attempt` | `pods/exec create` | 60 |
| `forbidden_sensitive_request` | 민감 요청 HTTP 403 | 25 |
| `enumeration_burst` | 5분 내 8회 이상·3종 리소스 | 30 |
| `identity_anomaly` | 기준 밖 IP/User-Agent | 25 |

- 30점 미만: normal
- 30~59점: suspicious
- 60점 이상: attack

### 대본

규칙은 단일 이벤트 하나만으로 판정하지 않고 여러 신호를 합산합니다. Secret 접근과 Pod Exec은 각각 60점으로 가장 높은 가중치를 부여했습니다. 민감 요청이 403으로 거부되면 25점을 추가하고, 5분 안에 8회 이상 요청하면서 3종 이상의 리소스를 조회하면 열거 burst로 30점을 추가합니다. 60점 이상이면 공격으로 분류하고, 규칙 결과는 항상 재현 가능하도록 유지했습니다.

## 9. 정상 행위 예시

### 핵심 내용

```json
{
  "verb": "list",
  "resource": "pods",
  "status": 200,
  "userAgent": "kubectl/v1.30"
}
```

- 허용 목록의 리소스
- 정상 `get/list` 동작
- HTTP 200
- 위험 점수 0

### 대본

정상 로그에서는 `pods`, `services`, `configmaps` 같은 허용된 리소스만 조회됩니다. 동작은 `get` 또는 `list`로 제한되고 HTTP 200 응답을 받습니다. 또한 정상 User-Agent와 기준 source IP가 사용되며 Secret 접근이나 Pod Exec, 반복 열거 증거가 없습니다. 따라서 이 사례는 위험 점수 0의 정상 행위로 분류됩니다.

## 10. 공격 행위 예시

### 핵심 내용

- `abnormal_1`: Secret 목록 조회, 403, 위험 점수 85
- `abnormal_2`: Pod Exec, 403, `curl/8.5.0`, 위험 점수 110
- `abnormal_3`: 18회 요청, 3종 리소스, 위험 점수 115

### 대본

첫 번째 공격은 ServiceAccount가 Secret 목록을 조회한 사례로, 민감 리소스 접근과 403 거부가 함께 발생해 85점이 되었습니다. 두 번째는 `pods/exec create`로 컨테이너 내부 명령 실행을 시도했고, `curl/8.5.0`이라는 기준 밖 User-Agent까지 관찰되어 110점이 되었습니다. 세 번째는 짧은 시간 안에 18개의 요청을 발생시키고 여러 리소스를 열거하면서 Secret 접근도 시도한 사례입니다. 반복성과 리소스 다양성이 함께 나타나 115점으로 탐지했습니다.

## 11. Gemma4 LLM 적용

### 핵심 내용

- SAVA 환경, Gemma4 12B IQ4_NL
- RTX A6000 물리 GPU 2번에서 실제 추론
- Redaction 후 JSON Schema 기반 요청
- 공격 가설·근거·오탐 조건·권고 생성

### 대본

LLM은 규칙 결과를 대체하는 용도가 아니라 분석가가 결과를 이해하도록 돕는 용도로 사용했습니다. Audit evidence에서 Token과 Password, 요청 Body를 먼저 제거하고 Gemma4에 전달했습니다. JSON Schema를 사용해 구조화된 결과를 받았고, 실제 SAVA 환경의 RTX A6000 GPU 2번에서 추론을 확인했습니다. 예를 들어 Pod Exec 사례에 대해 Credential 탈취와 컨테이너 내부 접근을 시도했을 가능성, 승인된 장애 대응이면 오탐일 수 있다는 조건, Identity와 RBAC를 확인하라는 권고를 생성했습니다.

## 12. 실제 탐지 결과

### 핵심 내용

| 시나리오 | 규칙 | LLM 상태 | LLM 판정 |
|---|---|---|---|
| `normal` | normal | skipped | normal |
| `abnormal_1` | attack | available | attack |
| `abnormal_2` | attack | available | attack |
| `abnormal_3` | attack | available | attack |

- 기본 시나리오: Precision 1.000, Recall 1.000, F1 1.000
- 공격 3개 모두 Gemma confidence 0.95

### 대본

실제 GPU 2번의 Gemma4로 정상 1개와 공격 3개를 재실행했습니다. 정상 로그는 규칙 기반 정상 판정으로 LLM 호출을 생략했고, 공격 3개는 모두 LLM 상태가 available이었습니다. 세 공격 사례 모두 Gemma4의 출력 분류가 규칙 결과와 일치했고 confidence는 0.95였습니다. 다만 이 값은 모델이 생성한 confidence이므로 통계적으로 보정된 확률이라고 해석하지는 않았습니다.

## 13. 오탐·미탐 확장 평가

### 핵심 내용

| 시나리오 | 정답 | 결과 | 유형 |
|---|---|---|---|
| `normal_breakglass` | 정상 | 공격 | 오탐 |
| `normal_sre_exec` | 정상 | 공격 | 오탐 |
| `attack_low_slow` | 공격 | 정상 | 미탐 |

- TP=3, TN=1, FP=2, FN=1
- Precision=0.600, Recall=0.750, F1=0.667

### 대본

기본 시나리오만 보면 정상과 공격의 차이가 명확하기 때문에 성능이 과도하게 좋아 보일 수 있습니다. 그래서 승인된 운영자의 Secret 조회와 Pod Exec을 정상 정답으로 추가했고, 요청 빈도가 낮은 저속 API 정찰을 공격 정답으로 추가했습니다. 그 결과 승인된 민감 작업 두 건은 오탐으로 잡혔고, 저속 정찰은 미탐이 되었습니다. 전체 확장 평가의 Precision은 0.600, Recall은 0.750, F1은 0.667입니다. 이 결과가 운영 환경의 trade-off를 더 잘 보여줍니다.

## 14. 한계와 개선 방향

### 핵심 내용

현재 한계:

- 단일 Namespace·제한된 ServiceAccount 중심
- 고정된 5분 시간창과 위험 점수
- Audit Log만 사용
- NAT·프록시·자동화 도구로 Identity 오탐 가능
- 정상 속도의 저속 정찰 미탐 가능
- LLM confidence는 보정된 확률이 아님

개선 방향:

- 계정·시간대·티켓 기반 allowlist
- 장기 누적 행동 기준선
- 네트워크·컨테이너 런타임·파일 접근 로그 결합
- 계정별 정상 IP/User-Agent 모델링
- LLM 결과에 원본 증거 링크와 신뢰도 보정 추가

### 대본

이 탐지기는 단일 Namespace와 제한된 ServiceAccount를 사용한 소규모 테스트베드에서 평가했습니다. 따라서 5분 시간창과 점수 기준을 그대로 운영 환경에 적용할 수는 없습니다. Audit Log만으로는 장애 대응인지 공격인지 완전히 구분할 수 없고, NAT나 프록시 때문에 Identity 이상이 오탐될 수도 있습니다. 또한 공격자가 정상 속도로 천천히 API를 사용하면 미탐될 수 있습니다. 향후에는 승인 티켓과 운영 계정 정보를 연동하고, 장기 행동 기준선과 네트워크·런타임 로그를 함께 사용해야 합니다.

## 15. 결론 및 다음 단계

### 핵심 내용

1. 민감 API·Pod Exec·403·반복 열거 조합으로 악용 신호 탐지
2. 실제 Gemma4를 GPU 2번에서 연결해 설명 가능한 결과 생성
3. 오탐·미탐을 포함한 현실적인 한계 확인

### 대본

결론적으로 Kubernetes Audit Log에서 Secret 접근, Pod Exec, 권한 거부, 반복 열거를 조합하면 API와 Credential 악용 신호를 탐지할 수 있었습니다. 실제 Gemma4는 GPU 2번에서 동작하며 공격 가설과 근거, 오탐 조건을 생성했습니다. 하지만 승인된 운영 작업은 오탐될 수 있고 저속 공격은 미탐될 수 있으므로 탐지 결과를 공격 의도의 확정으로 사용해서는 안 됩니다. 규칙은 재현 가능한 판정을 만들고, LLM은 그 판정을 사람이 이해할 수 있는 분석으로 확장한다는 것이 이번 프로젝트의 결론입니다.

## 16. 마무리 — THANK YOU

### 핵심 내용

- API / Credential Abuse Detection
- 실무클라우드보안
- 이주영

### 대본

이상으로 발표를 마치겠습니다. 핵심은 규칙으로 재현 가능한 탐지를 만들고, Audit Log 근거와 Gemma4 설명을 결합해 분석가가 결과를 이해할 수 있도록 하는 것입니다. 감사합니다.

## 발표 후 질문 대비

### Q. 왜 LLM이 최종 판정을 하지 않나요?

LLM은 같은 입력에도 출력이 달라질 수 있고, 공격 차단과 같은 고위험 결정을 직접 맡기 어렵습니다. 따라서 규칙을 최종 근거로 유지하고 LLM은 설명과 우선순위를 보조하도록 설계했습니다.

### Q. HTTP 403인데 왜 공격으로 보나요?

403은 공격이 성공했다는 뜻이 아닙니다. 권한 없는 주체가 Secret이나 Pod Exec 같은 민감 API를 호출하려고 했다는 공격 시도의 증거입니다.

### Q. 기본 결과가 100%인데 믿을 수 있나요?

기본 로그는 정상과 공격의 차이가 명확한 예시입니다. 그래서 승인된 운영 작업과 저속 정찰을 추가했고, 확장 평가에서는 Precision 0.600, Recall 0.750, F1 0.667이 나왔습니다.

### Q. LLM을 넣어서 정확도가 올라갔나요?

이번 설계에서 LLM은 규칙 판정을 덮어쓰지 않으므로 수치적인 탐지 성능을 인위적으로 올리지는 않았습니다. 대신 공격 근거, 공격 가설, 오탐 가능성을 자동으로 설명하는 역할을 수행했습니다.

## 결과 파일

- [발표자료](./api_credential_abuse_detection.pptx)
- [실제 Gemma4 전체 실행 결과](../results/category3/gemma_gpu2_20261020/full_ctx4096/)
- [최종 결과 보고서](../results/category3/FINAL_REPORT.md)
