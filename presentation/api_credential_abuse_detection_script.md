# API/Credential 악용 탐지 발표 대본

영문 PPT 발표용 한국어 대본이다. 발표 시간은 약 12~15분을 기준으로 작성했으며, 기본 시나리오와 오탐·미탐 확장 평가를 구분해 설명한다.

## 1. 표지 — API / Credential Abuse Detection

### 핵심 내용

- Kubernetes Audit Log 기반 API/Credential 악용 탐지
- 규칙 기반 탐지와 LLM 분석 결합
- 수업: 실무클라우드보안
- 발표자: 이주영

### 대본

안녕하세요. 컴퓨터공학과 석사과정 이주영입니다. 이번 프로젝트에서는 Kubernetes Audit Log를 이용해 정상적인 API 사용과 공격 의심 행위를 구분해 보았습니다. 먼저 규칙으로 위험도를 계산하고, LLM은 그 결과를 사람이 이해하기 쉽게 설명하도록 구성했습니다. 지금부터 실험 과정과 결과를 말씀드리겠습니다.

## 2. 목차 — Contents

### 핵심 내용

- 01 Project Overview
- 02 Detection Strategy
- 03 Methodology / LLM
- 04 Results / Limitations

### 대본

발표는 네 부분으로 나누었습니다. 먼저 왜 이 탐지가 필요한지와 테스트 환경을 설명하겠습니다. 그다음 정상 사용과 공격 시도를 구분하는 규칙을 보여드리겠습니다. 이어서 LLM을 어떻게 연결했는지 설명하고, 마지막으로 실제 결과와 오탐·미탐, 한계를 정리하겠습니다.

## 3. 문제 정의 및 프로젝트 목표

### 핵심 내용

- 탈취된 Credential은 정상 사용자와 동일한 Kubernetes API를 호출할 수 있음
- Secret 조회, Pod Exec, 리소스 열거는 민감한 행위
- 호출 주체, 리소스, 동작, 응답, 빈도, Identity를 함께 분석

### 대본

Kubernetes API는 편리하지만, 호출 방법에 따라 민감한 작업도 가능합니다. 예를 들어 Secret에는 비밀번호나 토큰이 들어갈 수 있고, Pod Exec을 사용하면 컨테이너 안에서 명령을 실행할 수 있습니다. Credential이 탈취되면 공격자도 정상 사용자와 같은 API를 호출할 수 있기 때문에 로그인 성공 여부만으로는 부족합니다. 그래서 누가, 무엇을, 얼마나 빠르게 호출했는지를 Audit Log에서 함께 보도록 했습니다.

## 4. 실습 환경 및 시나리오 개요

### 핵심 내용

- Namespace: `pbl-security`
- ServiceAccount: `pbl-crypto-platform-app`
- 저장소에 제공된 대표 Audit Log를 입력으로 사용
- 정상 리소스: `pods`, `services`, `configmaps`
- 공격 리소스: `secrets`, `pods/exec`
- 실제 Credential 탈취 없이, 제공된 로그와 재현 스크립트로 API 호출 패턴을 분석

### 대본

실습은 Kubernetes 테스트 클러스터에서 진행했습니다. 이 프로젝트에서 제공하는 `category3/logs/normal.log`와 `abnormal_1.log`부터 `abnormal_3.log`를 탐지기의 입력으로 사용했습니다. 정상 로그는 Pod·Service·ConfigMap 조회를 담고 있고, 공격 로그는 Secret 조회, Pod Exec, 짧은 시간 동안의 반복 조회를 담고 있습니다. 실제 자격증명을 훔친 것은 아니며, 저장소의 실습 스크립트로 같은 요청 패턴을 클러스터에서 재현할 수도 있습니다.

## 5. 정상 행위와 공격 행위의 흐름 비교

### 핵심 내용

- 정상: 허용 리소스 조회 → HTTP 200 → 정상
- 공격: Secret/Pod Exec/반복 열거 → 403 또는 비정상 패턴 → 위험 신호
- HTTP 403은 공격 성공이 아니라 공격 시도가 차단된 증거

### 대본

정상 사용은 허용된 리소스를 읽고 HTTP 200을 받는 흐름입니다. 반대로 Secret이나 `pods/exec`가 나타나면 주의해서 봐야 합니다. 여기서 403은 공격이 성공했다는 뜻은 아닙니다. 다만 권한이 없는 주체가 민감한 API를 호출했다는 기록이므로, 차단된 공격 시도 자체를 탐지 대상으로 포함했습니다.

## 6. 탐지 아키텍처

### 핵심 내용

```text
Audit Log → Normalize → Rule Engine → Redaction → LLM
```

- `findings.jsonl`: 이벤트별 탐지 근거
- `metrics.json`: TP/TN/FP/FN 및 평가 지표
- `report.md`: 설명·오탐·미탐·한계

### 대본

이 슬라이드는 각 구성 요소의 역할을 보여줍니다. Audit Log 단계에서는 저장소에 제공된 JSONL 로그를 읽습니다. Normalize 단계에서는 시간, 사용자, 리소스, 동작, 응답 코드, IP와 User-Agent처럼 판정에 필요한 필드를 같은 형식으로 정리합니다. Rule Engine은 같은 주체와 IP의 요청을 시간창으로 묶고 위험 점수와 근거를 만듭니다. 그 뒤 LLM에 전달할 Finding에서 Token, Password, 요청 Body를 제거하고, 필요한 정보만 구조화해 설명을 요청합니다. 최종 분류는 Rule Engine이 유지하고, LLM은 그 결과를 설명합니다.

## 7. 방법론 도식 — Evidence to Decision

### 핵심 내용

```text
Evidence 수집 → 정규화·그룹화 → 규칙 점수·라벨 → Redaction → LLM 설명 → 검증·피드백
```

- 같은 주체·IP의 이벤트를 300초 단위 Window로 그룹화
- 각 단계에서 원본 근거와 line number 보존
- 초기 분류는 규칙 점수로 결정
- LLM은 공격 가설·근거·오탐 조건을 설명
- 승인 티켓과 TP/TN/FP/FN 결과를 기준선 개선에 반영

### 대본

앞 슬라이드가 구성 요소를 보여줬다면, 여기서는 코드가 실제로 어떤 순서로 판정하는지 설명하겠습니다. 먼저 JSONL의 각 줄을 Audit Event로 변환하고, 같은 ServiceAccount와 source IP가 만든 이벤트를 시간순으로 정렬합니다. 첫 이벤트부터 300초 안에 들어온 요청을 하나의 Window로 묶고, 이 Window를 판정 단위로 사용합니다. 각 Window에서 Secret 접근, `pods/exec`, 민감 요청의 403, 반복 열거, 기준 밖 IP·User-Agent 규칙을 검사합니다. 그 결과로 risk score, rule id, 원본 line number를 함께 저장하고, 점수가 높은 Window만 민감정보를 제거해 LLM에 보냅니다. 따라서 LLM이 라벨을 정하는 것이 아니라, 규칙이 먼저 만든 라벨을 설명하는 구조입니다.

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

점수는 Window 안에서 규칙별로 계산하며, 같은 규칙이 여러 번 나타나도 한 Window에서는 한 번만 더합니다. 허용된 `pods`, `services`, `configmaps`의 `get/list`와 HTTP 200은 정상 근거로만 기록하고 점수는 주지 않습니다. Secret의 `get/list`와 `pods/exec create`는 각각 60점, 민감 요청의 HTTP 403은 25점입니다. 300초 안에 8개 이상의 요청과 3종 이상의 리소스가 함께 나타나면 30점, 기준 밖 IP나 User-Agent가 나타나면 25점을 더합니다. 30점 미만은 normal, 30~59점은 suspicious, 60점 이상은 attack 라벨을 부여합니다. 예를 들어 Secret 조회와 403이 함께 있으면 60+25로 85점이 됩니다. 이 계산은 같은 로그를 다시 넣어도 같은 결과를 내므로 재현할 수 있습니다.

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

이 사례는 저장소에 제공된 `normal.log`에서 확인한 정상 Window입니다. 허용된 `pods`, `services`, `configmaps`만 읽고 있고 동작도 `get`이나 `list`로 제한되어 있습니다. 응답은 모두 HTTP 200이고 User-Agent와 IP도 기준선과 같습니다. Secret, Pod Exec, 반복 열거가 없으므로 가중치가 붙는 규칙이 없고, 점수는 0점으로 normal 라벨이 됩니다.

## 10. 공격 행위 예시

### 핵심 내용

- `abnormal_1`: Secret 목록 조회, 403, 위험 점수 85
- `abnormal_2`: Pod Exec, 403, `curl/8.5.0`, 위험 점수 110
- `abnormal_3`: 18회 요청, 3종 리소스, 위험 점수 115

### 대본

이제 저장소에 제공된 세 개의 abnormal 로그에 같은 규칙을 적용합니다. `abnormal_1`은 Secret 조회 60점과 403 25점이 합쳐져 85점입니다. `abnormal_2`는 `pods/exec create` 60점, 403 25점, 기준 밖 User-Agent 25점으로 110점입니다. `abnormal_3`은 Secret 접근 60점, 403 25점, 18개 요청과 3종 리소스의 burst 30점으로 115점입니다. 중요한 점은 403이 공격 성공을 뜻하는 것이 아니라, 민감한 요청이 발생했다는 증거로 점수에 반영된다는 점입니다.

## 11. LLM 적용

### 핵심 내용

- LLM 연결
- Redaction 후 JSON Schema 기반 요청
- 공격 가설·근거·오탐 조건·권고 생성

### 대본

여기서 LLM은 최종 판정자가 아닙니다. 먼저 규칙이 만든 Finding에서 Token, Password, 요청 Body 같은 값을 제거하고, 사용자, 리소스, 응답 코드, 점수, rule id와 같은 필요한 정보만 JSON Schema 형태로 전달합니다. 예를 들어 Pod Exec 사례라면 “컨테이너 내부 명령 실행 요청이므로 계정 오용 가능성을 확인할 필요가 있다”고 설명하고, 동시에 승인된 장애 대응일 수도 있으므로 사용자, RBAC 권한, 승인 기록과 source IP를 확인하라고 안내합니다. 즉 LLM은 공격 사실을 증명하는 것이 아니라, 규칙이 남긴 근거와 추가 조사 방향을 정리합니다.

## 12. 실제 탐지 결과

### 핵심 내용

| 시나리오 | 규칙 | LLM 상태 | LLM 판정 |
|---|---|---|---|
| `normal` | normal | skipped | normal |
| `abnormal_1` | attack | available | attack |
| `abnormal_2` | attack | available | attack |
| `abnormal_3` | attack | available | attack |

- 기본 시나리오: Precision 1.000, Recall 1.000, F1 1.000
- 공격 3개 모두 LLM confidence 0.95

### 대본

저장소에 제공된 기본 로그 네 개를 동일한 탐지기에 입력했습니다. 정상 Window는 규칙에서 바로 normal로 판단해 LLM을 건너뛰었고, 세 개의 공격 Window만 LLM에 전달했습니다. 세 사례 모두 LLM의 설명 라벨이 규칙 결과와 일치했습니다. 출력된 confidence 0.95는 모델이 생성한 참고값일 뿐, 실제 공격 확률로 보정된 통계값은 아닙니다.


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

기본 로그만 보면 정상과 공격이 뚜렷해서 성능이 좋아 보일 수 있습니다. 그래서 저장소에 포함한 확장 평가 로그로 승인된 Secret 조회와 Pod Exec, 그리고 천천히 API를 조회하는 저속 정찰을 추가로 시험했습니다. 정상 작업 두 건은 공격으로 잘못 판단했고, 저속 정찰 한 건은 놓쳤습니다. 전체 결과는 Precision 0.600, Recall 0.750, F1 0.667로, 민감 API 규칙이 명확한 공격은 잡지만 승인 작업과 느린 공격에는 한계가 있음을 보여줍니다.

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

이번 결과를 운영 환경 성능으로 그대로 받아들이기는 어렵습니다. 테스트가 하나의 Namespace와 ServiceAccount를 중심으로 이루어졌고, 5분 창과 점수도 예시 데이터에 맞춘 값이기 때문입니다. Audit Log만 보면 장애 대응과 공격을 완전히 구분하기 어렵고, NAT나 프록시 때문에 정상 사용자가 낯선 IP로 보일 수도 있습니다. 반대로 공격자가 정상 속도로 천천히 움직이면 놓칠 수 있습니다. 앞으로는 승인 티켓, 계정별 기준선, 네트워크와 런타임 로그를 함께 봐야 합니다.

## 15. 결론 및 다음 단계

### 핵심 내용

1. 민감 API·Pod Exec·403·반복 열거 조합으로 악용 신호 탐지
2. LLM을 연결해 설명 가능한 결과 생성
3. 오탐·미탐을 포함한 현실적인 한계 확인

### 대본

이번 프로젝트에서는 Secret 접근, Pod Exec, 403, 반복 호출을 함께 보면 API와 Credential 악용 가능성을 찾아낼 수 있다는 점을 확인했습니다. 동시에 정상적인 관리자 작업은 오탐될 수 있고, 천천히 진행되는 공격은 놓칠 수 있다는 한계도 확인했습니다. 그래서 탐지 결과는 공격 확정이 아니라 추가 조사가 필요한 위험 경보로 사용해야 합니다. 규칙은 로그를 일관된 기준으로 분류하고, LLM은 어떤 근거로 경보가 발생했는지와 정상 작업일 가능성을 설명합니다. 최종 판단은 분석가가 원본 로그와 승인 기록을 확인한 뒤 내립니다.

## 16. 마무리 — THANK YOU

### 핵심 내용

- API / Credential Abuse Detection
- 실무클라우드보안
- 이주영

### 대본

이상으로 발표를 마치겠습니다. 규칙으로 위험 신호를 찾고, LLM으로 그 이유를 설명하며, 마지막 판단은 분석가가 내리는 구조입니다. 경청해주셔서 감사합니다.

## 발표 후 질문 대비

### Q. 왜 LLM이 최종 판정을 하지 않나요?

LLM은 같은 입력에도 표현이 달라질 수 있고, 공격 차단처럼 중요한 결정을 직접 맡기기에는 불확실성이 있습니다. 그래서 규칙이 위험도를 정하고, LLM은 그 판단의 근거를 설명하도록 역할을 나눴습니다.

### Q. HTTP 403인데 왜 공격으로 보나요?

403은 공격이 성공했다는 뜻은 아닙니다. 다만 권한이 없는 주체가 Secret이나 Pod Exec 같은 민감 API를 요청했다는 뜻이므로, 공격 시도로 볼 수 있는 중요한 단서입니다.

### Q. 기본 결과가 100%인데 믿을 수 있나요?

기본 네 사례는 구분이 쉬운 예시라서 100%가 나왔습니다. 그래서 승인된 운영 작업과 저속 정찰을 추가로 시험했고, 확장 평가에서는 Precision 0.600, Recall 0.750, F1 0.667이 나왔습니다. 이 결과를 운영 환경에 더 가까운 수치로 보고 있습니다.

### Q. LLM을 넣어서 정확도가 올라갔나요?

이번 설계에서 LLM은 규칙 판정을 덮어쓰지 않기 때문에 탐지 정확도를 직접 올리는 역할은 아닙니다. 대신 왜 경보가 발생했는지, 정상 작업일 가능성은 무엇인지, 다음에 무엇을 확인할지를 정리해 줍니다.

## 결과 파일

- [발표자료](./api_credential_abuse_detection.pptx)
- [LLM 실행 결과](../results/category3/)
- [최종 결과 보고서](../results/category3/FINAL_REPORT.md)
