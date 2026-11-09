# Category 3: Cryptocurrency Platform Kubernetes Incident (2025)

**한국어** | [English](README_EN.md)

## 실제 사례

2025년 암호화폐 플랫폼 Kubernetes 침해 사례에서는 workload에서 획득한 ServiceAccount credential로 Kubernetes API를 호출하고, Secret과 리소스를 열거한 뒤 다른 workload 접근을 시도하는 post-compromise 흐름이 확인됐습니다. Kubernetes에서는 Pod에 ServiceAccount token이 기본적으로 투영될 수 있으므로 최소 권한 RBAC가 중요합니다. 동작 원리는 [Kubernetes ServiceAccount 문서](https://kubernetes.io/docs/concepts/security/service-accounts/)를 참고합니다.

> 이 실습은 실제 Secret을 탈취하거나 다른 Pod에 명령을 실행하지 않습니다. 동일한 저권한 ServiceAccount가 허용된 조회와 거부되는 공격성 요청을 보내도록 안전하게 단순화합니다.

모든 스크립트는 동일한 `pbl-crypto-platform-app` ServiceAccount를 사용합니다. 이 계정은 Pods, Services, ConfigMaps의 `get/list`만 허용되고 Secrets 및 `pods/exec` 권한은 없습니다.

## 공격 행위 대응

| 스크립트 | 실제 공격 단계 | API 행위 | Audit Log 관찰점 |
| --- | --- | --- | --- |
| `normal.sh` | 정상 애플리케이션 API 사용 | pods/services/configmaps 조회 | 같은 사용자, `get/list`, `code=200` |
| `abnormal_1.sh` | Secret enumeration | secrets `list` | 같은 사용자, resource=secrets, `code=403` |
| `abnormal_2.sh` | 다른 workload 접근 | pods/exec `create` | 같은 사용자, subresource=exec, `code=403` |
| `abnormal_3.sh` | 대량 resource enumeration | pods/secrets/configmaps 반복 조회 | 같은 사용자, resource 다양화와 빈도 급증 |

## 실행 및 로그

터미널 1:

```bash
docker exec pbl-security-control-plane \
  tail -F /var/log/kubernetes/audit.log | \
grep --line-buffered pbl-crypto-platform-app
```

터미널 2:

```bash
cd pbl-project
./category3/normal.sh
./category3/abnormal_1.sh
./category3/abnormal_2.sh
./category3/abnormal_3.sh
```

최근 이벤트:

```bash
docker exec pbl-security-control-plane \
  grep 'pbl-crypto-platform-app' /var/log/kubernetes/audit.log | tail -n 50
```

예시는 `logs/normal.log`, `logs/abnormal_1.log`부터 `abnormal_3.log`까지 확인합니다.

## 자동 탐지기와 LLM 분석

프로젝트 루트에서 Audit Log를 규칙 기반으로 분석할 수 있습니다. 기본 실행은 외부 모델 없이 deterministic mock LLM을 사용하므로 클러스터나 GPU가 없어도 재현됩니다.

```bash
python -m detector.cli \
  --input category3/logs/normal.log \
  --output-dir results/category3/normal \
  --llm mock \
  --label normal

python -m detector.cli \
  --input category3/logs/abnormal_1.log \
  --output-dir results/category3/abnormal_1 \
  --llm mock \
  --label attack
```

각 결과 디렉터리에 다음 파일이 생성됩니다.

- `findings.jsonl`: 위험 점수, 탐지 규칙, 원본 필드 기반 증거, LLM 설명
- `metrics.json`: TP/TN/FP/FN, precision, recall, F1
- `report.md`: 정상·공격 구분 근거, 오탐·미탐 분석, 한계

네 가지 기본 시나리오를 실행한 통합 결과는 [최종 결과 보고서](../results/category3/FINAL_REPORT.md)에서 확인할 수 있습니다.

오탐·미탐을 포함한 확장 평가 입력은 `tests/fixtures/audit_normal_breakglass.jsonl`, `audit_normal_sre_exec.jsonl`, `audit_attack_low_slow.jsonl`이며, 실행 결과는 `results/category3/extended/`에 저장됩니다.

로컬 Gemma 모델은 SAVA 환경에서 `/data/LLM_model/llama.cpp/build/bin/llama-server`를 사용해 실행할 수 있습니다. 모델은 `/data/LLM_model/gemma4/gemma-4-12b-it-IQ4_NL.gguf`, 물리 GPU는 2번을 사용합니다. `scripts/start_local_llm.sh`가 해당 바이너리를 자동으로 찾습니다.

```bash
./scripts/start_local_llm.sh
python -m detector.cli \
  --input category3/logs/abnormal_1.log \
  --output-dir results/category3/abnormal_1-local \
  --llm local \
  --label attack \
  --llm-repeats 3
```

LLM은 규칙 결과를 덮어쓰지 않고 설명·상관분석·우선순위만 보조합니다. 모델을 사용할 수 없으면 `unavailable` 상태로 기록하고 규칙 기반 결과를 유지합니다.

실제 GPU 2번 Gemma4 전체 연동 결과는 `results/category3/gemma_gpu2_20261020/full_ctx4096/`에 있습니다. 응답은 JSON schema로 제한하고, Gemma의 채널 접두사는 파서에서 정규화합니다. 18개 이벤트가 포함된 `abnormal_3` 때문에 context size는 4096으로 설정했습니다.

평가용 `--label`은 정상·공격 ground truth를 명시합니다. `normal.log`와 `abnormal_1.log`~`abnormal_3.log`만 생략해도 자동 인식하며, 다른 파일명은 반드시 `--label`을 지정해야 합니다. `--llm-repeats 3`을 사용하면 반복 출력 일관성이 `metrics.json`에 기록됩니다.
