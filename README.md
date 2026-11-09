# 실무클라우드보안 PBL Project
**한국어** | [English](README_EN.md)

| 실습 | 관찰 도구 | 정상 행위 | 비정상 행위 |
| --- | --- | --- | --- |
| Category 1 | Falco | 설정·임시 파일·health check | shadow·token 접근, 셸 실행 |
| Category 2 | Hubble | 서비스 경로·DNS 통신 | 직접 접근·내부 탐색·비정상 포트 |
| Category 3 | Audit Log | Pod·ConfigMap·Service 조회 | Secret·Pod exec·반복 조회 |

## 1. 준비

- Ubuntu 22.04/24.04 또는 Debian 12
- x86_64 또는 ARM64
- `sudo` 사용 권한

Docker Engine, kind, kubectl, Helm, Cilium, Hubble, Falco는 미리 설치하지 않아도 됩니다.

## 2. 설치

저장소를 clone한 뒤 프로젝트 루트에서 실행합니다.

```bash
cd pbl-project
chmod +x install.sh category1/*.sh category2/*.sh category3/*.sh
./install.sh
```

Docker를 처음 설치한 경우 스크립트가 로그아웃을 요청할 수 있습니다. 그때는 VM에서 로그아웃 후 다시 로그인하고 `./install.sh`를 한 번 더 실행합니다.

설치 결과를 확인합니다.

```bash
kubectl get nodes
kubectl get pods -A
```

노드 3개가 `Ready`이고 워크로드, Cilium, Hubble, Falco Pod가 `Running`이면 준비 완료입니다. 노드 3개는 별도 VM이 아니라 현재 VM의 Docker 컨테이너입니다.

## 3. 실습

모든 명령은 프로젝트 루트에서 실행합니다.

```bash
# Category 1: Falco
./category1/normal.sh
./category1/abnormal_1.sh
./category1/abnormal_2.sh
./category1/abnormal_3.sh

# Category 2: Hubble
./category2/normal.sh
./category2/abnormal_1.sh
./category2/abnormal_2.sh
./category2/abnormal_3.sh

# Category 3: Kubernetes Audit Log
./category3/normal.sh
./category3/abnormal_1.sh
./category3/abnormal_2.sh
./category3/abnormal_3.sh
```

로그를 실시간으로 보는 방법은 각 문서를 따릅니다.

- [Category 1 - Falco](category1/README.md)
- [Category 2 - Hubble](category2/README.md)
- [Category 3 - Audit Log](category3/README.md)

## API/Credential 악용 자동 탐지

Category 3에는 Kubernetes Audit Log를 정규화하고, 허용되지 않은 Secret 접근·`pods/exec`·반복 열거를 규칙과 5분 시간창으로 탐지하는 Python 도구가 포함되어 있습니다.

```bash
python -m unittest discover -s tests -v
python -m detector.cli \
  --input category3/logs/abnormal_1.log \
  --output-dir results/category3/abnormal_1 \
  --llm mock \
  --label attack
```

결과 디렉터리에는 `findings.jsonl`, `metrics.json`, `report.md`가 생성됩니다. `report.md`에는 각 판정의 근거와 정상·공격 구분, 오탐·미탐 분석, 한계가 포함됩니다.

기본 네 시나리오를 실행한 제출용 요약은 [Category 3 최종 결과](results/category3/FINAL_REPORT.md)입니다.

LLM 분석은 기본적으로 mock 모드이며, 로컬 Gemma GGUF를 사용하려면 SAVA 환경에서 `./scripts/start_local_llm.sh`를 실행합니다. 스크립트는 `/data/LLM_model/llama.cpp/build/bin/llama-server`를 자동으로 찾고, 기본 모델 경로는 `/data/LLM_model/gemma4/gemma-4-12b-it-IQ4_NL.gguf`, 물리 GPU는 2번입니다. LLM은 규칙 결과를 대체하지 않고 설명과 우선순위만 보조합니다. 실제 GPU 2번 전체 결과는 `results/category3/gemma_gpu2_20261020/full_ctx4096/`에 있습니다.

`metrics.json`에는 시간창·이벤트·시나리오 단위 지표와 rule-only/LLM 결과 비교가 포함됩니다. LLM 반복 일관성은 `--llm-repeats 3`으로 확인할 수 있습니다. 평가 파일명이 기본 시나리오 이름이 아니면 `--label normal|attack`을 명시해야 합니다.
