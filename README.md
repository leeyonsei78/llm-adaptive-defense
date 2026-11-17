# LLM Adaptive Defense — 적응형 AI 공격에 대한 LLM/규칙 방어 연구

적응형 AI(LLM) 공격에 대해 **LLM 방어가 가능한지·얼마나 효과적인지·어떤 설계 원칙이 유효한지**를
로컬·합성 환경에서 조건별로 실측한 캡스톤 연구. 로컬 Ollama(Qwen 2.5-Coder 14B, DeepSeek-Coder-v2 16B)와
Python 표준 라이브러리만으로 공격자·방어자·표적을 모두 구성해 재현 가능하게 만들었다.

> **핵심 입장:** "AI 방어가 우월하다"가 아니라 **"어떤 모델이 · 어떤 공격 난이도에 · 어떤 비용으로 작동하는가"**
> 라는 조건부 결론. 실측값만 보고하고 운영 환경 일반화는 주장하지 않는다.

## 주요 실험 (논문 6장)
- **정책 적용 시점**: SQL 인증 공격의 동기 vs 비동기 방어, 패치 전 노출 ≈ 도착률 × 추론시간 (§6.2–6.7)
- **계정 탈취(ATO) 능력 사다리**: 공격자 능력 L1–L3, 정보 대등성 하 216 캠페인 (§6.9)
- **교차 모델**: 공격자·방어자를 Qwen↔DeepSeek로 교차 — 최난도 L3를 막은 유일한 설정이 DeepSeek 방어자 (§6.11)
- **실트래픽 탐지**: 고정 파이프라인 공격 에이전트 vs 규칙·LLM 탐지 — 은밀 공격에선 규칙 > LLM (§6.12)
- **독립(규칙 비공개) holdout**: 규칙을 못 본 별도 에이전트가 blind 작성한 사례로 재검증 → 순환성 완화 (§6.13)
- **약점 교정**: holdout이 드러낸 공유 IP 오탐·무상태 한계를 IP 보강 규칙·상태 추적으로 교정 (§6.14)
- **에이전트 아키텍처 + networkx 듀얼그래프**: 고정 vs ReAct, 평면 vs 듀얼그래프 지식표현 비교 (§6.15)

## 저장소 구조
- `agent_lab/` — 합성 취약 표적·공격 에이전트(고정·ReAct)·방어 탐지기·멀티타겟 피벗·지식표현(networkx 듀얼그래프)
- `experiments/` — 실험별 러너(SQL 재생, ATO 사다리, 교차 모델, holdout, 상태 추적, 에이전트 아키텍처 등)
- `research/` — 실행 산출물(원시 결과·소스 스냅샷·프로토콜·보고서), 재현용 provenance 보존
- `vm_setup/` — 실 CVE/Metasploit 단계용 VirtualBox + Docker 런북(향후)
- 루트 `ato_*.py` · `ai_study.py` · `app.py` — 핵심 모듈과 교육용 실습 웹앱

## 재현
```powershell
python -m unittest -v                              # 전체 테스트
python experiments/run_ato_adaptive.py             # ATO 능력 사다리
python experiments/run_ato_holdout.py              # 독립 holdout 재검증
python experiments/run_agent_arch.py --repeats 6   # 에이전트 아키텍처·듀얼그래프
```
로컬 Ollama와 해당 모델 설치가 필요하다(규칙 전용 실험은 모델 불필요). 결과는 `research/<실험>_runs/<타임스탬프>/`에 저장된다.

## 안전·윤리 전제 (불변)
합성 데이터만 사용하며, 모든 공격 트래픽은 **127.0.0.1 루프백 + 코드 레벨 allowlist**로 외부 전송을 물리적으로 차단한다.
API 키는 환경변수로만 두고 코드·로그·커밋에 포함하지 않는다. 실제 표적·실 서비스·개인정보(PII)는 포함하지 않는다. 교육·연구 목적.

---

# Security Lab (교육용 실습 앱 · 상세 실험 노트)

## 후속 이력/모델 기여 분리 실험 완료

최신 후속 원고: [research/BEHAVIOR_STUDY.md](research/BEHAVIOR_STUDY.md). 통합 HTML: http://127.0.0.1:8765/research/paper_revision.html#behavior-study

24개 설계 에피소드(12대조쌍, 6가족, 종속 변형)에서 현재 요청 규칙/Qwen 12/24, 단순 이력 규칙 20/24, 강화 이력 규칙 24/24, Qwen 전체 이력 14/24 정답. 사후 탐색의 Qwen 기법 추출+시간 규칙은 24/24였지만 같은 자료 재사용이며 독립 평가가 아니다. 현재 요청이 동일하도록 설계했으므로 현재 요청만 보는 판별의 50%를 실제 운영 성능으로 일반화하지 않는다.

- 원시 결과: `research/behavior_runs/20261116_context_v1/` (120 HTTP, 주 모델 판정 48회 + 워밍업 1회, 탐색 추출 18회)
- 계획: `research/BEHAVIOR_PROTOCOL.md`, `research/BEHAVIOR_HYBRID_PROTOCOL.md`
- 후속 보고서 재생성: `python experiments/build_behavior_report.py --run research/behavior_runs/20261116_context_v1`
- 통합 HTML의 선행 SQL 보고서는 `research/archive/before_behavior_update/`에 보존. 아래 SQL 보고서 빌더만 실행하면 후속 부록이 빠지므로 후속 빌더를 다시 실행한다.

## 2026-11-16 후속 실험 완료

최신 논문 반영본: [research/PAPER_LOCAL_STUDY.md](research/PAPER_LOCAL_STUDY.md). 실행 중 앱에서 http://127.0.0.1:8765/research/paper_revision.html 을 열면 표와 그래프를 볼 수 있다. 서버 재시작은 필요 없다.

수동 Qwen 실험과 별도로 5조건 × 3반복 × 10개 고정 사례의 실제 HTTP 재생을 완료했다. 방어 없음/규칙/항상 안전/동기 AI/비동기 AI의 공격 성공은 각각 12/12, 3/12, 0/12, 0/12, 3/12다. 개발 사례의 기전 검증이며 AI의 일반적인 우월성을 입증하지 않는다.

- 계획: `research/SQL_REPLAY_PROTOCOL.md`
- 원시 결과: `research/replay_runs/20261116T134723524805Z/`
- 재실행: `python experiments/run_sql_replay.py --repeats 3 --gap 0.5`
- 논문 재생성: `python experiments/build_local_paper.py --run research/replay_runs/20261116T134723524805Z`
- 이전 보고서: `research/archive/before_local_ai_update/`. 아래 `build_report.py`는 이전 LLM 없는 연구용이며 실행하면 최신 HTML/보고서를 이전 내용으로 덮어쓴다. 최신 내용은 `build_local_paper.py`로 생성한다.

## 실제 AI 공격·방어 예비 실험

http://127.0.0.1:8765/ai 에서 실행합니다. 로컬 Ollama와 설치된 Qwen 모델이 필요합니다. 기존 즉시 실습과 분리된 선택 기능입니다. AI 공격자가 매 시도 새 입력을 선택하고 이전 HTTP 응답을 봅니다. 방어 조건은 없음/고정 규칙/동기 AI/비동기 AI입니다. AI는 검증된 `monitor` 또는 SQL 매개변수 바인딩 활성화만 선택할 수 있습니다. 대상은 캠페인 전용 loopback 임시 포트 서버이며 외부 주소를 받지 않습니다.

최대 5회 시도, 모델 호출마다 90초 제한입니다. 같은 모델·추론 자원을 두 역할이 공유하므로 큐 대기 시간을 함께 기록합니다. timeout 이후 Ollama 내부 생성이 바로 중단된다는 보장은 없습니다. 이 구성에서 관찰한 지연을 별도 하드웨어의 운영 성능으로 일반화하지 않습니다. 기본 2회는 기능 확인 규모이며 독립 캠페인 반복과 별도 공격 모델·앱·정상 로그인 평가가 추가로 필요합니다.

기록은 `research/ai_runs/<캠페인ID>.json`에 저장됩니다. 모델명·입출력 원문·해시·토큰·추론/큐 시간·실제 HTTP 결과·정책 적용 시각을 포함합니다. 실패 시 AI 성공으로 대체하지 않습니다. 서버 재시작 후에도 ID로 저장 결과를 읽을 수 있습니다. SQL 전용이며 정상 대조는 틀린 비밀번호의 거부 두 건뿐입니다. 합법 로그인 성공률이나 실제 FPR을 측정한 결과가 아닙니다.

명령행 실측: `python experiments/run_ai_pilot.py --rounds 2`. 이 실행은 조건별 1개 캠페인의 실제 모델 기능 확인입니다. 논문 성능 비교 결과로 사용하지 않습니다.

## 논문 보완 실험

보고서: http://127.0.0.1:8765/research/

`research/REPORT.md`에 요약, `research/PROTOCOL.md`에 실험 범위와 평가 규칙이 있습니다. 고정 사례 16종 × 방어 8조합 × 10회 = 1,280건의 실제 로컬 HTTP 요청과, 7개 합성 특징 시나리오의 행동 규칙 반례 재생을 수행했습니다. Qwen이나 공개 IDS 데이터셋 성능을 검증한 결과는 아닙니다.

재실행: `python experiments/run_study.py`. 그래프 생성에는 matplotlib이 필요합니다. 초안 HTML 보완본 및 보고서 생성: `python experiments/build_report.py --paper "원본 HTML 경로"`. 결과는 `research/results/`에 저장합니다. 원본은 수정하지 않습니다.

Python 3 표준 라이브러리만 사용하는 로컬 모의해킹 실습 웹 앱입니다.

## 주소 기반 진단 흐름

- 컨트롤 센터: http://127.0.0.1:8765
- 취약한 Papertrail 웹사이트: http://127.0.0.1:8766
- 개별 공격 입력 실습: http://127.0.0.1:8765/practice

대상 입력에 `127.0.0.1` 또는 `http://127.0.0.1:8766`을 넣고 진단합니다. 실제 HTTP 요청으로 로그인 우회, 미인코딩 HTML 반사, 관리자 문서 접근을 검사합니다. XSS 자동 진단은 응답의 실행 가능한 태그를 검사하며 브라우저 실행 확인과 구분합니다.

기본 해설과 방어 코드는 Codex가 미리 작성했습니다. **Codex 방어안 적용 + 재진단**을 누르면 즉시 방어를 활성화하고 같은 공격을 다시 보냅니다. Qwen/Ollama 호출은 제거했습니다. 실시간 Codex API도 필요하지 않습니다.

취약 사이트에는 비어 있는 입력란, 정상 값과 공격 값 예시, 예상 결과가 있습니다. 로그인은 `admin`과 `admin' -- `, 문서는 `1001`과 `1002`를 비교하세요. XSS 예시는 사이트 화면에서 확인할 수 있습니다. 실행 결과는 각 입력란 아래 격리된 화면에 표시됩니다. 방어 후 같은 공격 값을 다시 입력해 비교하세요.

서버 재시작 또는 취약 상태 초기화 시 방어 상태가 초기화됩니다.

## 실행

`start.bat`를 더블클릭하면 서버를 백그라운드로 실행하고 브라우저를 엽니다. 실행 로그는 `server.log`, 오류는 `server-error.log`에 기록됩니다. PC를 재시작한 뒤에는 다시 실행하세요.

터미널에서 직접 실행하려면:

```powershell
cd C:\codex_qwen_pentest
python app.py
```

브라우저에서 http://127.0.0.1:8765 를 여세요. 종료는 서버 창에서 Ctrl+C입니다.

SQL 인젝션, XSS, IDOR 탭에서 입력을 바꾸고 **공격 실행 & 방어 비교**를 누릅니다. SQL은 실제 SQLite 메모리 DB에서 실행됩니다. 비밀번호는 실습에서 항상 틀린 값으로 전달합니다. XSS는 sandbox iframe 안에서 실행되며 CSP로 외부 리소스를 제한합니다. IDOR는 가상 student 세션의 문서 접근을 비교합니다. 데이터는 저장하지 않습니다.

공격·방어 구현은 app.py의 lab 함수에서 확인할 수 있습니다. 이 앱은 교육용이며 운영 환경 인증 시스템의 예제가 아닙니다. 서버는 127.0.0.1에만 바인딩합니다.

## 검증

```powershell
python -m unittest -v
```
