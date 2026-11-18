# 금융권 API 공격 판단 실험 (OWASP 업무로직) — 논문 §6.17

최근 금융권 해킹의 지배적 벡터는 SQLi처럼 페이로드 시그니처가 있는 공격이 아니라,
**완전히 정상처럼 보이는 API 업무로직 공격**(BOLA, 파라미터 조작 등)이다. 2025 API
위협 보고서(Thales/Imperva)는 금융을 API 공격 1위 표적으로, BOLA·파라미터 조작을
"시그니처 기반 도구와 거친 rate limit이 놓치는" 주 벡터로 지목한다. 이를 방어자가
**판단할 수 있는지**를, 기존 §6.12 방법론(규칙 vs LLM)을 그대로 확장해 측정한다.

## 구성 (코드)
- `agent_lab/fin_api_target.py` — 합성 금융 API(계정·잔액·프로필·이체), **loopback 전용**,
  요청별 **그라운드 트루스** 로깅. 심은 취약점:
  - API1 **BOLA/IDOR**: `GET /api/accounts/{id}` 객체권한 미검증
  - API3 **Mass assignment**: `POST /api/profile`가 role·balance·is_admin까지 적용
  - API5 **BFLA**: `GET /api/admin/users` 역할 미검증
  - API6 **비즈니스-플로우 남용**: `POST /api/transfer` 음수·초과·리플레이 허용
- `agent_lab/fin_api_attacker.py` — benign + 5개 공격 세션(타깃 BOLA / 스크래핑 BOLA /
  mass assignment / BFLA / transfer abuse). 전부 loopback HTTP.
- `agent_lab/fin_api_defender.py` — 5개 탐지기:
  - `rule_syntactic` (SQLi/XSS 시그니처)
  - `rule_context` (소유권·역할·플로우 모델 보유)
  - `rule_behavioral` (소유권 라벨 없이 관측 행동만: 다수 계정·admin 접근·음수 이체 등)
  - `llm_detect(reveal_owner=True)` (맥락 제공)
  - `llm_detect(reveal_owner=False)` (맥락 미제공, 행동만 → 추론)
- `experiments/run_fin_api_detection.py` — 표적 기동→세션 생성→채점(§6.12식 표).
- `agent_lab/test_fin_api.py` — 23 assertions.

## 재현
```
python agent_lab/test_fin_api.py          # 23/23
python experiments/run_fin_api_detection.py --n-rules 12 --n-llm 6 --model qwen2.5-coder:14b
```
결과: `research/fin_api_runs/<timestamp>/results.json`

## 결과 (qwen2.5-coder:14b, 규칙 n=12 / LLM n=6, temp 0)

| 세션 (OWASP) | 시그니처 | 맥락규칙 | 행위규칙 | LLM(맥락) | LLM(행위) |
|---|---|---|---|---|---|
| 정상 (오탐) | 0/12 | 0/12 | 0/12 | 0/6 | 0/6 |
| **타깃형 BOLA** (API1) | 0/12 | 12/12 | **0/12** | 6/6 | **6/6** |
| 스크래핑 BOLA (API1) | 0/12 | 12/12 | 12/12 | 6/6 | 6/6 |
| Mass assignment (API3) | 0/12 | 12/12 | 12/12 | 6/6 | 6/6 |
| BFLA (API5) | 0/12 | 12/12 | 12/12 | 6/6 | 6/6 |
| 비즈니스-플로우 남용 (API6) | 0/12 | 12/12 | 12/12 | 6/6 | 6/6 |

Wilson 95% CI: 0/12=[0,0.24], 12/12=[0.76,1.0], 0/6=[0,0.39], 6/6=[0.61,1.0].

## 핵심 발견 — AI가 고유 가치를 내는 지점
1. **시그니처 규칙은 전 공격 0/12** — 요청이 정상 형태라 매칭할 문자열이 없다
   (§6.12 탈취 자격증명 공백의 API 버전).
2. **관측 가능한 행동 이상**이 있는 공격(스크래핑·mass assignment·BFLA·음수 이체)은
   행위 규칙과 LLM 모두 탐지(12/12·6/6).
3. **타깃형 BOLA**(다른 계정 1~2개만 조용히 읽기)는 볼륨 이상이 없어 **행위 규칙이
   실패(0/12)**하는데, **LLM은 소유권 라벨을 못 받은 행위 모드에서도 6/6으로 탐지**했다
   — "한 사용자가 자기 것이 아닌 계정 번호들을 읽는다"는 맥락을 추론하면서 정상 세션은
   오탐 0으로 통과. → **시그니처·임계값 규칙이 구조적으로 실패하는 미묘한 인가 위반에서
   LLM의 맥락 추론이 고유한 탐지 가치를 낸다.**

§6.12의 "crisp 시그니처는 규칙 > 소형 LLM"과 합치면: **공격이 시그니처로 정의되면 규칙,
인가-맥락으로 정의되면 LLM(또는 맥락 모델)**.

## 방어자 함의
금융 API에는 WAF/시그니처만으로 불충분하다 — 객체·기능 권한과 거래 의미를 **요청 시점에
맥락으로** 검증해야 한다(서버측 객체권한 검사, 필드 allowlist, 역할 검사, 거래 한도·멱등성).
명시적 맥락 모델이 없거나 임계값 규칙이 놓치는 **미묘한 인가 위반(타깃 BOLA)**에서는 LLM의
맥락 추론이 보강 탐지로 유효(오탐 0). "탐지 이후"(권한 최소화·재인증·거래 차단)는 §6.13/6.14와
동일하게 필요하며, 운영에선 LLM 지연·비용(§6.11)을 함께 고려.

## 홀드아웃·일반화 재검증 (§6.18)
설계에 쓰지 않은 패턴으로 재평가(`experiments/run_fin_api_holdout.py`, 알려진 레이블로 채점).

| 홀드아웃 세션 | 레이블 | 시그니처 | 맥락 | 행위 | LLM(맥락) | LLM(행위) |
|---|---|---|---|---|---|---|
| 최소 BOLA (1계정) | 공격 | 0/12 | 12/12 | 0/12 | 6/6 | 6/6 |
| 크리덴셜 스터핑 (API4) | 공격 | 0/12 | 0/12 | 12/12 | 6/6 | 6/6 |
| **신규필드 mass assignment** | 공격 | **0/12** | **0/12** | **0/12** | **6/6** | **6/6** |
| 정상: 본인계정 by-id | 정상 | 0/12 | 0/12 | 0/12 | 0/6 | **6/6 (오탐)** |
| 정상: 이메일 수정 | 정상 | 0/12 | 0/12 | 0/12 | 0/6 | 0/6 |

**발견 1 — 규칙 취약성 vs LLM 일반화:** `isAdmin`·`account_limit`처럼 고정 allowlist에 없는
신규 권한 필드 mass assignment는 **맥락·행위 규칙 모두 0/12**로 놓쳤으나 **LLM은 6/6** 탐지.

**발견 2 — 자기정정(행위모드 LLM의 오탐 대가):** 소유권 없는 행위모드 LLM은 본인 계정을 숫자
id로 읽는 정상 행위를 **6/6 오탐**("숫자 id 접근=의심" 휴리스틱). 반면 **맥락 제공 LLM(llm_ctx)만
공격 전부 탐지 + 오탐 0**. → **실무 결론: LLM 탐지엔 반드시 인가 맥락(소유권·역할)을 제공하라.**

재현: `python experiments/run_fin_api_holdout.py --n-rules 12 --n-llm 6 --model qwen2.5-coder:14b`

## 한계
합성 표적 1개·temp 0(통계 아님). 표적·공격·탐지기·홀드아웃을 저자가 작성(규칙·프롬프트를 아는
상태) → **완전 독립(제3자 blind 작성)은 §6.13식으로 후속**. n=12/6. 과다정보노출은 미구현.
