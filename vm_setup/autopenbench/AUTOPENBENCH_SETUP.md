# AutoPenBench 로컬 구동 — 셋업·상태·재개 가이드

외부 침투테스트 벤치마크 **AutoPenBench**(arXiv:2410.03225, MIT)를 격리 VirtualBox VM 안에서
**로컬 Ollama**로 구동하는 진행 기록. Cochise(§6.16)에 이은 두 번째 외부 하네스 외적타당성 검증.

## 환경 (VM: pentest-lab, Ubuntu 24.04)
- 클론: `/home/lab/labs/autopenbench` (github.com/lucagioacchini/auto-pen-bench)
- 설치 완료: `python3 -m venv .venv && . .venv/bin/activate && pip install -e .`
  (openai 1.51, instructor 1.5, paramiko 3.5, pydantic 2.9), `.env`(AUTOPENBENCH/KALISCRIPTS) 생성.
- apt: cmake, docker-compose(v1). docker는 lab 그룹으로 sudo 없이 동작(로그인 셸).
- LLM: 호스트 Ollama를 **SSH 역터널**로 `127.0.0.1:11500`에 노출 → 러너가 `OPENAI_BASE_URL`로 지향.

## 비트롯 수정 (중요)
`benchmark/machines/kali/Dockerfile`이 **죽은 Kali 키링 URL**(`kali-archive-keyring_2025.1_all.deb`,
404)에서 실패 + 그 뒤 거대 metapackage 설치/full-upgrade. 베이스 이미지
`lucagioacchini/kali-linux-headless:latest`에 **sshd·nmap·nc·python3·metasploit·키링이 이미 존재**함을
확인 → 최소 Dockerfile(`kali_Dockerfile.min`, 이 폴더)로 교체해 즉시 빌드. 원본은 VM에
`Dockerfile.orig.bak` 백업. (apt 서명키만 낡아 `apt update`는 경고 뜨지만 런타임 도구엔 영향 없음.)

## 구동 방법
1. 이미지 빌드(과제 1개만):
   `docker-compose -f benchmark/machines/docker-compose.yml -f benchmark/machines/in-vitro/access_control/docker-compose.yml build`
   (kali:latest 8.6GB + in-vitro_access_control_vmN 빌드)
2. 러너(`run_autopenbench_task.py`, 이 폴더 → VM의 autopenbench 루트에 `_run.py`로 복사):
   `cd ~/labs/autopenbench && . .venv/bin/activate && APB_CATEGORY=access_control APB_IDX=0 python _run.py`
   - 러너가 `OPENAI_BASE_URL=http://127.0.0.1:11500/v1`, 모델 `llama3.1:8b`로 에이전트·평가자 로컬화,
     평가자 하드코딩 `gpt-4o`는 `evaluator.model` override, 툴콜 실패 시 JSON 모드 폴백.

## 현재 상태 (2026-11-18)
- ✅ **인프라 end-to-end 로컬 구동 확인**: `driver.reset()`이 네트워크 생성 + kali_master +
  대상 컨테이너(Debian, student 사용자, sshd) 빌드·기동, 과제·마일스톤 로드 정상.
- ❌ **에이전트 LLM 단계 실패(유일한 블로커)**: instructor 구조화출력(복잡한 Union
  `ActionModel[ExecuteBash|SSHConnect|FinalAnswer]`)을 로컬 llama3.1이 **인스턴스가 아니라 JSON
  스키마를 반환**해 파싱 실패(TOOLS·JSON 모드 둘 다 `InstructorRetryException: action field required`).
  → §6.16 Cochise tool-calling 소견과 **동일 계열**: GPT-4o 전제로 만든 하네스가 로컬 소형모델의
  구조화출력을 못 받는다.

## 다음 세션 재개 — 할 일
1. **경량 JSON 액션 파서로 우회**(instructor 대신): 모델에 `{"tool":"execute_bash|ssh_connect|final_answer",
   "args":{...}}` 평문 JSON을 요청→수동 파싱→해당 pydantic 인스턴스 생성→`driver.step(action)`.
   도구 필드: ExecuteBash(machine_ipaddr, cmd), SSHConnect(ssh_ipaddr, ssh_port, ssh_username,
   ssh_password), FinalAnswer(flag). 이러면 로컬 모델로도 실제 nmap/ssh 궤적 확보 가능.
   - 대안: instructor Mode.MD_JSON / JSON_SCHEMA 시도, 또는 더 능력있는 모델(§6.19처럼 모델 의존적).
2. 성공 시 궤적·마일스톤 도달을 논문 §6.16b(외부 벤치마크 AutoPenBench)로 반영.
3. **보안 전제 유지**: in-vitro는 합성 취약앱(실 CVE 아님). real-world/cve는 **미실행**(코드 감사만).
   공격 트래픽은 VM 내부 격리 docker 네트워크. 재부팅 금지(VM/터널/표적 유지 중).
