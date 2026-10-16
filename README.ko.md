# ARTINEX

[English](README.md) · [한국어](README.ko.md)

Windows 디스크 이미지(E01 / raw)에서 LLM 서비스 6종의 사용 흔적을 찾아
**사용자 행위 타임라인**과 **복구된 대화 내용**을 뽑아내는 포렌식 파서 모음과, 그 6개를 한 번에 돌리는 ARTINEX 통합 실행기.
명령행 통합 실행기, GUI, Autopsy 애드온을 제공한다.
ARTINEX 는 이 통합 파서 전체의 이름이다 (저장소: `LLM_Forensic_Parser`).

WHS4 팀 프로젝트 「LLM 대화 내용 추출 및 사용자 행위 분석」 산출물.

## 구성

| 폴더 | 대상 | 진입점 | 실행 환경 |
|---|---|---|---|
| `ChatGPT_APP_Parser` | ChatGPT / Codex 데스크톱 앱 (MS Store `OpenAI.Codex`) | `run_parser.py` | Python 3.12 · pytsk3 · libewf-python |
| `ChatGPT_Web_Parser` | chatgpt.com (Chrome) | `python -m chatgpt_parser.cli` | Python 3.12 · pytsk3 · brotli · cramjam |
| `Claude_APP_Parser` | Claude 데스크톱 앱 | `run_parser.py` | Python 3.12 · pytsk3 · libewf-python · ccl-chromium-reader · zstandard |
| `Claude_Web_Parser` | claude.ai (Chrome) | `python -m claude_web_forensics` | Python 3.12 · dissect · ccl-chromium-reader |
| `Gemini_Web_Parser` | gemini.google.com (Chrome) | `gemini_parser.py` | Python 3.10+ · pytsk3 · libewf-python |
| `LMstudio_parser` | LM Studio (로컬 LLM) | `lmstudio_parser.py` | Python 3.12 · dissect |
| [`integration`](integration/README.ko.md) | ARTINEX 통합 실행기 : 위 6개를 순서대로 실행·검증·병합 | `llm_forensic.py` | 표준 라이브러리만 (파서는 공용 `.venv312`) |
| [`gui`](gui/README.ko.md) | ARTINEX GUI : 그래픽 화면에서 입력·실행·결과 확인 | `main.py` | 공용 Python 3.12 가상환경 · PyQt6 |
| [`Autopsy_Addon`](Autopsy_Addon/README.ko.md) | Autopsy 애드온 : 파서 실행 및 Autopsy 결과 등록 | `setup.ps1` (설치) | Autopsy 4.23.1 검증 · 외부 Python 3.12 |

파서마다 자세한 사용법과 판정 규칙은 각 폴더의 README 에 있다.

## 다운로드 및 설치 준비

Autopsy 사용자는 [Releases](https://github.com/WHS4-Erelem/LLM_Forensic_Parser/releases)에서 해당 버전의 안내에 따라 Autopsy용 배포 ZIP을 다운로드하고 전체 압축을 해제한다. 소스 코드로 작업하는 경우 저장소를 다운로드하거나 Git으로 복제할 수 있다. 이후 명령은 `integration`과 `Autopsy_Addon`이 있는 배포 폴더 또는 저장소 루트에서 시작한다.

- [저장소](https://github.com/WHS4-Erelem/LLM_Forensic_Parser)
- [Releases](https://github.com/WHS4-Erelem/LLM_Forensic_Parser/releases) : Autopsy용 배포 패키지와 버전별 설치 안내.

설치는 Windows PowerShell 기준이다. 최초 환경 준비에는 uv·Python·의존성 다운로드를 위한 네트워크가 필요하다. `setup.ps1`이 Python 3.12 가상환경을 준비한다.

## 공통 출력 계약

모든 파서는 같은 형식의 CSV 두 개를 낸다. 통합기는 이 계약을 어긴 결과를 적재하지 않는다.

- `timeline.csv` 7열: `Model, Timestamp, User_behavior, Behavior_details, Verdict, Artifact_path, Artifact_details`
- `recovered_conversations.csv` 10열: `Model, timestamp, conversation_uuid, conversation_title, message_uuid, parent_message_uuid, message order, role, content, Artifact_path`
- `Verdict` 는 `확정` 또는 `의심`, 시각은 `YYYY-MM-DD HH:MM:SS.ffffff KST`, 빈 값은 `-`
- `User_behavior` 는 팀 행위 분류 체계 `integration/user_behaviors.txt` 의 이름만 쓴다 (서비스명 없이). 목록 밖 이름은 통합기가 경고로 보고한다

## 빠른 시작 (ARTINEX 통합 실행)

`setup.ps1` 은 [uv](https://docs.astral.sh/uv/) 가 없으면 WinGet(`astral-sh.uv`)으로 먼저 설치하고, 파서 6개와 GUI(PyQt6)가 함께 쓰는 `.venv312` 를 만든다.

```powershell
cd integration
powershell -ExecutionPolicy Bypass -File setup.ps1

# 명령행 실행 (입력 경로를 실제 증거 이미지 경로로 변경)
.\.venv312\Scripts\python.exe llm_forensic.py -i "D:\Evidence\sample.E01" -o out

# GUI 실행
.\.venv312\Scripts\python.exe ..\gui\main.py
```

> 참고: 설치 중 AhnLab Safe Transaction 등의 보안 프로그램이 차단하면, 새 PowerShell 창에서 `uv --version`으로 설치 여부를 확인한 뒤 `setup.ps1`을 다시 실행한다. uv가 없거나 WinGet을 쓸 수 없다면 [공식 안내](https://docs.astral.sh/uv/getting-started/installation/)에 따라 먼저 설치한다.

결과는 `out\<evidence_id>\` 에 병합 `timeline.csv` · `recovered_conversations.csv` · `unified.db`(SQLite) ·
`evidence_manifest.json`(세그먼트별 SHA-256) · `integration_report.json`(파서별 상태·오류 목록) · 파서별 원본 결과 폴더로 남는다.
종료코드 0 전부 성공 / 1 일부 파서 실패·계약 위반 / 2 입력 실패 / 3 통합 DB·출력 오류. 자세한 내용은 [통합 실행기 안내](integration/README.ko.md)와 [GUI 안내](gui/README.ko.md).

## Autopsy 애드온

Autopsy에서 증거 이미지를 등록한 뒤 ARTINEX 모듈로 파서를 실행하고, 사용자 행위와 복구된 대화를 Autopsy에서 확인할 수 있다. 검증 환경은 Windows 11 · Autopsy 4.23.1이다.

[Releases](https://github.com/WHS4-Erelem/LLM_Forensic_Parser/releases)에서 **Autopsy용 배포 ZIP 전체**를 받아 압축을 해제한다. `Autopsy_Addon`, `integration`, 파서 폴더 6개를 함께 유지해야 한다. 애드온은 배포 폴더의 파서를 외부 Python 프로세스로 실행하므로, 설치 후 배포 폴더를 이동하거나 삭제하면 안 된다. 이동했다면 설치 스크립트를 다시 실행한다.

Autopsy를 종료하고 압축을 해제한 배포 패키지 루트에서 실행한다.

```powershell
# 영어 결과 (기본값)
powershell -ExecutionPolicy Bypass -File .\Autopsy_Addon\setup.ps1

# 한국어 결과
powershell -ExecutionPolicy Bypass -File .\Autopsy_Addon\setup.ps1 -Language ko
```

애드온은 결과를 **기본으로 영어로** 표시한다. `-Language ko`를 지정하면 한국어로 표시하며, 그 밖의 값은 오류로 설치를 중단한다. 영어 설정에서는 행위명, 판정, 행위 상세의 파서 고정 문구, 근거 상세의 라벨과 고정 문구, Timeline 설명, 애드온 안내 문구를 영어로 표시한다. 대화 내용, 제목, 프롬프트, 파일명, 경로, ID, 시각 등 증거 값은 복구된 그대로 두며(한국어 증거는 한국어 그대로), 파서의 CSV·JSON 파일은 수정하지 않는다. 전체 목록과 한계는 [표시 언어](Autopsy_Addon/README.ko.md#표시-언어)를 참고한다.

설치 후 Autopsy를 다시 열고 Ingest 모듈 목록에서 **ARTINEX**를 선택한다. 상세 설치 방법·결과 확인·제약 사항은 [국문 안내](Autopsy_Addon/README.ko.md)와 [영문 안내](Autopsy_Addon/README.md)를 참고한다.

## 개발 검증

정답 시트가 있는 경우에만 실행한다. 일반 분석에 필요한 단계는 아니다. 아래 명령은 `integration` 폴더 기준이며 `<evidence_id>`를 실제 결과 폴더명으로 변경한다.

```powershell
.\.venv312\Scripts\python.exe validation\verify_merged.py --timeline "out\<evidence_id>\timeline.csv" --key validation\scenario_keys\plain_2026-09-15.csv
```

## 라이선스

ARTINEX 자체 작성 코드(파서 6종, 통합 실행기, GUI, Autopsy 애드온)는 **AGPL-3.0-or-later**(GNU Affero General Public License v3.0 이상)로 배포한다.
Copyright (C) 2026 WHS4-Erelem contributors. 라이선스 전문은 [`LICENSE`](LICENSE).

`setup.ps1` 이 설치하는 외부 라이브러리(pytsk3, libewf-python, dissect.*, ccl_chromium_reader, PyQt6 등)는 ARTINEX 에 포함되지 않으며, 각자의 라이선스와 저작권 고지를 따른다.
