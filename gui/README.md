# ARTINEX GUI

**ARTINEX** 는 통합 LLM 포렌식 파서 전체의 이름이다. 이 폴더(`gui/`)는 그 ARTINEX 를 **실행하고
분석 결과를 보여 주는 PyQt6 데스크톱 인터페이스**다.

GUI 는 통합 Runner(`integration/llm_forensic.py`)와 파서 6개를 **수정하지 않고** 호출한다.
GUI 자체는 포렌식 Parser 가 아니며 판정·Finding 을 만들지 않는다. 화면에 보이는 값은 모두
통합 Runner 가 만든 `timeline.csv` / `recovered_conversations.csv` / `integration_report.json` 에서 읽은 것이다.

```
E01 / DD  →  PyQt6 GUI  →  integration/llm_forensic.py  →  parsers.json 에 등록된 파서  →  공통 Schema
          →  timeline.csv · recovered_conversations.csv · unified.db · integration_report.json  →  GUI 표시
```

GUI 는 **통합 Runner 하나만** 실행한다. 개별 파서를 직접 실행하지 않고, 파서 실행 명령을 GUI 에 적어 두지도
않는다 — 파서 목록과 실행 방법의 source of truth 는 `integration/parsers.json` 이다. 새 파서가 등록되면
GUI 를 고치지 않아도 선택 목록에 나타난다.

**플러그인 기능은 포함하지 않는다.** 저장소에 `Autopsy_Addon/` 이 있어도 GUI 는 그것을 import·실행하지 않고
버튼·메뉴도 만들지 않는다 (`gui/tests/test_gui_integration.py::PluginIsolationTest` 가 이를 지킨다).

### 결과 폴더는 `<출력 폴더>\<evidence_id>`

통합 Runner 는 결과를 사용자가 고른 출력 폴더 **바로 아래가 아니라** `<out>\<evidence_id>\` 에 만든다
(`evidence_id` = 첫 세그먼트 앞 64 MiB SHA-256 의 앞 16자). GUI 는 이 경로를 계산하지 않고
Runner 의 `[Report]` 출력 경로에서 얻는다. 그 줄을 놓친 경우에만 출력 폴더를 훑어 결과 폴더를 찾는다.

```
<out>\<evidence_id>\
├─ timeline.csv · recovered_conversations.csv      ← 병합 결과 (팀 열 + provenance 열)
├─ unified.db · integration_report.json · evidence_manifest.json
└─ <parser_name>\                                  ← 파서별 원본 결과 + run.log
```

## 실행

저장소를 받은 폴더(`llm_forensic.py` 가 있는 `integration` 과 `gui` 가 나란히 보이는 곳)에서
PowerShell 을 열고 그대로 입력한다.

```powershell
powershell -ExecutionPolicy Bypass -File integration\setup.ps1   # 최초 1회: 파서와 GUI(PyQt6)가 함께 쓰는 .venv312 생성
integration\.venv312\Scripts\python.exe gui\main.py
```

저장소를 아직 받지 않았다면 먼저 받고 그 폴더로 이동한다.

```powershell
git clone https://github.com/WHS4-Erelem/LLM_Forensic_Parser.git
cd LLM_Forensic_Parser
```

`gui\main.py` 는 어느 폴더에서 실행해도 되지만, 위 상대 경로 예시는 저장소 루트를 기준으로 한다.

`setup.ps1` 은 uv 가 없으면 먼저 설치하고, 파서 6개의 의존성과 `gui\requirements.txt` 를 같은 `.venv312` 에 설치한다.
GUI 는 자신을 실행한 Python 으로 통합 Runner 를 띄운다. 다른 Python 에 PyQt6 만 설치해 GUI 를 띄워도 되지만, 파서는 항상
`.venv312` 에서 실행되므로 이 환경은 있어야 한다. 가상환경이 없으면 통합 Runner 는 각 파서를
`PARSER_EXECUTION_ERROR` 로 기록하고 끝까지 진행하며, GUI 는 그 실패를 Errors 탭에 보여 준다.

## 화면 흐름

| 단계 | 내용 |
|---|---|
| 1. Case Setup | 사건명 / 사건번호 / 분석가 / 메모. **새 분석 시작** 또는 **기존 분석 불러오기** |
| 2. Evidence Setup | 증거 이미지(E01·DD) · 결과 폴더 · Run All / Manual Selection(`--only`) · `--quick` · 입력 검증 |
| 3. Analysis Progress | 모듈별 상태, 실시간 stdout/stderr 로그, **분석 중단** 버튼. 진행률은 Runner 가 비율을 내지 않아 indeterminate |
| 4. Results Workspace | 왼쪽 개요 · 가운데 Overview/Timeline/Conversations/Artifacts/Errors · 오른쪽 근거 상세 |

Timeline 행을 선택하면 오른쪽 **근거 상세** 패널이 그 행의 값으로 즉시 바뀐다
(행위 · Verdict · Timestamp · Behavior Details · Artifact Path · Artifact Details · provenance).
Errors / Artifacts 표도 같은 패널을 쓴다.

**분석 중단** 은 실행 중인 Runner 프로세스를 kill 한다. 그 시점까지 Runner 가 이미 쓴 결과 파일은
그대로 남고 GUI 가 지우지 않는다 — 중단된 실행의 결과는 불완전할 수 있다.

Overview 의 **증거·무결성** 패널은 `evidence_manifest.json` / `integration_report.json` 에 기록된 값만
표시한다. GUI 는 해시를 다시 계산하지 않는다. `--quick` 으로 돌렸으면 `evidence_sha256` 이 `-` 이고,
그것이 정상 결과라는 사유를 함께 보여 준다.

## 파일

| 경로 | 역할 |
|---|---|
| `gui/main.py` | 진입점. QApplication · QSS 적용 |
| `gui/requirements.txt` | GUI 실행에 필요한 Python 의존성 |
| `gui/main_window.py` | TopBar + 4단계 화면, 결과 3분할 워크스페이스, 상세 패널 |
| `gui/integration_runner.py` | `QProcess` 로 통합 Runner 실행, 표준출력 파싱(모듈 상태·결과 폴더) |
| `gui/result_loader.py` | 결과 폴더 읽기 전용 로더 (CSV·보고서 → 지표·세션·아티팩트·오류) |
| `gui/case_manager.py` | `case_info.json` 저장·읽기 |
| `gui/styles.qss` | Dark DFIR 테마 (Teal accent). delegate 가 직접 그리는 색은 `main_window.DARK` 와 같은 값이다 |
| `gui/tests/test_gui_integration.py` | GUI ↔ 통합 계약 회귀 테스트 (CLI 인자 · console 파싱 · 결과 로딩 · 플러그인 격리) |

테스트는 GUI 와 같은 해석기(PyQt6 가 설치된 `.venv312`)로 돌린다.

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
integration\.venv312\Scripts\python.exe -B -m unittest discover -s gui/tests
```

## 통합 Runner 계약 (GUI 가 맞추는 대상)

| 항목 | 내용 |
|---|---|
| 실행 | `python -u integration/llm_forensic.py -i <IMAGE> -o <OUT> --registry <parsers.json> [--only a,b] [--quick]` |
| 파서 선택 | GUI 체크박스 → `--only` (전체 선택이면 `--only` 를 붙이지 않는다) |
| `--quick` | **전체·세그먼트 무결성 해시 계산만 생략**한다. 파서·아티팩트를 생략하지 않는다. 이때 `evidence_sha256` 이 `-` 로 남는 것은 정상이며 GUI 는 오류로 표시하지 않는다 |
| 종료코드 | `0` 전부 성공 / `1` 일부 파서 실패·계약 위반 / `2` 입력 실패 / `3` 통합 DB·병합 출력 오류 |
| `exit=1` | **전체 실패가 아니다.** 정상 파서의 `timeline.csv` 등이 존재하므로 GUI 는 결과 화면을 열고, 실패 파서만 Errors & Limitations 에 보여 준다 |
| `exit=2/3` | 병합 CSV 가 없어도 `integration_report.json` 이 있으면 결과 화면을 열어 오류를 보여 준다 |
| console | `[Evidence]` · `[Runner]` · `[DB]` · `[Timeline]` · `[Report]` · `[Summary]`. `[DB] FAILED` 는 파서를 하나도 실행하지 못한 상태라 화면에 바로 표시한다 |
| 파서 상태 | report 의 `success` / `failed` / `contract_violation` / `normalization_error` / `db_error` / `output_error` 를 그대로 쓴다. GUI 가 없는 상태를 만들지 않는다 |
| warning | `UNKNOWN_USER_BEHAVIOR` 같은 warning 은 경고다 — warning 하나로 파서를 Failed 로 바꾸지 않는다 |
| `--only` 재실행 | 같은 `evidence_id` 의 이전 결과가 병합본에 남을 수 있다. report 의 `preserved_from_previous_runs` 를 읽어 "이전 실행에서 남은 행" 으로 표시하고, 이번 실행 성공으로 세지 않는다 |

### 기존 결과 불러오기

사용자가 고른 폴더가 `<out>\<evidence_id>` 자체여도, 여러 `<evidence_id>` 를 가진 `<out>` 이어도 모두 열린다
(`find_result_dirs`). 기존 결과는 **읽기만** 한다.

## 포렌식 안전

- 증거 이미지는 **읽기만** 한다. 복사·변환·이름변경·삭제를 하지 않는다
  (입력 검증에서 앞 8바이트만 읽어 E01 시그니처를 확인한다).
- 새 파일은 결과 폴더에만 만든다. GUI 가 추가로 쓰는 파일은 `case_info.json` 하나뿐이고,
  Runner 산출물(`timeline.csv`, `recovered_conversations.csv`, `unified.db`,
  `integration_report.json`, `evidence_manifest.json`)은 다시 쓰지 않는다.
- CSV 헤더(끝 공백 포함)와 값은 바꾸지 않는다. 표의 열 이름만 화면용으로 정리해 보여 준다.
- Runner 가 주지 않는 값(진행률 %, 서비스 자동 탐지 결과, 아티팩트 분류)은 만들어 내지 않고
  `-` 또는 indeterminate 로 표시한다.

## 현재 제한

- 통합 Runner 에 **서비스 자동 탐지가 없다** → Run All / Manual Selection 만 제공한다.
- Runner 가 진행 비율을 내보내지 않는다 → 퍼센트 대신 현재 단계 문구 + indeterminate bar.
- 입력은 **이미지 파일만** 받는다 (`-i`). 아티팩트 폴더 입력은 Runner 가 지원하지 않는다.
- 내보내기 기능은 **결과 폴더 열기**와 상세 패널의 값 단위 **복사**(클립보드) 두 가지뿐이다.
  CSV/XLSX/HTML/PDF 로 다시 저장하는 기능은 없다 — 원본 CSV 는 결과 폴더에 그대로 있다.
- `근거 파일 위치 열기` 는 경로가 이 PC 에 실제로 존재할 때만 활성화된다
  (대부분의 Artifact Path 는 이미지 내부 경로라 비활성이 정상이다).
