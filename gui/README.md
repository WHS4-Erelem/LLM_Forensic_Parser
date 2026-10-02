# elelem LLM Forensic Parser — PyQt6 GUI

기존 통합 Runner(`integration/llm_forensic.py`)와 파서 6개를 **수정하지 않고** 호출하는 데스크톱 UI다.
GUI 는 새 포렌식 Parser 가 아니며, 판정·Finding 을 만들지 않는다. 화면에 보이는 값은 모두
통합 Runner 가 만든 `timeline.csv` / `recovered_conversations.csv` / `integration_report.json` 에서 읽은 것이다.

```
E01 / DD  →  PyQt6 GUI  →  integration/llm_forensic.py  →  파서 6개  →  공통 Schema
          →  timeline.csv · recovered_conversations.csv · unified.db · integration_report.json  →  GUI 표시
```

## 실행

```powershell
cd C:\Users\ksy_0\Documents\LLM_Forensic_Parser
python -m pip install PyQt6          # 설치되어 있으면 생략
python gui\main.py
```

파서를 실제로 돌리려면 저장소 README 대로 파서별 가상환경이 먼저 있어야 한다
(`integration\setup.ps1` → `.venv312`, `.venv314`). 가상환경이 없으면 통합 Runner 는 각 파서를
`PARSER_EXECUTION_ERROR` 로 기록하고 끝까지 진행하며, GUI 는 그 실패를 Errors 탭에 보여 준다.

## 화면 흐름

| 단계 | 내용 |
|---|---|
| 1. Case Setup | 사건명 / 사건번호 / 분석가 / 메모. **새 분석 시작** 또는 **기존 분석 불러오기** |
| 2. Evidence Setup | 증거 이미지(E01·DD) · 결과 폴더 · Run All / Manual Selection(`--only`) · `--quick` · 입력 검증 |
| 3. Analysis Progress | 모듈별 상태, 실시간 stdout/stderr 로그. 진행률은 Runner 가 비율을 내지 않아 indeterminate |
| 4. Results Workspace | 왼쪽 개요 · 가운데 Overview/Timeline/Conversations/Artifacts/Errors · 오른쪽 근거 상세 |

Timeline 행을 선택하면 오른쪽 **근거 상세** 패널이 그 행의 값으로 즉시 바뀐다
(행위 · Verdict · Timestamp · Behavior Details · Artifact Path · Artifact Details · provenance).
Errors / Artifacts 표도 같은 패널을 쓴다.

## 파일

| 경로 | 역할 |
|---|---|
| `gui/main.py` | 진입점. QApplication · QSS 적용 |
| `gui/main_window.py` | TopBar + 4단계 화면, 결과 3분할 워크스페이스, 상세 패널 |
| `gui/integration_runner.py` | `QProcess` 로 통합 Runner 실행, 표준출력 파싱(모듈 상태·결과 폴더) |
| `gui/result_loader.py` | 결과 폴더 읽기 전용 로더 (CSV·보고서 → 지표·세션·아티팩트·오류) |
| `gui/case_manager.py` | `case_info.json` 저장·읽기 |
| `gui/styles.qss` | Light DFIR 테마 (Teal accent) |

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
- Export 는 "결과 폴더 열기"만 있다. CSV/XLSX/HTML/PDF 내보내기는 미구현.
- `근거 파일 위치 열기` 는 경로가 이 PC 에 실제로 존재할 때만 활성화된다
  (대부분의 Artifact Path 는 이미지 내부 경로라 비활성이 정상이다).
