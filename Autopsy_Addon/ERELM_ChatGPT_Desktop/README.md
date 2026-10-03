# ERELM ChatGPT Desktop (Codex) Parser — Autopsy Add-on

Autopsy 안에서 ERELM 의 ChatGPT Desktop(Codex) 파서를 돌려, 사용자 행위와 대화를 Autopsy 결과 화면과 Timeline 에 올리는 Data Source Ingest Module 입니다.

| | |
|---|---|
| Module type | Data Source Ingest Module (Python / Jython) |
| Minimum Autopsy version | 4.23 (4.23.1 에서 확인) |
| Operating system | Windows (파서의 Prefetch 해석이 Windows 전용) |
| Author | WHS4 ERELM (에레렘) |
| Source | https://github.com/WHS4-Erelem/LLM_Forensic_Parser — `Autopsy_Addon/ERELM_ChatGPT_Desktop`, `ChatGPT_APP_Parser` |
| Version | 0.1.0 (파서 cxparser 0.3.11 이상) |

## 구조 (thin adapter)

```
E01 / raw → Autopsy / TSK → FileManager → [이 모듈] → 외부 CPython: ChatGPT_APP_Parser → timeline.csv / recovered_conversations.csv → Blackboard · Timeline · Report
```

- **Autopsy 가 하는 일**: 이미지 열기, 파일시스템 해석, 파일 찾기, 결과 표시.
- **이 모듈이 하는 일**: Codex 관련 파일만 사건 폴더(`ModuleOutput/ERELM_ChatGPT_Desktop/ds_<id>/export`)에 꺼내고, Autopsy 가 이미 읽어 둔 MFT 시각을 `_host_metadata.json` 으로 같이 넘긴 뒤 파서를 실행하고, 결과 CSV 를 Blackboard 에 올립니다.
- **ERELM 파서가 하는 일**: 아티팩트 해석, 아티팩트 간 대조, 사용자 행위 판정. 파서는 디스크 이미지를 열지 않습니다.

Autopsy 의 Python 은 Jython 2.7 이라 CPython 3 파서를 직접 import 하지 않고 별도 프로세스로 실행합니다. Ingest 를 취소하면 파서 프로세스도 종료됩니다. 모듈은 전역 상태를 쓰지 않습니다(ingest job 마다 새 인스턴스).

## 설치

1. 파서 실행 환경 준비 (한 번): 저장소의 `integration/setup.ps1` 로 `.venv312` 를 만들거나, Python 3.10~3.12 에 `ChatGPT_APP_Parser/requirements.txt` 를 설치합니다.
2. 이 폴더(`ERELM_ChatGPT_Desktop`)를 Autopsy 의 Python 모듈 폴더에 복사합니다. Autopsy 메뉴 **Tools → Python Plugins** 가 그 폴더를 엽니다 (4.23.1 기본: `%APPDATA%\autopsy\dev\python_modules`).
3. `erelm_config.example.json` 을 `erelm_config.json` 으로 복사하고 두 경로를 적습니다 (`/` 로 써도 됩니다).
   ```json
   {
     "python": "C:\\path\\to\\llm-parser\\integration\\.venv312\\Scripts\\python.exe",
     "parser_dir": "C:\\path\\to\\llm-parser\\ChatGPT_APP_Parser"
   }
   ```
   환경변수 `ERELM_PYTHON`, `ERELM_PARSER_DIR` 로도 줄 수 있습니다. 파서 폴더를 모듈 폴더 안에 `ChatGPT_APP_Parser` 로 같이 넣으면 `parser_dir` 는 생략할 수 있습니다.
4. Autopsy 를 다시 시작합니다.

## 사용

1. 사건을 만들고 Data Source 로 디스크 이미지(E01, raw 분할 `.001`)를 추가합니다.
2. Ingest Module 선택 화면에서 **ERELM ChatGPT Desktop (Codex) Parser** 를 체크합니다. 다른 모듈은 필요 없습니다.
3. 끝나면 아래에서 결과를 봅니다.

| 위치 | 내용 |
|---|---|
| Data Artifacts → **LLM User Behavior (ERELM)** | `timeline.csv` 한 행 = 한 건. Timestamp (KST), LLM Service, User Behavior, Behavior Details, Verdict(확정/의심), Artifact Path, Artifact Details. 근거 파일(rollout, logs_2.sqlite 등)에 붙습니다 |
| Data Artifacts → **Messages** | 복원된 대화. 대화 UUID = Thread ID, 제목 = Subject, 사용자 발화 = Outgoing |
| **Timeline** | 시각이 있는 행위는 `[ChatGPT Desktop] <행위> (<판정>): <상세>` 설명으로, 대화는 Messages 로 표시 |
| Reports | 파서 원본 산출물 `timeline.csv`, `recovered_conversations.csv`, `cx_result.json` |
| Ingest Inbox | 건수 요약. Codex 흔적이 없는 이미지는 "No ChatGPT Desktop (Codex) files" 한 줄 |

같은 Data Source 에 다시 돌려도 결과가 중복으로 쌓이지 않습니다.

명령행(화면 없이) 실행도 됩니다.

```
autopsy64.exe --createCase --caseName=case1 --caseBaseDir=C:\cases --addDataSource --dataSourcePath=C:\evidence\image.001 --runIngest
```

## 한계

- 삭제된 파일은 꺼내지 않습니다(같은 경로의 현존 파일과 겹치지 않게). 삭제된 rollout 복구는 파서를 이미지에 직접 돌릴 때만 됩니다.
- `$UsnJrnl` 은 넘기지 않습니다. 로그인은 인증 로그만으로 판정되고(의심), 계정 전환·앱 삭제처럼 USN 대조가 필요한 행위는 나오지 않습니다.
- 다운로드 판정에 쓰는 대상 파일 메타데이터는 사용자 폴더의 `Downloads`, `Desktop`, `Documents` 아래만 넘깁니다. 다른 위치에 저장한 파일은 시각 없이 나오거나 빠집니다.
- 논리 파일 세트(폴더를 Data Source 로 추가)에는 MFT 시각이 없어 설치·다운로드 판정이 빠집니다.

## 파일

- `ERELM_ChatGPT_Desktop.py` — 모듈 본체
- `erelm_config.example.json` — 설정 예시. 복사해서 `erelm_config.json` 으로 쓴다 (PC마다 다른 경로라 저장소에는 예시만 둔다)
- `README.md` — 이 문서
