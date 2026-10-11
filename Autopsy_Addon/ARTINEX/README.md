# ARTINEX — Autopsy Add-on

Autopsy 안에서 ARTINEX 의 LLM 포렌식 파서 6종(ChatGPT Desktop · ChatGPT Web · Claude Desktop · Claude Web · Gemini Web · LM Studio)을 돌려,
사용자 행위와 복원 대화를 Autopsy 결과 화면과 Timeline 에 올리는 Data Source Ingest Module 입니다.

| | |
|---|---|
| Module type | Data Source Ingest Module (Python / Jython) |
| Minimum Autopsy version | 4.23 (4.23.1 에서 확인) |
| Operating system | Windows (파서들의 Prefetch 해석·Zone.Identifier 스트림 읽기가 Windows 전용) |
| Author | WHS4 ERELM (에레렘) |
| Source | https://github.com/WHS4-Erelem/LLM_Forensic_Parser — `Autopsy_Addon/`, 파서 폴더 6개 |
| Version | 0.4.1 |
| External parsers | ChatGPT_APP_Parser 0.3.31 · ChatGPT_Web_Parser 0.2.0 · Claude_APP_Parser 1.5.0 · Claude_Web_Parser 1.0.0 · Gemini_Web_Parser 1.4.8.6 · LMstudio_parser (0.4.21 Build 2 기준) |

## 구조 (thin adapter)

```
E01 / raw → Autopsy / TSK → FileManager → [이 모듈] → 볼륨 루트 모양의 추출 폴더 → 외부 CPython 파서 6종 (각자의 폴더 입력 모드)
                                                   → timeline.csv / recovered_conversations.csv → 계약 검사 → Blackboard · Timeline · Report
```

- **Autopsy 가 하는 일**: 이미지 열기, 파일시스템 해석, 파일 찾기, 결과 표시.
- **이 모듈이 하는 일**: 통합 실행(`integration/parsers.json`)에서 각 파서가 실제로 읽는 파일만 작업 폴더(`<작업 루트>/<사건>_ds_<id>/<실행시각>/vol<fs>/export`)에
  볼륨 기준 경로(`Users/...`, `Windows/Prefetch/...`, `ProgramData/...`, `$Recycle.Bin/...`) 그대로 꺼내고, 파서마다 실행 근거가 있는 볼륨에서만 실행한 뒤
  결과 CSV 를 팀 계약(헤더·열 수·시각·판정·빈 셀)으로 검사해 Blackboard 에 올립니다. 여러 파서가 쓰는 파일은 한 번만 꺼내고,
  파서마다 그 파서가 읽는 파일만 하드 링크로 모은 입력 폴더(`vol<fs>/in_<파서>`)를 넘깁니다 — 다른 파서용 공통 입력을 자기 입력으로 오인하지 않게.
- **ARTINEX 파서가 하는 일**: 아티팩트 해석, 아티팩트 간 대조, 사용자 행위 판정, 대화 복구. 파서는 디스크 이미지를 열지 않습니다.

Autopsy 의 Python 은 Jython 2.7 이라 CPython 3 파서를 직접 import 하지 않고 별도 프로세스로 실행합니다 (파서당 상한 1시간). 모듈은 전역 상태를 쓰지 않고(ingest job 마다 새 인스턴스),
실행마다 새 작업 폴더를 쓰므로 이전 추출 파일·CSV 와 섞이지 않습니다.

## 설치

```
powershell -ExecutionPolicy Bypass -File <저장소>\Autopsy_Addon\setup.ps1
```

이 한 번으로 실행 환경 준비와 애드온 설치가 끝납니다. 스크립트가 하는 일:

1. 자기 위치로 저장소 루트를 찾고 파서 진입점 6개를 확인합니다.
2. 통합파서와 같은 전용 가상환경 `integration\.venv312\Scripts\python.exe` 만 씁니다 (시스템 Python·`py` 런처·PATH 의 Python 은 찾지 않습니다).
   가상환경이고 Python 3.12 이며 파서 의존성의 주요 모듈(pytsk3·pyewf·brotli·cramjam·zstandard·pycryptodome·ccl_simplesnappy·dissect.ntfs·dissect.fve·
   dissect.evidence·dissect.volume·ccl_chromium_reader)을 import 할 수 있는지 검사합니다. requirements 의 버전까지 대조하지는 않습니다.
   - 검사를 통과하면 그대로 씁니다 (다시 설치하지 않음).
   - 가상환경이 없거나 검사에 실패하면 `integration\setup.ps1` 을 불러 `.venv312` 를 다시 만듭니다. 그 스크립트에 필요한 `uv` 가 없으면 공식 설치 스크립트
     (`https://astral.sh/uv/install.ps1`)로 설치하고 현재 프로세스 PATH 에 넣습니다.
   - 준비 뒤 종료 코드와 실제 가상환경·의존성을 다시 검사하고, 실패하면 원인을 표시하고 **설치하지 않고** 끝납니다.
3. Autopsy 플러그인 폴더를 찾습니다: 설치된 Autopsy 의 `etc\autopsy.conf` `default_userdir` + `python_modules`. 그것으로 못 찾을 때만 `%APPDATA%\autopsy` 아래를 찾고,
   후보가 0개이거나 여러 개일 때만 묻습니다. 직접 주려면 `-PluginDir <python_modules 폴더>`.
4. 대체 작업 위치를 준비합니다. 실제 작업 위치는 설치 때 정하지 않고 Ingest 때 실제 사건 경로로 정합니다(아래 '작업 위치').
   여기서는 사건 폴더를 쓸 수 없을 때 쓸 대체 위치(기존 설정의 `work_dir`, 없으면 `C:\artinex_work`)를 만들고 쓰기·ADS 를 시험해 결과만 표시합니다.
   Autopsy 의 사건 기본 폴더는 보지 않습니다 — 실제 사건은 다른 곳에 만들 수 있기 때문입니다.
5. 모듈 파일만 플러그인 폴더(`<python_modules>\ARTINEX`)에 복사하고 `artinex_config.json` 을 갱신합니다. 기존 설정(`work_dir`·`keep_export` 등)은 그대로 두고 `python`(전용 가상환경 python.exe 의 절대 경로)·`repo_root` 만 바꿉니다.
   기존 설정이 JSON 으로 읽히지 않으면 덮어쓰지 않고 멈춥니다. 이름을 바꾸기 전 모듈(`ERELM_LLM_Parser`, `ERELM_ChatGPT_Desktop`)이 있으면 지우고, 새 설정이 없으면 옛 `erelm_config.json` 의 설정(`work_dir` 등)을 옮겨 옵니다.

끝나면 실제 Python, 플러그인 폴더, 설정 파일, 대체 작업 위치를 표시합니다. **Autopsy 를 다시 시작한 뒤** Ingest 모듈 목록에서 **ARTINEX** 를 선택합니다.

예외 상황
- 네트워크가 막혀 `uv`·패키지를 받을 수 없으면 환경 준비가 실패하고 설치를 멈춥니다. 네트워크가 되는 곳에서 `integration\setup.ps1` 을 실행해 `.venv312` 를 준비한 뒤 다시 실행합니다.
- `integration\setup.ps1` 은 기존 `.venv312` 를 지우고 새로 만듭니다 — 검사를 통과하지 못한 환경일 때만 부릅니다.
- 설정 파일 위치: `<python_modules>\ARTINEX\artinex_config.json` (`python`, `repo_root`, 선택 `work_dir`(대체 작업 위치)·`keep_export`). 환경변수 `ARTINEX_PYTHON`·`ARTINEX_REPO_ROOT`·`ARTINEX_WORK_DIR` 가 있으면 그 값이 우선합니다.
- 저장소 안의 `Autopsy_Addon/ARTINEX` 를 그대로 플러그인 폴더로 쓰면(정션 등) 설정 없이 저장소와 `integration/.venv312` 를 씁니다.

## 사용

1. 사건을 만들고 Data Source 로 디스크 이미지(E01, raw, raw 분할 `.001`)를 추가합니다.
2. Ingest Module 선택 화면에서 **ARTINEX** 를 체크합니다. 다른 모듈은 필요 없습니다.
3. 끝나면 아래에서 결과를 봅니다.

| 위치 | 내용 |
|---|---|
| Data Artifacts → **LLM User Behavior (ARTINEX)** | 파서별 `timeline.csv` 한 행 = 한 건. Timestamp (KST), LLM Service(`Model` 열), User Behavior, Behavior Details, Verdict(확정/의심), Artifact Path(CSV 값 그대로), Artifact Details. 근거 파일에 붙습니다 (아래 '증거 연결') |
| Data Artifacts → **Messages** | 복원된 대화. Message Type = 파서 이름, 대화 UUID = Thread ID, 제목 = Subject, 사용자 발화 = Outgoing |
| **Timeline** | 시각이 있는 행위는 `[<파서>] <행위> (<판정>): <상세>` 설명으로, 대화는 Messages 로 표시 |
| Reports | 파서별 `timeline.csv`, `recovered_conversations.csv` 와 파서 고유 JSON(`cx_result.json`, `result.json`, `gemini_results.json`) |
| Ingest Inbox | 파서·볼륨별 상태 한 줄씩 (아래 표) |

| Inbox 상태 | 뜻 |
|---|---|
| `N behaviors, M messages (ran on file 3, package folder 1 …)` | 정상. 괄호는 실행 근거 (`file`, `deleted file`, `deleted trace`, `package folder`) |
| `not run (no input it reads)` | 그 볼륨에서 실행 조건에 해당하는 관련 입력을 찾지 못해 실행하지 않음 (`export_skipped.txt` 에 `parser_not_run`). 관련 행위가 없다는 판정이 아님 — USN 에만 남은 활동은 확인하지 않은 상태 |
| `no artifacts` | 실행했지만 흔적 없음 (Claude Desktop exit 2 `ARTIFACT_NOT_FOUND`) |
| `failed (exit N, see run.log)` / `output missing` / `CSV contract violation (...)` | 그 파서만 실패. 다음 파서는 계속 실행 |
| `failed at run/csv/post/report (오류) - partially registered …` | 그 단계에서 예외. 실패 전에 등록된 건수를 함께 표시 |
| `[incomplete input: N not exported …]` | 그 파서가 읽는 입력 중 꺼내지 못한 것이 있음 — 추출 오류, 1GB 초과 `$MFT`·`$J`(`big`), 메타데이터 2만 개 제한 초과(`meta_limit`), History 다운로드 목록을 읽지 못함(`history_targets_failed`), 다른 볼륨 후보가 여럿(`history_target_ambiguous`). 정상 완료와 구분 (Inbox 경고). 상한·제한 초과는 사유도 함께 표시 (`불완전 입력: $MFT 또는 $J가 1GB 상한을 초과하여 분석 입력에서 제외됨`, `불완전 입력: Downloads·Desktop·Documents 메타데이터가 20000개 제한을 초과하여 일부 수집되지 않음`) — 그 입력을 읽는 파서에만. 나머지 입력으로 분석·등록은 계속함. History 대상 파일이 이미지에 없는 것(`history_target_not_found`)은 이미지 입력도 같으므로 누락으로 세지 않음 |
| `(N linked to data source, see link_notes.txt)` | 근거 파일을 하나로 정할 수 없어 Data Source 에 붙인 행 수 |
| `Cancelled …` | Ingest 취소. 실패가 아니며 뒤 파서는 실행하지 않음 |
| 요약 끝의 `extracted files removed / kept (…)` | 작업 폴더의 추출본을 지웠는지, 남겼다면 왜인지와 그 위치 |

**작업 위치** — Zone.Identifier·`$J` 를 실제 대체 데이터 스트림(ADS)으로 넘겨야 하므로 Ingest 실행마다 쓰기와 ADS 생성을 시험해 고릅니다.
1. 실제 사건의 `ModuleOutput\ARTINEX` 를 우선 사용합니다.
2. 그곳에서 파일 쓰기 또는 ADS 사용이 불가능하면(예: exFAT 외장 드라이브의 사건) 대체 위치 `C:\artinex_work`(설정 `work_dir` 로 바꿀 수 있음)를 사용합니다. `work_dir` 가 있어도 사건 폴더를 먼저 확인합니다. 다른 드라이브를 자동으로 고르지 않습니다.
3. 두 위치 모두 사용할 수 없으면 원인을 Inbox(오류)·Autopsy 로그에 남기고 실행을 중단합니다.

고른 위치와 대체 위치를 쓴 사유는 Autopsy 로그(`work root …`)에 남습니다. 대체 위치를 쓰면 Report 사본은 사건 폴더 `ModuleOutput\ARTINEX\ds_<id>\…` 에 복사해 등록합니다.

**작업 폴더** (`<작업 위치>\<사건>_ds_<id>\<실행시각>\`, 실행마다 새로 만듦)

| 안의 것 | 내용 | 실행 뒤 |
|---|---|---|
| `vol<fs>\export\` | Autopsy 에서 꺼낸 원본 파일·`$MFT`·`$J`·`_host_metadata.json` (용량 대부분) | 정상 완료면 자동 삭제 |
| `vol<fs>\in_<파서>\` | 파서별 입력 폴더 (export 의 하드 링크) | 정상 완료면 자동 삭제 |
| `vol<fs>\<파서>\` | 결과 CSV·파서 JSON·`run.log`(첫 줄에 실제 실행 명령·cwd·환경변수, 그 아래 파서 출력)·`link_notes.txt` | 남김 |
| `export_skipped.txt` | 추출 제외·실패·특수 처리 및 파서 미실행 사유 기록 (아래 표, 한 줄에 `종류<TAB>…`) | 남김 |

| `export_skipped.txt` 종류 | 뜻 | 불완전 입력? |
|---|---|---|
| `presence` | 이름·시각 확인용 0바이트 존재 파일 (원본 크기 기록). 추출 실패가 아님. 나중에 원본으로 다시 쓰면 `presence_upgraded` | 아니오 |
| `derived` | 다른 모듈이 만든 파생 파일(ZIP 안 파일 등) — 수집 대상에서 의도적으로 제외 | 아니오 |
| `ads` | Zone.Identifier 외 대체 데이터 스트림 — 어느 파서도 읽지 않아 제외 | 아니오 |
| `deleted` | 삭제 파일 본문을 수집하지 않은 기록 (폴더 입력은 Claude Desktop 외 삭제 파일 내용을 읽지 않음) | 아니오 |
| `deleted_exported` | 삭제 파일 추출 성공 기록 (`_deleted/<MFT>/…`) | 아니오 |
| `history_target_not_found` | History 다운로드 대상이 이미지에 없음 (이미지 입력도 같음) | 아니오 |
| `parser_not_run` | `parser_not_run<TAB>vol<fs><TAB><파서><TAB>실행 조건에 해당하는 관련 입력을 찾지 못함` — 관련 입력을 찾지 못해 그 볼륨에서 파서를 실행하지 않은 기록. 관련 행위가 없다는 판정이 아님 | 아니오 |
| `big` | `big<TAB>vol<fs><TAB>/$MFT 또는 /$Extend/$UsnJrnl:$J<TAB>size=<원본 크기><TAB>limit=1073741824<TAB>parsers=<그 파일을 읽는 파서>` — 1GB 상한 초과로 넘기지 않음 | 예 |
| `meta_limit` | `meta_limit<TAB>all volumes<TAB>limit=20000<TAB>collected=<수집 수><TAB>…<TAB>parsers=chatgpt_desktop,claude_web` — 2만 개 제한 다음 대상이 있어 그 뒤 메타데이터를 수집하지 않음 | 예 |
| `error`, `view_error`, `history_targets_failed`, `history_target_ambiguous` | 실제 추출 오류 / 입력 폴더 링크 실패 / History 다운로드 목록 읽기 실패 / 다른 볼륨 후보가 여럿 | 예 |

실패한 파서가 있거나 `incomplete input` 이 있으면 원인을 볼 수 있게 추출본을 남깁니다. 정상이어도 남기려면 `artinex_config.json` 에 `"keep_export": true` 를 넣습니다.
취소하면 그때까지의 추출본이 남습니다. 남은 실행시각 폴더는 언제든 지워도 됩니다 (원본은 이미지에, Report 사본은 사건 폴더에 있음).

같은 Data Source 에 다시 돌리면 같은 행은 다시 올리지 않습니다(`already present`). 중복 판정은 연결 파일과 행 키(`Row Key (ARTINEX dedup)` 속성)로 합니다 —
행 키는 CSV 한 행의 값에서 실행마다 바뀌는 입력 폴더 경로(Gemini·LM Studio 의 `Artifact_path`·상세)를 `<input>` 으로 바꿔 만든 해시이고, CSV 값 자체는 그대로 둡니다.
값이 달라진 행은 새 artifact 로 추가되며 이전 artifact 는 지우지 않습니다. 행 키가 없는 0.3.0 이전 artifact 와는 한 번 겹쳐 올라갈 수 있습니다. Report 는 새로 올라간 행이 있는 파서만 등록합니다.

명령행(화면 없이) 실행도 됩니다.

```
autopsy64.exe --createCase --caseName=case1 --caseBaseDir=C:\cases --addDataSource --dataSourcePath=C:\evidence\image.001 --runIngest
```

## 파서별 실행 명령

실행 cwd 는 각 파서 폴더, 공통 환경변수 `PYTHONIOENCODING=utf-8`. `{in}` = 추출 폴더(볼륨 루트 모양), `{out}` = 파서별 결과 폴더(추출 폴더 밖).
분석 옵션은 통합 실행과 같습니다 (Claude Web `--extended-fs` 없음, 각 파서 기본 옵션).

| 파서 | 명령 (python 뒤) | 환경변수 | 정상 종료 코드 | 폴더 입력에서 읽는 NTFS 메타파일 |
|---|---|---|---|---|
| ChatGPT Desktop | `run_parser.py --input {in} --input-type dir --out-dir {out} --format both --overwrite` | — | 0, 1(일부 파일 오류·결과 생성) | `$J` |
| ChatGPT Web | `-m chatgpt_parser.cli --dir {in} --csv-dir {out} --out {out}/result.json --overwrite` | — | 0 | — |
| Claude Desktop | `run_parser.py --input {in} --input-type dir --out-dir {out} --no-banner` | — | 0, 1 (exit 2 + `ARTIFACT_NOT_FOUND` = 흔적 없음) | `$MFT`, `$J` |
| Claude Web | `-m claude_web_forensics analyze --dir {in} --output {out} --overwrite` | `PYTHONPATH=src` | 0 | `$MFT` |
| Gemini Web | `gemini_parser.py --folder {in} --output {out} --csv` | — | 0 | — |
| LM Studio | `lmstudio_parser.py {in} --output {out}` | — | 0 | `$MFT`, `$J` |

## 수집 범위

범위 = `integration/parsers.json` 의 인자·기본 옵션으로 이미지를 넣었을 때 각 파서가 실제로 읽는 파일·폴더·스트림. 코드에 있어도 통합 실행에서 켜지지 않는 기능
(Claude Web `--extended-fs` 의 USN·휴지통 등)의 입력은 넣지 않았습니다. 사용자·프로필·패키지 버전은 경로 패턴으로 찾습니다(`*`).
○ = 그 입력이 있으면 그 볼륨에서 그 파서를 실행(실행 근거). △ = 읽기만 하는 보조 입력.

| 수집 대상 (볼륨 기준) | 꺼내는 형태 | 읽는 파서 | 통합(이미지) 실행에서 읽는 곳 |
|---|---|---|---|
| `Users/*/.codex/` 의 `sessions/**/rollout-*.jsonl`, `session_index.jsonl`, `.codex-global-state.json`, `auth.json`, `state_5`·`thread_history_1`·`logs_2.sqlite`(+`-wal`/`-shm`) | 내용 | ChatGPT Desktop ○ | cxparser `pipeline.PARSERS` (나머지 `.codex` 파일·`Documents/Codex` 는 목록용이라 제외) |
| `…/Packages/OpenAI.Codex_2p2nqsd0c76g0/…/Cache/Cache_Data/{index,data_0-3,f_*}` | 내용 | ChatGPT Desktop ○ | `locate` webcache |
| `…/Packages/OpenAI.Codex_2p2nqsd0c76g0/…/Codex/web/Codex/sentry/scope_v3.json` | 내용 | ChatGPT Desktop ○ | `locate` sentry_scope (0.3.31) |
| `Windows/Prefetch/CODEX.EXE-*.pf`, `CHATGPT.EXE-*.pf` | 내용 | ChatGPT Desktop ○ | `locate` prefetch |
| `…/Recent/*.lnk` (바로 아래) | 내용 | ChatGPT Desktop △ | `recent_lnk` |
| `Program Files/WindowsApps/OpenAI.Codex_*` 폴더 | 메타데이터 | ChatGPT Desktop ○ (설치 행) | `package_install` |
| `Packages/OpenAI.Codex_2p2nqsd0c76g0` 폴더 | 메타데이터 | ChatGPT Desktop △ | `package_install` |
| `Downloads`·`Desktop`·`Documents` 파일 (보조 메타데이터 탐색 2만 개 제한 — 전체 추출 파일 수 제한이 아님. 넘으면 `meta_limit`) | 메타데이터(시각·크기·첫 8바이트·MFT 번호) | ChatGPT Desktop △ (바로가기 대상), Claude Web △ (`$MFT` 근거) | `recent_lnk`, Claude Web `filesystem` |
| Claude 앱 루트 5곳(`Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude`, `Roaming/Claude`, `Local/Claude`, `Local/Claude-Data`, `Local/AnthropicClaude`) 아래 `Cache/Cache_Data`, `IndexedDB/https_claude.ai_*`, `Local Storage/leveldb`, `Session Storage`, 설정 JSON 6종, `logs/*.log` | 내용 (삭제 파일은 `_deleted/<MFT>/…`) | Claude Desktop ○ | `locate.SCAN_ROOTS` × `_PATTERNS` (미할당 MFT 포함) |
| 위 루트와 그 하위 폴더 | 메타데이터(MFT 번호·순번) | Claude Desktop △ (USN 부모 대조) | `usn.Selector` |
| `ProgramData/Claude/logs/*.log`, `Windows/Prefetch/CLAUDE*.pf` | 내용 | Claude Desktop ○ | `locate` applog_shared, prefetch |
| `Program Files/WindowsApps/Claude_*/AppxManifest.xml` | 내용 | Claude Desktop ○ | `locate` package_binary (목록. 이것이 있어야 USN 까지 진행) |
| Chrome 프로필(`…/Google/Chrome/User Data/{Default,Profile *,Guest Profile}`) `History`(+`-wal`/`-shm`/`-journal`), `Cache/Cache_Data/**`, `Local Storage/leveldb/**`, `Sessions/Session_*`·`Tabs_*` | 내용 | ChatGPT Web ○, Claude Web ○, Gemini ○ | 각 파서 프로필 수집 |
| 프로필 `Cookies`·`Network/Cookies`(+`-wal`/`-shm`/`-journal`) | 내용 | Claude Web ○, Gemini ○ | |
| 프로필 `Preferences` / `Secure Preferences` | 내용 | ChatGPT Web ○, Gemini ○ / Gemini ○ | |
| 프로필 `Session Storage/**` | 내용 | ChatGPT Web ○, Gemini ○ | |
| 프로필 `IndexedDB/https_claude.*` / `IndexedDB/**` | 내용 | Claude Web ○ / Gemini ○ | |
| 프로필 `shared_proto_db/*` / `Service Worker/**` | 내용 | ChatGPT Web ○ / Gemini ○ | |
| `Users/*/Downloads/**` (+ `Zone.Identifier` ADS) | 내용 | Claude Web △, Gemini △ | Claude Web `collect_files`(Downloads 탐색), Gemini 다운로드 해석 |
| 프로필 History `downloads.target_path`·`current_path` 가 가리키는 파일(Downloads 밖·다른 볼륨 포함, + `Zone.Identifier`) | 내용 (History 와 같은 볼륨의 입력 폴더에 드라이브 문자를 뗀 경로로). 같은 볼륨에 없으면 다른 볼륨 **하나**에서만 가져오고 그 파일의 MFT 번호는 넘기지 않음. 다른 볼륨 후보가 여럿이면 가져오지 않고 `history_target_ambiguous` | Claude Web △, Gemini △ | Claude Web `pipeline`·`filesystem`, Gemini `resolve_download` — 둘 다 드라이브 문자를 떼고 모든 볼륨에서 찾음 |
| `Users/*/.lmstudio/**`, `…/Programs/LM Studio/**`, `…/lm-studio-updater/**`, `Start Menu/Programs/LM Studio/**`, `Start Menu/**/*LM Studio*`, `Windows/Prefetch/*LM?STUDIO*.pf` | `.json`·`.md`·`.txt`·`.log`·`server-logs/*` 는 내용, 나머지는 존재 파일 | LM Studio ○ | `collect_ntfs_current` 대상 폴더 |
| `Downloads`·`Desktop`·`Documents`·`$Recycle.Bin` 의 LM Studio 관련 이름(`RELEVANT_NAME_RE`: `*.md`, `*.gguf`, `*.conversation.json`, `LM Studio.lnk` 등) | 위와 같음 | LM Studio ○ | `should_record_path` 필터 |
| `$Recycle.Bin/*/$I*` / `$R*` | 내용 / 존재 파일 | Gemini △ | Gemini 휴지통 (`$R` 는 있는지만 봄) |
| 볼륨 루트 `$MFT`, `$Extend/$UsnJrnl:$J` | 원본 그대로 (1GB 초과 제외) | 위 'NTFS 메타파일' 열의 파서를 그 볼륨에서 돌릴 때만 | 각 파서의 MFT·USN 분석 |

0.2 에서 뺀 것: `Documents/Codex`·나머지 `.codex`·패키지 폴더 전체(ChatGPT Desktop 목록용), `Local State`·`Network` 의 Cookies 외 파일(아무도 안 읽음),
`claudesetup.log`(통합 실행은 `Temp` 를 탐색하지 않음), `.lmstudio-home-pointer`·LM Studio 의 `Recent` 탐색(폴더 입력에서만 읽던 것),
`Desktop`·`Documents` 전체(LM Studio 관련 이름만), Claude 앱 루트의 분류 밖 파일(GPUCache 등), Chrome `User Data/*`·WindowsApps `Claude_*`·`Prefetch` 폴더 메타데이터(쓰는 파서 없음).

**존재 파일**: 읽는 파서가 이름·시각만 쓰는 파일(LM Studio 의 `.gguf`·실행 파일, Gemini 의 `$R`)은 0바이트에 원본 수정 시각을 둔 파일로만 꺼내고 원본 크기를
`export_skipped.txt` 에 `presence` 로 적습니다. 크기와 무관한 규칙이며, 내용을 읽는 파일은 크기 상한 없이 원본 그대로(스트리밍) 꺼내고 크기를 대조합니다.
같은 파일을 내용으로 읽는 다른 파서가 있으면(예: `Downloads` 의 `.gguf`) 원본 내용으로 꺼냅니다. 먼저 존재 파일로 꺼낸 뒤에 내용이 필요한 요청이 오면
(예: Desktop 의 `.gguf` 를 History 가 다운로드 대상으로 가리킴) 그 자리에서 원본으로 다시 쓰고 크기를 대조합니다(`presence_upgraded`).
존재 파일로 충분한 근거 (파서 코드 확인):
- LM Studio `add_local_file`: 본문은 `should_read_content`(`.json` ≤64MB, `.md`·`.txt` ≤16MB, `server-logs` 아래 ≤16MB)일 때만 읽고 그때만 `content:sha256` 을 만든다.
  `st_size` 는 내부 식별자 `stable_id(경로, 크기)` 와 `ArtifactRecord.size` 에만 들어가는데, `size` 를 읽는 판정·출력 코드가 없고 출력은 CSV 2개뿐이다.
  `.gguf`·실행 파일의 행위(모델 받기·설치 등)는 이름과 `$MFT` 시각(`_host_metadata.json` → 원본 `$MFT`)으로 만든다. 크기 비교는 JSON 안의 `sizeBytes` 값으로만 한다.
- Gemini `payload_exists`: `$R` 가 일반 파일인지(`S_ISREG`)만 본다. `$R` 폴더(지운 폴더)는 두 입력 모두 '없음' 으로 나와 따로 만들지 않는다.

## 원본 메타데이터 전달

- 모든 파일은 Autopsy 의 `ContentUtils.writeToFile` 로 버퍼 단위로 쓰고(파일 전체를 메모리에 올리지 않음), 쓴 크기를 원본 크기와 대조합니다(다르면 오류로 기록하고 그 복사본을 지움).
  복사본의 수정 시각은 원본 `$STANDARD_INFORMATION` 수정 시각으로 되돌립니다.
- `Zone.Identifier` 는 추출 폴더에 실제 ADS(`파일:Zone.Identifier`)로 씁니다 (텍스트 파일로 바꾸지 않음). 작업 위치는 ADS 를 쓸 수 있는 곳만 고르므로(위 '작업 위치'),
  개별 파일이 실패하면 그 파일만 `error` 로 기록하고 다음 파일을 계속 꺼냅니다. ADS 는 주 파일을 모두 꺼낸 뒤 마지막에 씁니다 — Autopsy 는 `x.pdf:Zone.Identifier` 를
  `x.pdf` 보다 먼저 돌려줄 수 있는데(인덱스 순서), 주 파일을 나중에 쓰면 Windows 가 그 파일의 ADS 를 지웁니다(0.4.0 까지의 버그, 0.4.1 에서 수정). 주 파일을 못 꺼냈으면 그 ADS 도 쓰지 않습니다.
- `_host_metadata.json`(원본 경로·MFT 레코드 번호·순번·시각·크기·첫 8바이트·삭제 여부)은 원본 경로와 MFT 레코드를 잇는 보조 정보입니다. 시각·USN 은 파서가 원본 `$MFT`·`$J` 에서 직접 읽습니다.
- 볼륨마다 추출 폴더를 따로 두고(`vol<fs id>`) 볼륨마다 파서를 따로 실행합니다.
- 삭제(unallocated) 파일은 Claude Desktop 수집 범위의 것만 `_deleted/<MFT번호>/<원래 경로>` 에 꺼냅니다. 다른 파서의 수집 범위에 있는 삭제 파일은 내용을 넘기지 않지만,
  `$MFT`·`$J` 를 읽는 파서(ChatGPT Desktop, LM Studio)에는 그 볼륨에서 실행할 근거(`deleted trace`)가 됩니다 — 앱을 지운 뒤 USN·MFT 흔적만 남은 경우.

## 실행 근거 (메타데이터만 남은 경우)

| 파서 | 일반 파일 없이도 실행하는 근거 | 그때 폴더 입력이 쓰는 것 |
|---|---|---|
| ChatGPT Desktop | WindowsApps `OpenAI.Codex_*` 패키지 폴더, 수집 범위의 삭제 파일 흔적 | 패키지 폴더 메타데이터(설치 행), `$J`(USN 행) |
| Claude Desktop | `_deleted` 로 꺼낸 삭제 파일, WindowsApps `AppxManifest.xml` | 삭제 파일 내용, `$MFT` 시각, `$J` |
| LM Studio | 수집 범위의 삭제 파일 흔적 | `$MFT`+`$J` (USN 설치·삭제·대화 삭제, 상주 JSON 복구) |
| ChatGPT Web · Claude Web · Gemini | 없음 — Chrome 프로필 파일이 있어야 실행 | |

폴더 루트만 남은 Claude Desktop(분류되는 파일 0개)은 실행하지 않습니다 — 이미지 입력에서도 같은 조건에서 `ARTIFACT_NOT_FOUND` 로 끝나 USN 까지 가지 않습니다.
USN 에만 남은 활동(관련 파일·폴더·삭제 흔적이 Autopsy 에 하나도 없을 때)은 폴더 입력으로 찾지 않습니다 (한계 표). 그래서 파서 미실행(`parser_not_run`)은
"관련 행위가 없다는 판정"이 아니라 "실행 조건에 해당하는 관련 입력을 찾지 못함"입니다 — 그 볼륨의 USN 은 분석하지 않은 상태입니다.

## 증거 연결

CSV 의 `Artifact_path` 는 그대로 Artifact Path 속성에 넣고, 연결할 AbstractFile 은 내부에서만 해석합니다.
- 표기: `C:\Users\…`(드라이브 문자), `Users/…`(상대), 그 파서 입력 폴더의 절대 경로, `volumeN:\…`. 여러 경로(`|`)는 첫 경로를 씁니다.
- 그 파서를 실행한 **볼륨에서 꺼낸 파일 목록**에서만 찾습니다 — 다른 볼륨의 같은 경로 파일을 고르지 않습니다.
- 추출 폴더 절대 경로가 `_deleted/<MFT>/…` 를 가리키면 그 삭제 파일에 붙습니다.
- 같은 원래 경로에 현존·삭제 파일이 함께 있으면 `Artifact_details` 의 `MFT=<번호>`(없으면 `삭제 엔트리=True`)로 고릅니다.
  후보가 하나로 줄지 않거나(예: 대화 CSV 는 상세 열이 없음) 꺼낸 파일이 없으면 Data Source 에 붙이고 `<파서>/link_notes.txt` 에 사유를 남깁니다. 삭제 행을 같은 경로의 현존 파일에 임의로 붙이지 않습니다.

## 한계 (이미지 직접 입력과 다른 점)

| 파서 | 폴더 입력에서 빠지거나 다른 것 | 영향 |
|---|---|---|
| 공통 | Autopsy 가 보여 주는 삭제 파일은 디렉터리 인덱스·MFT 에 이름이 남은 것뿐. 드라이브 문자는 항상 `C:`(SYSTEM 하이브 MountedDevices 를 넘기지 않음). `$MFT`·`$J` 는 Autopsy 가 보고하는 논리 크기(`$J` 는 희소 앞부분 포함)가 파일별 1GB 를 넘으면 넘기지 않음(`big`, 그 파일을 읽는 파서에만 `incomplete input` + 상한 초과 경고, 나머지 입력으로 분석 계속). `Downloads`·`Desktop`·`Documents` 보조 메타데이터는 2만 개까지만 수집(넘으면 `meta_limit` 경고, 수집한 것으로 분석 계속) | 비-C 볼륨의 경로 표기, 큰 `$MFT`·`$J` 의 MFT·USN 행, 제한 밖 파일의 바로가기 대상·`$MFT` 근거 |
| ChatGPT Desktop | 삭제 파일 내용 | 삭제된 rollout·WAL 복구 없음 (`$J` 는 읽음). `$J` 만 남고 관련 파일·폴더·삭제 흔적이 없는 볼륨은 실행하지 않음 |
| Claude Desktop | `$FN` 시각, 재사용된 MFT 레코드 판별 | 이 이미지에서는 차이 없음 |
| ChatGPT Web | 없음 | `Artifact_path` 도 두 모드가 같음 |
| Claude Web | Zone.Identifier 외 ADS 목록. History 대상 중 이 Data Source 밖(다른 디스크·네트워크 경로)의 파일. 다른 볼륨에서 가져온 History 대상의 `$MFT` 근거 | 볼륨 식별 정보를 넘기지 않으므로 다른 볼륨 파일은 내용·크기·Zone.Identifier 만 넘기고 MFT 근거는 생략. 다른 볼륨 후보가 여럿이면 넘기지 않음 |
| Gemini Web | `Default`·`Profile N` 외 프로필 이름. History 대상 중 이 Data Source 밖의 파일 | 그 파일은 `file_exists=False` (이미지 입력도 같음) |
| LM Studio | 이미지 입력의 폴더 깊이 제한(프로그램 폴더 4단계 등) 없음 | 깊은 경로의 파일이 artifact 로 더 잡힐 수 있음(행위 판정 없음). `Artifact_path` 는 입력 폴더 절대 경로 / `volume0:\…` (파서 폴더 모드 형식) |

**임시 추출 경로 표시 (미해결)**: Gemini Web·LM Studio 결과(`Artifact_path`, LM Studio 설치 행의 `Behavior_details` 등)에는 원본 증거 경로 대신 분석 PC 의 입력 폴더 경로
(`<작업 위치>\<사건>_ds_<id>\<실행시각>\vol<fs>\in_<파서>\Users\…`)가 그대로 표시됩니다. 이 폴더는 정상 완료 시 지워지므로 그 경로로 파일을 열 수 없습니다 —
`in_<파서>\` 뒤의 부분이 볼륨 안 원래 경로이고, 근거 파일은 artifact 가 붙은 Autopsy 파일(증거 연결)로 확인합니다. Blackboard·Report CSV 모두 같은 값입니다.

LM Studio 폴더 입력은 입력 폴더 아래의 `*.csv`·`*.db` 를 '사전 파싱 MFT/USN 목록'으로 읽습니다 (이미지 입력에는 없는 경로). LM Studio 입력 폴더(`in_lmstudio`)에는
LM Studio 가 이미지 입력에서 기록하는 파일만 있고, 그중 `*.csv`·`*.db` 는 내용을 읽지 않는 파일이라 0바이트 존재 파일이므로 이 경로로 행이 생기지 않습니다.
`Downloads` 의 `*.csv`·`*.db` 는 Claude Web·Gemini 입력 폴더에만 들어갑니다.

## 검증

실제 Autopsy 실행과 단위 검증을 나눠 적습니다. 비교 기준은 같은 저장소 코드(main `7943997` 의 파서)로 같은 이미지를 돌린 통합 실행 결과입니다.

**1. 실제 Autopsy Ingest (0.4.1, 2026-10-11)** — Autopsy 4.23.1 명령행(`--runIngest`, Ingest 모듈은 ARTINEX 만)

| 사건 | 기업 내부정보 유출 `WHS_project_FINAL.dd` (새 사건, `C:\autopsy_cases`, NTFS) | 해킹 `Erelem_Final.dd` (기존 사건 `erelm_val1`, `D:` exFAT) |
|---|---|---|
| 작업 위치 | 사건 폴더 `ModuleOutput\ARTINEX` (로그 `work root … (case folder)`) | 사건 폴더 ADS 시험 실패 → 대체 위치 `C:\artinex_work` (로그에 사유: `no alternate data streams`) |
| 추출 | 5,651 파일(존재 파일 4,590), 오류 0, `incomplete input` 0 | 5,565 파일(존재 파일 4,597, 파생 제외 7, 삭제 본문 미수집 5), 오류 0, `incomplete input` 0 |
| `export_skipped.txt` | `parser_not_run` 6줄 (데이터 없는 다른 볼륨의 6개 파서) | `parser_not_run` 6줄 (같은 경우) |
| 통합 실행과 CSV 12개 비교 | 행 수 전부 일치. 완전 일치 7, 경로 표기(입력 폴더 절대 경로·`C:\`·`volume=`·`MFT=`)만 다름 4, LM Studio timeline 5행 다름 | 행 수 전부 일치. 완전 일치 7, 경로 표기만 다름 4, LM Studio timeline 6행 다름 |
| 정리 | 정상 완료 → 추출본 삭제, 결과 CSV·`export_skipped.txt` 유지 | 같음. Report 사본은 사건 폴더 `ModuleOutput\ARTINEX\ds_1\<실행시각>` 에 등록 |

LM Studio 차이는 폴더 입력 모드의 표기·근거 차이이며 0.2·0.3 검증 때와 같은 종류입니다: 근거가 `[$UsnJrnl]` 대신 `[$MFT]`·`[Conversation]`, 상세의 경로가 `volume0:\…` 대신 입력 폴더 절대 경로,
`Artifact_path` 의 `$J` 순서. 행위·시각·판정은 같습니다.

| 재실행 (같은 Data Source) | 결과 |
|---|---|
| 기업 2회차 (첫 실행 직후) | 새 등록 0건, 209건 모두 `already present` |
| 기업 3회차 (ADS 순서 수정 후) | Claude Web 1행만 새로 등록(값이 바뀐 행 — Zone.Identifier 근거가 추가됨), 나머지 `already present`. Claude Web CSV 가 통합 실행과 완전 일치 |
| 해킹 (오늘 0.4.0 결과가 있는 사건) | ChatGPT Desktop 4행만 새로 등록(0.3.31 Sentry 행위 — 0.4.1 에서 `scope_v3.json` 수집 추가), 나머지 152건 `already present`. Report 3건 추가 |

이 Ingest 에서 발견해 고친 것: Autopsy 는 `Downloads` 의 `x.pdf:Zone.Identifier` 를 `x.pdf` 보다 먼저 돌려주는데(인덱스 순서) ADS 를 먼저 쓰고 주 파일을 나중에 쓰면
Windows 가 ADS 를 지워, Claude Web 의 Zone.Identifier 근거가 빠졌습니다(0.2 부터 있던 문제). ADS 를 마지막에 쓰도록 수정했습니다.
0.3.0 Ingest 에서 고친 것: 다른 모듈이 만든 ZIP 안 파생 파일이 `Downloads/%` 에 걸리던 문제 — 원본 파일시스템(`FS`)·논리 파일(`LOCAL`)만 꺼냄(`derived`).

**2. 단위 검증 85건** — Autopsy 동봉 Jython 2.7.4 + sqlite-jdbc, Autopsy API 대역(가짜 볼륨 3개, 가짜 파서 6개, `artifactExists` 는 실제 Autopsy 와 같은 부분집합 비교). 모두 통과.

| 범주 | 확인한 것 |
|---|---|
| 작업 위치 | NTFS 사건 폴더 → 사건 폴더(`work_dir` 가 있어도), exFAT 사건 폴더 → 대체 위치·사유 로그, 쓰기 불가 사건 폴더 → 대체 위치, 설정 없음 → `C:\artinex_work`, 둘 다 불가 → 두 사유와 함께 ERROR·실행 안 함 |
| 미실행 기록 | `parser_not_run` 이 볼륨·파서별로 `export_skipped.txt` 에, 모두 실행한 볼륨은 기록 없음, 작업 폴더에 다른 요약·로그 파일 없음, Inbox 문구 유지 |
| 2만 개 제한 | 정확히 제한 개수 → 경고 없음 / 다음 대상이 있음 → `meta_limit`(제한·수집 수·범위·파서) + ChatGPT Desktop 에만 경고(LM Studio 없음), 수집한 메타데이터는 전달, 분석 계속·입력 폴더 보존 |
| 1GB 상한 | 2GB `$MFT` → `big`(볼륨·파일·크기·상한·파서) + `$MFT` 를 읽는 LM Studio 에만 경고(`$J` 만 읽는 ChatGPT Desktop 없음), 등록 계속(WARNING·OK), 입력 폴더 보존 |
| 수집 범위 | 목록용·분류 밖 파일 제외, 하위 폴더 메타데이터 기록, ZIP 안 파생 파일 제외 |
| 대용량·존재 파일 | 200MB 파일 SHA-256·크기 동일, `.gguf` 0바이트 존재 파일 + 원본 크기 기록 |
| ADS | ADS 가 주 파일보다 먼저 와도 실제 스트림으로 남음(수정 전 코드에서는 실패 확인), 주 파일 실패 → ADS 안 씀, 개별 실패 기록 후 다음 ADS 계속, 실패해도 주 파일 유지 |
| History 대상 | Downloads 밖(Desktop) 파일 + Zone.Identifier 추출, 다른 볼륨 파일을 History 볼륨 입력에(그 파일의 MFT 번호는 `_host_metadata.json` 에 넣지 않음), 다른 볼륨 후보 2곳이면 가져오지 않고 기록, 없는 대상 기록, History 를 읽지 못하면 `incomplete input`, LM Studio 존재 파일을 History 가 가리키면 원본으로 승격 |
| 파서별 입력 폴더 | `Downloads/*.csv` 가 웹 파서에만, `$MFT` 는 읽는 파서에만, 하드 링크, 링크로 ADS 읽힘, 각 폴더에 `_host_metadata.json` |
| 재실행·정리 | 입력 폴더 경로가 다른 재실행에서 `already present`. 정상 완료 → `export`·`in_*` 삭제, 결과·`export_skipped.txt` 유지 / 실패·`incomplete input`·`keep_export` → 유지 |
| 메타데이터만 있는 볼륨·증거 연결·오류 격리·취소 | 0.4.0 과 같은 항목 모두 통과 |

**3. `setup.ps1`**

| 상황 | 방법 | 결과 |
|---|---|---|
| 0.4.1: 대체 위치 준비(`C:\artinex_work` 쓰기·ADS 확인), 기존 `work_dir` 보존, `python`·`repo_root` 갱신 | 실제 저장소·Autopsy 설치 | 통과 |
| 전용 가상환경만 사용(없음+준비 실패 → 중단 / 의존성 없음 → 준비·재검사 / 정상 → 재사용), 깨진 설정 JSON → 중단 | 가짜 저장소 (0.4.0 에서 시험, 해당 코드는 바뀌지 않음) | 통과 |
| `uv` 없음 → 공식 설치 → 같은 프로세스에서 사용 | PATH 의 uv 를 빼고 임시 `UV_INSTALL_DIR` | 통과. uv 가 처음부터 없는 별도 PC 에서는 미검증 |

미검증: 실제 여러 볼륨 이미지(다른 볼륨 History 대상·모호한 후보는 단위 검증만), 실제 이미지에서 2만 개 제한·1GB 상한 초과(두 이미지 모두 상한 안 — 단위 검증만),
사건 폴더와 대체 위치가 모두 불가한 실제 환경(단위 검증만).

## 파일

- `ARTINEX.py` — 모듈 본체 (파서 레지스트리 `PARSERS`, 수집 목록 `FILE_QUERIES`·`META_DIR_QUERIES`·`NTFS_META`)
- `artinex_config.example.json` — 설정 예시. `setup.ps1` 이 `artinex_config.json` 을 만들고 갱신한다 (PC마다 다른 경로라 저장소에는 예시만 둔다)
- `../setup.ps1` — 환경 준비·설치 스크립트
- `README.md` — 이 문서
