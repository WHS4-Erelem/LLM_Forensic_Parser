# ARTINEX : Autopsy용 LLM 사용 아티팩트 Ingest 모듈

[한국어](README.md) · [English](README.en.md)

- __설명:__ Autopsy에서 Windows 디스크 이미지를 대상으로 LLM 서비스 6종(ChatGPT Desktop, ChatGPT Web, Claude Desktop, Claude Web, Gemini Web, LM Studio)의 ARTINEX 포렌식 파서를 실행하고, 재구성한 사용자 행위와 복구된 대화를 Blackboard, Timeline, Reports에 등록합니다.
- __작성자:__ WHS4-Erelem
- __검증한 Autopsy 버전:__ 4.23.1(다른 버전은 검증하지 않았습니다)
- __모듈 위치:__ https://github.com/WHS4-Erelem/LLM_Forensic_Parser (`Autopsy_Addon/ARTINEX/` 모듈 폴더. 모듈에는 전체 배포 패키지가 필요합니다. 설치 항목 참고)
- __웹사이트:__ https://github.com/WHS4-Erelem/LLM_Forensic_Parser
- __소스 코드:__ https://github.com/WHS4-Erelem/LLM_Forensic_Parser
- __라이선스:__ AGPL-3.0-or-later([`LICENSE`](../LICENSE) 참고)

## 개요

ARTINEX는 Windows PC에서 사용자가 LLM 서비스를 어떻게 사용했는지 재구성하는 디지털 포렌식 프로젝트입니다. 독립적인 CPython 파서 6개, 통합 실행기, 이 Autopsy 애드온으로 구성됩니다.

애드온은 얇은 어댑터 역할을 합니다. Autopsy가 이미지를 열고 파일시스템을 해석하면, 애드온은 각 파서가 읽는 파일만 볼륨 루트 구조를 재현한 임시 폴더로 추출합니다. 이후 각 파서를 별도의 Python 3.12 프로세스로 실행하고, CSV 출력 계약을 검사한 뒤 결과 행을 Autopsy에 등록합니다.

디스크 이미지 → Autopsy / TSK → ARTINEX 모듈 → 볼륨별 추출 폴더 → ARTINEX 파서 6개(폴더 입력 모드).

파서 결과인 `timeline.csv` / `recovered_conversations.csv` → 출력 계약 검사 → Blackboard, Timeline, Reports.

Autopsy의 Python은 Jython 2.7이므로 파서를 직접 import하지 않습니다. 파서는 전용 가상환경에서 외부 프로세스로 실행됩니다.

## 주요 기능

- 하나의 Data Source Ingest Module인 **ARTINEX**로 파서 6개를 모두 실행합니다. 다른 Autopsy 모듈은 필요하지 않습니다.
- 각 파서가 읽는 파일, 폴더, NTFS 메타데이터(`$MFT`, `$Extend/$UsnJrnl:$J`, `Zone.Identifier` 스트림)만 추출합니다. 추출한 복사본은 원본 수정 시각을 유지합니다.
- 각 파서는 입력이 있는 볼륨에서만 실행하며, 볼륨마다 별도로 실행합니다.
- 등록 전에 모든 CSV의 공통 출력 계약(헤더, 열 수, 타임스탬프 형식, 판정, 빈 셀)을 검사합니다. 계약을 위반한 파서는 실패로 보고하고 해당 결과 행은 등록하지 않습니다.
- 이미지 내 근거 파일을 명확하게 식별할 수 있으면 각 행을 그 파일에 연결합니다. 그렇지 않으면 데이터 소스에 연결하고 사유를 `link_notes.txt`에 기록합니다.
- 실패를 격리합니다. 한 파서가 실패하거나 제한 시간을 초과하거나 결과를 생성하지 않아도 나머지 파서는 계속 실행합니다.
- 같은 데이터 소스에서 모듈을 다시 실행할 때 중복 행 등록을 방지합니다.
- 추출할 수 없거나 제한을 초과한 파일 등 불완전 입력을 포함하여, 파서별·볼륨별 상태를 Ingest Inbox에 기록합니다.

## 시스템 요구 사항

| 항목 | 요구 사항 |
|---|---|
| 운영체제 | Windows(Windows 11에서 검증). 일부 파서는 Windows Prefetch와 NTFS 대체 데이터 스트림을 읽습니다. |
| Autopsy | 4.23.1에서 검증했습니다. 다른 버전은 검증하지 않았습니다. |
| 배포 패키지 | [Releases](https://github.com/WHS4-Erelem/LLM_Forensic_Parser/releases)의 Autopsy용 배포 ZIP 전체. `Autopsy_Addon`, `integration`, 파서 폴더 6개가 필요합니다. |
| Python | 설치 스크립트가 생성하는 `integration\.venv312`의 전용 Python 3.12 가상환경. 일부 파서 의존성(pytsk3, libewf-python)은 Python 3.12까지만 Windows 휠을 제공합니다. |
| uv | 설치 스크립트에서 환경 생성에 사용합니다. uv가 없으면 공식 설치 프로그램으로 설치합니다. |
| 네트워크 | 설치 중 uv, Python 3.12, 패키지를 다운로드할 때 필요합니다. 분석 중에는 필요하지 않습니다. |
| 디스크 공간 | 애드온은 파서가 읽는 파일을 작업 폴더로 추출합니다(기본 위치는 사건 폴더 내부). `Zone.Identifier` 스트림을 실제 대체 데이터 스트림으로 전달하므로 작업 폴더는 NTFS에 있어야 합니다. |

## 설치

1. [Releases](https://github.com/WHS4-Erelem/LLM_Forensic_Parser/releases)에서 사용할 버전의 릴리스 안내를 확인하고, **Autopsy용 배포 ZIP**을 다운로드합니다. 압축 파일 전체를 계속 보관할 위치에 해제합니다. `Autopsy_Addon`, `integration`, 파서 폴더 6개가 함께 있는 폴더가 배포 패키지 루트입니다. `ARTINEX` 모듈 폴더만 따로 꺼내지 마세요.

2. Autopsy를 종료하고 PowerShell에서 설치 스크립트를 실행합니다.

   ```powershell
   # 압축을 해제한 배포 패키지 루트에서 실행합니다.
   powershell -ExecutionPolicy Bypass -File .\Autopsy_Addon\setup.ps1
   ```

   스크립트는 다음 작업을 수행합니다.

   1. 저장소에 파서 진입점 6개가 있는지 확인합니다.
   2. 전용 가상환경 `integration\.venv312`를 검사합니다. 가상환경이어야 하고, Python 3.12를 사용하며, 주요 파서 의존성을 import할 수 있어야 합니다.
      - 검사를 통과하면 재설치 없이 환경을 재사용합니다.
      - 환경이 없으면 `integration\setup.ps1`을 실행합니다. 이 스크립트는 필요한 경우 uv를 설치하고 환경을 생성합니다.
      - 환경이 있지만 검사에 실패하면(Python 버전 불일치, 인터프리터 손상, 패키지 누락), 이 저장소의 `integration\.venv312`만 삭제하고 다시 생성합니다. 경로가 예상과 다르거나 정션·링크이거나 삭제할 수 없으면 설치하지 않고 중단합니다.
      - 준비 후 종료 코드와 환경을 다시 검사하며, 둘 중 하나라도 실패하면 설치하지 않고 중단합니다.
   3. 설치된 Autopsy 설정에서 Python 플러그인 폴더(`python_modules`)를 찾습니다. 후보가 없거나 여러 개일 때만 사용자에게 묻습니다. `-PluginDir <python_modules folder>`로 직접 지정할 수도 있습니다.
   4. 대체 작업 위치(기본값 `C:\artinex_work`)를 준비하고 파일과 대체 데이터 스트림을 저장할 수 있는지 검사합니다.
   5. 모듈을 `<python_modules>\ARTINEX`에 복사하고, Python 인터프리터와 저장소의 절대 경로를 `artinex_config.json`에 기록합니다. 해당 파일의 기존 설정은 유지합니다.

3. Autopsy를 시작합니다. Ingest 모듈 목록에 **ARTINEX**가 표시됩니다.

모듈은 압축을 해제한 배포 폴더의 파서를 그 위치에서 실행하므로 설치 후 해당 폴더를 이동하거나 삭제하지 마세요. 이동했다면 설치 스크립트를 다시 실행하세요.

설정 파일: `<python_modules>\ARTINEX\artinex_config.json`

| 키 | 의미 |
|---|---|
| `python` | `integration\.venv312\Scripts\python.exe`의 절대 경로(설치 스크립트가 설정) |
| `repo_root` | 저장소의 절대 경로(설치 스크립트가 설정) |
| `work_dir` | 선택 설정. 사건 폴더를 사용할 수 없을 때만 사용하는 대체 작업 위치 |
| `keep_export` | 선택 설정. `true`이면 정상 실행 후에도 추출 파일을 유지 |

환경변수 `ARTINEX_PYTHON`, `ARTINEX_REPO_ROOT`, `ARTINEX_WORK_DIR`가 있으면 위 설정값보다 우선합니다.

## Autopsy에서 사용하기

1. 사건을 생성하고 디스크 이미지를 데이터 소스로 추가합니다.
2. Ingest 모듈 선택 화면에서 **ARTINEX**를 활성화합니다. ARTINEX 실행에 다른 모듈은 필요하지 않습니다.
3. Ingest가 완료되면 다음 위치에서 결과를 확인합니다.

| 위치 | 내용 |
|---|---|
| Data Artifacts → **LLM User Behavior (ARTINEX)** | 각 파서의 `timeline.csv` 한 행당 아티팩트 한 건 |
| Data Artifacts → **Messages** | `recovered_conversations.csv`에서 복구한 대화 메시지 |
| **Timeline** | `[<parser>] <behavior> (<verdict>): <details>` 형식으로 설명되는 시각이 있는 행위와 메시지 |
| **Reports** | 각 파서의 `timeline.csv`, `recovered_conversations.csv`, 파서 JSON 결과(`cx_result.json`, `result.json`, `gemini_results.json`) |
| **Ingest Inbox** | 파서별·볼륨별 상태 한 줄 |

Ingest Inbox의 상태 문구는 다음과 같습니다.

| 상태 | 의미 |
|---|---|
| `N behaviors, M messages (ran on …)` | 파서가 실행되었고 결과 행이 등록되었습니다. 괄호 안에는 실행 근거가 된 입력이 표시됩니다. |
| `not run (no input it reads)` | 해당 볼륨에서 이 파서의 입력을 찾지 못했습니다. 해당 행위가 발생하지 않았다는 뜻은 아닙니다. |
| `no artifacts` | 파서가 실행되었지만 흔적을 찾지 못했습니다. |
| `failed (exit N, see run.log)`, `output missing`, `CSV contract violation (…)` | 해당 파서만 실패했습니다. 다른 파서는 계속 실행됩니다. |
| `[incomplete input: N not exported …]` | 해당 파서의 일부 입력을 추출할 수 없었거나 제한을 초과했습니다. `export_skipped.txt`를 확인하세요. |
| `(N linked to data source, see link_notes.txt)` | 근거 파일을 명확하게 식별할 수 없어 데이터 소스에 연결한 행입니다. |
| `Cancelled …` | Ingest가 취소되었습니다. 이후 파서는 실행되지 않았습니다. |

작업 위치: 매 실행마다 먼저 `<case folder>\ModuleOutput\ARTINEX`를 사용해 봅니다. 해당 위치에 파일이나 대체 데이터 스트림을 쓸 수 없으면(예: 사건 폴더가 exFAT 드라이브에 있는 경우) 대체 작업 위치를 사용합니다. 두 위치 모두 사용할 수 없으면 중단하고, 두 사유를 Ingest Inbox와 Autopsy 로그에 기록합니다.

매 실행마다 `<work location>\<case>_ds_<id>\<run time>\`를 생성합니다. 정상 실행 후 추출 파일은 삭제하지만 결과, `run.log`(정확한 실행 명령 포함), `export_skipped.txt`는 유지합니다. 파서가 실패했거나 입력이 불완전한 경우에는 추출 파일도 유지합니다.

같은 데이터 소스에서 모듈을 다시 실행해도 이미 등록된 행은 다시 등록하지 않습니다. 값이 변경된 행은 새로운 아티팩트로 추가하며, 이전 아티팩트는 삭제하지 않습니다.

각 파서의 제한 시간은 볼륨당 1시간입니다. 제한 시간에 도달하면 프로세스를 종료하고 해당 파서를 실패로 보고합니다.

## 지원 LLM 서비스와 아티팩트

| 서비스 | 파서 | 주요 분석 아티팩트 |
|---|---|---|
| ChatGPT Desktop(OpenAI Codex 앱, Microsoft Store 패키지) | ChatGPT_APP_Parser 0.3.31 | `.codex` 세션 파일과 SQLite 데이터베이스, 앱 웹 캐시, Sentry scope 파일, Prefetch, Recent 바로가기, 패키지 폴더 시각, USN 저널 |
| ChatGPT Web(Chrome) | ChatGPT_Web_Parser 0.2.0 | Chrome History, Cache, Local Storage, Session Storage, Sessions, Preferences, shared_proto_db |
| Claude Desktop | Claude_APP_Parser 1.5.0 | Claude 앱 캐시, IndexedDB, Local/Session Storage, 설정 JSON, 앱 로그, Prefetch, 패키지 매니페스트, `$MFT`, USN 저널, Autopsy에서 확인 가능한 삭제 파일 |
| Claude Web(Chrome) | Claude_Web_Parser 1.0.0 | Chrome History, Cache, Cookies, Local Storage, IndexedDB, Sessions, `Zone.Identifier`가 있는 다운로드 파일, `$MFT` |
| Gemini Web(Chrome) | Gemini_Web_Parser 1.4.8.6 | Chrome History, Cache, Cookies, Preferences, Local/Session Storage, IndexedDB, Service Worker, `Zone.Identifier`가 있는 다운로드 파일, 휴지통 |
| LM Studio | LMstudio_parser(기준 앱 버전 0.4.21 Build 2) | `.lmstudio` 폴더, 프로그램·업데이터 폴더, 시작 메뉴 바로가기, Prefetch, Downloads/Desktop/Documents/Recycle Bin의 관련 파일, `$MFT`, USN 저널 |

웹 파서는 Google Chrome 프로필만 분석합니다. 애드온은 통합 실행기와 동일하게 각 파서의 기본 분석 옵션을 사용하며, Claude Web의 `--extended-fs` 옵션을 활성화하지 않습니다. 따라서 Claude Web에는 `$MFT`와 `Zone.Identifier`가 있는 다운로드 파일을 전달하지만, 해당 옵션에서 사용하는 USN 저널·휴지통 입력은 전달하지 않습니다. 다른 파서는 기본 분석에 필요한 경우 해당 아티팩트를 전달받습니다.

## 분석 결과

**CSV 열 이름은 영어지만 행위명, 판정, 상세 설명은 한국어로 작성됩니다.** 파서가 작성한 값을 그대로 Autopsy에 등록합니다.

`timeline.csv`(사용자 행위 한 건당 한 행):

| 열 | 내용 |
|---|---|
| `Model` | 서비스(예: `chatgpt-desktop`) |
| `Timestamp` | `YYYY-MM-DD HH:MM:SS.ffffff KST`. 알 수 없으면 `-` |
| `User_behavior` | 한국어 행위명(아래 표 참고) |
| `Behavior_details` | 한국어 설명 |
| `Verdict` | `확정`(confirmed) 또는 `의심`(suspected) |
| `Artifact_path` | 파서가 기록한 근거 파일 경로 |
| `Artifact_details` | 근거 상세 정보(레코드 ID, MFT 번호 등) |

`recovered_conversations.csv`(복구된 메시지 한 건당 한 행): `Model`, `timestamp`, `conversation_uuid`, `conversation_title`, `message_uuid`, `parent_message_uuid`, `message order`, `role`, `content`, `Artifact_path`.

Autopsy에서 타임라인 열은 **LLM User Behavior (ARTINEX)** 아티팩트의 속성(Timestamp (KST), LLM Service, User Behavior, Behavior Details, Verdict, Artifact Path, Artifact Details)이 됩니다. 메시지는 **Messages** 아티팩트가 됩니다. 메시지 유형은 파서 이름, 스레드 ID는 대화 UUID, 제목은 대화 제목이며 사용자 메시지는 발신 메시지로 표시됩니다.

`User_behavior`에서 사용하는 행위명(한국어 값 : 영어 의미):

| 값 | 의미 | 값 | 의미 |
|---|---|---|---|
| 로그인 | Login | 사용자 프롬프트 입력/전송 | Prompt entered/sent |
| 로그아웃 | Logout | 사용자 프롬프트 삭제 | Prompt deleted |
| 계정 전환 | Account switch | 임시 채팅 사용 | Temporary chat used |
| 계정 이름 변경 | Account renamed | 이미지 업로드 / 삭제 | Image uploaded / upload deleted |
| 애플리케이션 설치 | App installed | 문서 업로드 / 삭제 | Document uploaded / upload deleted |
| 애플리케이션 실행 | App launched | 문서 다운로드 | Document downloaded |
| 애플리케이션 삭제 | App uninstalled | 이미지 생성 요청 | Image generation requested |
| 정상 종료 | Normal exit | 생성 이미지 다운로드 / 삭제 | Generated image downloaded / deleted |
| 강제 종료 | Forced exit | 모델 변경 | Model changed |
| 새로운 대화 생성 | New conversation | 모델 다운로드 내역 | Model download history |
| 기존 대화 삭제 | Conversation deleted | 브라우저 시크릿 모드 | Browser incognito mode |
| 대화 수정 | Conversation edited | 방문기록 삭제 | Browsing history deleted |
| 대화 재시도 | Response regenerated | 캐시 삭제 | Cache deleted |
| 대화 공유 / 공유 링크 생성 | Conversation shared / share link created | 대화 데이터 Export | Conversation data exported |

## 알려진 제약 사항

- **검증 환경:** Windows 11과 Autopsy 4.23.1에서 raw(`.dd`) 형식의 NTFS 시나리오 이미지 2개로 검증했습니다. E01 이미지, BitLocker 볼륨, 다른 Autopsy 버전, 다른 운영체제는 애드온에서 검증하지 않았습니다.
- **독립 실행 모듈이 아님:** 전체 배포 패키지와 설치 스크립트가 생성하는 Python 3.12 환경이 필요합니다. 모듈 폴더만 복사해서 설치할 수 없습니다.
- **폴더 입력 모드:** 파서는 이미지 대신 추출 파일을 입력받습니다. 파서에 이미지를 직접 입력하는 경우와 비교하면 다음 차이가 있습니다.
  - Autopsy가 목록에 표시하는 삭제 파일(디렉터리 인덱스나 MFT에 이름이 남아 있는 파일)만 사용할 수 있으며, Claude Desktop 수집 범위의 삭제 파일만 내용까지 추출합니다.
  - 드라이브 문자는 항상 `C:`로 표시됩니다.
- **결과의 임시 경로:** Gemini Web과 LM Studio 결과 행은 원본 경로 대신 분석 PC의 임시 입력 폴더 경로(`…\vol<fs>\in_<parser>\Users\…`)를 표시합니다. `in_<parser>\` 뒤의 부분이 볼륨 내부 경로입니다. 정상 실행 후 해당 폴더가 삭제되므로 아티팩트에 연결된 Autopsy 파일로 확인하세요.
- **크기 제한:** `$MFT`와 `$UsnJrnl:$J`는 각각 1GB를 초과하면 추출하지 않으며, Downloads/Desktop/Documents의 메타데이터 수집은 20,000개에서 중단합니다. 두 경우 모두 영향을 받는 파서에 불완전 입력으로 보고합니다.
- **출력 언어:** 행위명과 설명은 한국어로만 제공됩니다.
- **제한 시간:** 파서별 실행 시간은 볼륨당 1시간으로 제한됩니다.

## 문제 해결

| 문제 | 해결 방법 |
|---|---|
| Ingest 모듈 목록에 ARTINEX가 없음 | 설치 스크립트 실행 후 Autopsy를 다시 시작하세요. `<python_modules>\ARTINEX\ARTINEX.py`가 있는지 확인하세요(Autopsy의 Tools → Python Plugins에서 해당 폴더를 열 수 있습니다). |
| 설치가 "parser environment preparation failed" 메시지와 함께 중단됨 | 해당 메시지 위의 내용을 확인하세요. 패키지를 다운로드하지 못했다면 PyPI와 GitHub에 접속할 수 있는 네트워크에서 설치를 다시 실행하세요. |
| uv가 없는 PC에서 보안 프로그램(예: AhnLab Safe Transaction, 진단명 `Execution/MDP.Powershell.M1201`)이 설치를 차단함 | 차단은 uv 설치가 끝난 뒤 발생합니다. **새 PowerShell 창**을 열어 설치 스크립트를 다시 실행하세요. 이를 피하려면 uv를 먼저 설치한 뒤 스크립트를 실행하세요(https://docs.astral.sh/uv/ 참고). |
| 설치가 "could not delete … .venv312" 메시지와 함께 중단됨 | 해당 Python을 사용하는 프로그램(예: Autopsy, 통합 실행기)을 종료하고 설치를 다시 실행하세요. |
| 설치가 "… is a junction or symbolic link" 메시지와 함께 중단됨 | 정션이나 링크를 직접 제거한 뒤 설치를 다시 실행하세요. |
| 파서에 `failed (exit N, see run.log)`가 표시됨 | 해당 파서 결과 폴더의 `run.log`를 여세요. 첫 줄에는 정확한 명령, 작업 폴더, 환경이 기록되어 있습니다. |
| `[incomplete input …]`가 표시됨 | 실행 폴더의 `export_skipped.txt`를 여세요. 각 줄에 사유(`error`, `big`, `meta_limit` 등)가 기록되어 있습니다. |
| 결과 행이 파일 대신 데이터 소스에 연결됨 | 해당 파서 결과 폴더의 `link_notes.txt`를 확인하세요. |
| 사건 폴더가 exFAT 또는 네트워크 드라이브에 있음 | 사건 폴더가 쓰기 또는 대체 데이터 스트림 검사를 통과하지 못하면 대체 작업 위치(`C:\artinex_work` 또는 설정의 `work_dir`)를 사용합니다. 사유는 Autopsy 로그(`work root …`)에 기록됩니다. |
| 배포 폴더를 이동함 | `artinex_config.json`이 새 위치를 가리키도록 설치 스크립트를 다시 실행하세요. |

## 라이선스 및 기여 정보

- **라이선스:** ARTINEX 자체 작성 코드(이 모듈, 파서, 통합 실행기)는 GNU Affero General Public License v3.0 이상(AGPL-3.0-or-later)으로 배포됩니다. Copyright (C) 2026 WHS4-Erelem contributors. 전문은 [`LICENSE`](../LICENSE)에 있습니다.
- **개발:** WHS4-Erelem, ARTINEX 프로젝트.
- **소스 코드:** https://github.com/WHS4-Erelem/LLM_Forensic_Parser
- **기반 도구:** [Autopsy](https://www.autopsy.com/)와 The Sleuth Kit(Basis Technology).
- **파서에서 사용하는 주요 외부 패키지**(설치 스크립트로 설치하며 ARTINEX에 포함되지 않습니다. 각각 자체 라이선스와 저작권 고지를 따릅니다): pytsk3, libewf-python, dissect.cstruct / util / ntfs / fve / evidence / volume, ccl_chromium_reader, ccl_simplesnappy, Brotli, cramjam, zstandard, zstd, pycryptodome. 설치 스크립트는 PyQt6도 설치하며, 이는 이 모듈이 아니라 ARTINEX 데스크톱 GUI에서 사용합니다.
