# ARTINEX 통합 실행기

ARTINEX 는 LLM 서비스 6종(ChatGPT Desktop, ChatGPT Web, Claude Desktop, Claude Web, Gemini Web, LM Studio) 파서를 하나로 묶은 포렌식 파서다. 이 폴더는 그 통합 실행기다.

디스크 이미지 하나를 주면 파서 6개를 순서대로 실행하고, 결과 CSV 가 공통 형식(헤더, 판정, 시각, 빈 셀)을 지키는지 검사한 뒤 SQLite 에 적재하고, 병합 `timeline.csv` / `recovered_conversations.csv` 와 실행 요약 `integration_report.json` 을 만든다. 표준 라이브러리만 쓴다.

## 실행

```
powershell -ExecutionPolicy Bypass -File setup.ps1            # 최초 1회: .venv312 생성 (uv 가 없으면 먼저 설치)
python llm_forensic.py -i <이미지.E01|.dd> -o out              # 전체 실행
python llm_forensic.py -i <이미지> -o out --only chatgpt_desktop,lmstudio
python llm_forensic.py -i <이미지> -o out --quick              # 이미지 전체 해시 생략 (개발용)
python llm_forensic.py --self-test
```

| 옵션 | 설명 |
|---|---|
| `-i`, `--image` | E01(분할 `.E01~`), raw(`.dd` `.raw` `.img`, 분할 `.001~`). 분할 이미지는 첫 세그먼트만 준다. 나머지를 모아 결번을 검사한다 |
| `-o`, `--out` | 결과 폴더. 그 아래 `<evidence_id>\` 에 쓴다 |
| `--registry` | 파서 레지스트리 (기본 `parsers.json`) |
| `--only a,b` | 지정한 파서만 실행. 나머지 파서의 이전 결과는 DB 에 남아 병합본에 그대로 포함된다 |
| `--quick` | 세그먼트 전체 SHA-256 계산을 건너뛴다. `evidence_sha256` 이 `-` 가 되어 무결성 대조에 쓸 수 없다 |

종료코드: 0 전부 성공 / 1 일부 파서 실패 또는 계약 위반 / 2 입력 실패 / 3 DB 또는 병합 출력 오류.

콘솔에는 통합기가 만든 요약(`[Evidence] [DB] [Runner] [Timeline] [Report] [Summary]`)만 나온다. 파서의 stdout/stderr 는 `<파서명>\run.log` 에만 남긴다. 실패하면 `[Runner]` 아래에 첫 오류 한 줄과 `detail:` 경로(실행 실패는 run.log, 계약 위반은 integration_report.json)를 보여 준다.

## 결과 (`out\<evidence_id>\`)

| 파일 | 내용 |
|---|---|
| `<파서명>\` | 파서별 원본 결과와 `run.log`(파서 버전, python, 명령, 시작 시각, stdout/stderr, 종료코드). 같은 이미지로 재실행하면 그 파서 폴더만 새 결과로 바뀐다. 통합 대상은 `timeline.csv`, `recovered_conversations.csv`, `run.log` 뿐이고 `result.json`, `cx_result.json` 같은 파서 고유 파일은 읽지 않는다 |
| `timeline.csv`, `recovered_conversations.csv` | 병합본. 원본 7열/10열은 헤더와 값 모두 파서가 쓴 그대로이고, 그 뒤에 provenance 열이 붙는다. 병합 CSV 로 쓸 때만 빈 값은 `-`, `=` `+` `-` `@` 로 시작하는 셀은 앞에 `'` 를 붙인다(Excel 수식 방지). `unified.db` 에는 원본 값 그대로 들어 있다 |
| `unified.db` | SQLite. evidence / runs / events / messages |
| `integration_report.json` | 파서별 상태(`success` / `failed` / `contract_violation` / `normalization_error` / `db_error`), 적재 행 수, 오류 목록 |
| `evidence_manifest.json` | 세그먼트별 `{file, size_bytes, sha256}` 와 전체 `evidence_sha256`. 분석이 끝난 뒤 같은 명령으로 다시 계산해 대조한다 |

`<파서명>\*.csv` 는 통합기가 고쳐 쓰지 않는다.

### 열 이름

파서 CSV 는 공통 헤더(`Model`, `Behavior_details ` 등 끝 공백 포함)와 바이트 단위로 같아야 받는다. 다르면 `HEADER_MISMATCH` 로 거부하고 고쳐 받지 않는다.

통합 내부(unified.db)에서만 canonical 이름을 쓴다: 앞뒤 공백 제거, 소문자, 공백은 `_`. 병합 CSV 의 헤더는 원본 그대로다.

- timeline: `model, timestamp, user_behavior, behavior_details, verdict, artifact_path, artifact_details`
- recovered_conversations: `model, timestamp, conversation_uuid, conversation_title, message_uuid, parent_message_uuid, message_order, role, content, artifact_path`

### provenance 열 (병합 CSV 와 DB 공통, 원본 열 뒤에 덧붙임)

| 열 | 뜻 |
|---|---|
| `timestamp`, `artifact_path` | 파서가 쓴 원본 값 |
| `timestamp_utc` | (DB 만) 원본 KST 표기를 UTC ISO 로 환산한 값. 병합 CSV 정렬에 쓴다 |
| `artifact_path_normalized` | 드라이브, 볼륨, 이미지 접두어를 떼고 `\` 구분, 소문자로 만든 경로. 검색과 중복 판별용. 여러 경로는 `\|` 로 나눠 각각 정규화한 뒤 ` \| ` 로 잇는다. NTFS ADS 표기(`:Zone.Identifier`, `:$J`)는 그대로 |
| `volume_ref` | 증거가 있던 볼륨의 드라이브 문자. 아래 설명 |
| `source_parser`, `parser_version`, `source_file`, `parse_time_utc` | 어느 파서의 어느 파일에서, 어떤 코드 버전(소스 해시 포함)으로, 언제(UTC) 나왔는지 |
| `evidence_id`, `evidence_sha256` | 어떤 이미지인지. `evidence_sha256` 은 세그먼트 전체를 순서대로 이어 계산한 SHA-256 이고, `evidence_id` 는 첫 64MiB 지문의 앞 16자로 폴더 이름용 식별자일 뿐 무결성 값이 아니다 |

`volume_ref` 는 파서가 확인한 값과 통합기의 추정을 표기로 구분한다.

- 파서가 드라이브 문자를 준 경로(`C:\…`)는 그 문자 그대로 `C:`.
- 파서가 `volumeN:` 이나 `::NTFS@오프셋/` 으로만 부르는 볼륨, 그리고 볼륨 표기 없는 루트 기준 경로(`Users/…`)는 같은 파서 결과 안에 그 볼륨의 `Users\` 또는 `Windows\` 경로가 있을 때만 시스템 볼륨으로 추정해 `C: (추정, volume0)` / `C: (추정, ntfs@227540992)` / `C: (추정)` 으로 적는다. 괄호 안은 파서가 준 볼륨 식별자다(경로에서, 없으면 `Artifact_details` 의 `volume=ntfs@오프셋`).
- 그 외(복구·데이터 파티션, 경로 없음)는 `-`.
- `(추정)` 이 붙은 값은 `SYSTEM\MountedDevices` 등으로 확인하고 쓴다. 두 볼륨에 모두 `Users` 가 있는 이미지(듀얼 부트, 옛 Windows 파티션)는 둘 다 `C:` 로 추정되고, 데이터 볼륨에 백업 `Users` 폴더만 있어도 그 볼륨이 `C:` 로 추정된다. 볼륨 표기 없는 상대 경로는 한 파서 결과 안에서 모두 한 볼륨으로 보므로 `Recovery/…`, `$Recycle.Bin/…` 도 `C:` 로 추정된다.

## 같은 이미지 재실행

- 실행 시작 시 한 트랜잭션으로 이전 결과를 지운다. 실패하면 `DB_ERROR` 로 파서를 실행하지 않고 종료코드 3.
  - 전체 실행: 해당 `evidence_id` 의 events/messages 전체를 지우고 이번 결과만 다시 적재.
  - `--only a,b`: `evidence_id` + `source_parser` 가 a, b 인 행만 지우고 교체. 실행하지 않은 파서의 결과는 병합본에 남는다.
- `runs` 는 실행 이력이라 지우지 않는다. `runs.status` 에 그 실행의 상태, `runs.violations` 에 오류 목록(JSON).
- 이전 버전이 만든 `unified.db` 는 처음 열 때 열 이름만 canonical 로 바꾼다. 행과 runs 이력은 보존하고 `artifact_path_normalized` 만 현재 규칙으로 다시 계산한다.

## 오류 유형

`integration_report.json` 과 `runs.violations` 의 항목은 parser, type, file, row, field, actual, expected, message 다. row 는 헤더를 1행으로 센 CSV 행 번호(Excel 에서 보이는 번호와 같다).

| 유형 | 상태 | 뜻 |
|---|---|---|
| `PARSER_EXECUTION_ERROR` | failed | 종료코드가 0 이 아님, 시간 초과, 실행 불가. 상세는 `<파서명>\run.log` |
| `UNSUPPORTED_INPUT` | failed | 레지스트리 `inputs` 에 없는 이미지 확장자. 파서를 실행하지 않고 사유만 run.log 에 남긴다 |
| `OUTPUT_MISSING` | failed | 레지스트리 outputs 의 CSV 가 없음 |
| `CSV_FORMAT_ERROR` | contract_violation | UTF-8 CSV 로 읽히지 않음 |
| `HEADER_MISMATCH` | contract_violation | 헤더가 공통 형식과 다름 (열 위치별로 공백·대소문자 차이 표시) |
| `COLUMN_COUNT_MISMATCH` | contract_violation | 행의 열 수가 다름 |
| `INVALID_TIMESTAMP` | contract_violation | `YYYY-MM-DD HH:MM:SS.ffffff KST` 또는 `-` 가 아님 |
| `INVALID_VERDICT` | contract_violation | `확정` / `의심` 이 아님 |
| `EMPTY_CELL` | contract_violation | timeline 의 빈 셀 (값이 없으면 `-`) |
| `NORMALIZATION_ERROR` | normalization_error | 통합 쪽 정규화 계산 실패 |
| `DB_ERROR` | db_error | DB 열기, 초기화, 적재, 조회 실패 |
| `OUTPUT_WRITE_ERROR` | — | 병합 CSV 나 보고서 쓰기 실패 (Excel 이 파일을 열고 있는 경우 등) |
| `UNKNOWN_USER_BEHAVIOR` | warning (success 유지) | `user_behaviors.txt` 에 없는 행위명. 적재는 하고 보고서와 콘솔에 파서·행·값을 남긴다 |

형식을 어긴 파서 결과는 고쳐 받지 않고 그 파서 결과 전체를 적재하지 않은 채 `contract_violation` 으로 보고한다. 병합본에 잘못된 행이 섞이지 않게 하기 위해서다.

`[Runner]` 가 `OK events=0 messages=0` 이면 콘솔에 0건 표시가 붙고 보고서의 `artifacts_found` 가 false 다. 흔적이 없는 것인지 파서가 입력을 못 읽은 것인지는 `<파서명>\run.log` 로 구분한다.

## 행위 분류 (`user_behaviors.txt`)

timeline 의 `User_behavior` 에 허용되는 이름 목록이다. 파서 6개가 같은 행위를 같은 이름으로 부르게 하는 공통 사양이고 배포본에 포함된다. 목록 밖 이름은 `UNKNOWN_USER_BEHAVIOR` 경고로 보고하되 적재는 한다. 파서들이 이름을 다 맞춘 뒤에는 `ERROR_STATUS["UNKNOWN_USER_BEHAVIOR"]` 를 `contract_violation` 으로 바꿔 위반으로 승격한다.

## 파서 레지스트리 (`parsers.json`)

파서는 손대지 않고 실행 방법만 레지스트리에 적는다. 파서마다 python, 작업 폴더, 인자(`{image}` `{out}` 치환), 출력 파일명, 시간 제한, 버전을 얻는 방법(CLI 또는 소스 상수)을 둔다. `parser_version` 에는 소스 전체의 해시(`code=`)를 항상 덧붙인다.

파서가 확장자를 검사해 거절하는 경우에만 `inputs` 에 지원 확장자를 선언한다(현재 gemini_web, lmstudio). 선언이 없으면 검사하지 않는다. 파서의 허용 목록이 넓어지면 이 선언도 같이 갱신한다.

## 정답지 대조 (개발·검증 전용, `validation\`)

실제 분석에서는 쓰지 않는다. 정답 시트가 있는 실험 이미지에서 파서 탐지력을 재는 도구이며, `llm_forensic.py` 는 이 폴더를 읽지 않는다.

```
python validation\verify_merged.py --timeline out\<evidence_id>\timeline.csv --key validation\scenario_keys\plain_2026-09-15.csv
```

서비스별 정답지(`validation\scenario_keys\*.csv`: model, event_id, action, kst)와 병합 타임라인을 ±120초 창으로 대조해 `verify_report.md` 를 만든다.

## 실행 환경

`setup.ps1` 은 uv 가 없으면 공식 설치 스크립트로 먼저 설치한 뒤, `.venv312`(Python 3.12) 하나를 만들고 파서 6개의 requirements 와 GUI 의 `gui/requirements.txt`(PyQt6)를 모두 설치한다. 이미 `.venv312` 가 있으면 새로 만들지 않고 패키지만 맞추며, 설치가 하나라도 실패하면 그 자리에서 멈춘다. 3.12 로 고정한 이유는 `pytsk3`, `libewf-python` 의 Windows 휠이 3.12 까지만 있고, Claude Web 파서의 zstd 가 3.14 에서는 MSVC 빌드를 요구하기 때문이다. Autopsy 애드온(`../Autopsy_Addon`)도 같은 환경을 쓴다.
