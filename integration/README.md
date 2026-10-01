# LLM 파서 통합 실행기

이미지 하나를 주면 파서 6개를 순서대로 실행하고, 결과 CSV 계약(헤더·판정·시각·빈 셀 `-`)을 검사한 뒤
SQLite 에 적재하고 병합 `timeline.csv` / `recovered_conversations.csv` 와 실행 요약 `integration_report.json` 을 만든다.

```
powershell -ExecutionPolicy Bypass -File setup.ps1            # 최초 1회: .venv312 / .venv314 생성
python llm_forensic.py -i <이미지.E01|.dd> -o out              # 전체 실행
python llm_forensic.py -i <이미지> -o out --only chatgpt_desktop,lmstudio
python llm_forensic.py --self-test
```

결과: `out\<evidence_id>\`
- `<파서명>\` 파서별 원본 결과(그대로 보존, 같은 이미지로 재실행하면 그 파서 폴더만 새 결과로 교체) + `run.log`(파서 버전·python·명령·시작 시각·stdout/stderr·종료코드)
  - 통합 대상은 계약 CSV 2개(`timeline.csv`, `recovered_conversations.csv`)와 `run.log` 만이다. `result.json`, `cx_result.json`, `gemini_results.json` 같은 그 외 파일은 파서 담당자가 남기는 고유 부산물(원본 레코드·규칙 판정 상세)로, 파서마다 있거나 없고 형식도 다르다. 통합기는 읽지 않는다 (예외: 레지스트리 `volume_json` 으로 지정한 파서의 JSON 에서 볼륨 오프셋만 꺼낸다).
- `timeline.csv`, `recovered_conversations.csv` 병합본 — 팀 7열/10열은 헤더·값 모두 파서가 쓴 그대로, 그 뒤에 provenance 열
- `unified.db` — evidence / runs / events / messages
- `integration_report.json` — 파서별 상태(`success` / `failed` / `contract_violation` / `normalization_error` / `db_error`), 적재 행 수, 오류 목록
- `evidence_manifest.json` — 세그먼트별 `{file, size_bytes, sha256}` 매니페스트 + 전체 `evidence_sha256`. 분석 종료 후 같은 명령으로 다시 계산해 대조한다

열 이름 (canonical header)
- 파서 CSV 는 팀 계약 헤더(`Model`, `Behavior_details ` 등 끝 공백 포함)와 바이트 단위로 같아야 받는다. 다르면 고쳐 받지 않고 `HEADER_MISMATCH`.
- 계약 검사를 통과한 뒤 통합 내부(unified.db)에서만 canonical 이름을 쓴다: 앞뒤 공백 제거 → 소문자 → 공백은 `_`. 병합 CSV 의 헤더는 팀 계약 이름 그대로다 (벤치마크·파서 출력과 같은 헤더).
  - timeline: `model, timestamp, user_behavior, behavior_details, verdict, artifact_path, artifact_details`
  - recovered_conversations: `model, timestamp, conversation_uuid, conversation_title, message_uuid, parent_message_uuid, message_order, role, content, artifact_path`
- 파서가 쓴 CSV 파일(`<파서명>\*.csv`)은 다시 쓰지 않는다.

provenance 열 (병합 CSV·DB 공통, 원본 열을 덮어쓰지 않고 덧붙임)

| 열 | 뜻 |
|---|---|
| `timestamp`, `artifact_path` | 파서가 쓴 원본 값 (timestamp_raw, artifact_path_raw) |
| `timestamp_utc` | (DB 만) 원본 KST 표기를 UTC ISO 로 환산한 정규화 시각. 병합 CSV 정렬에 쓴다 |
| `artifact_path_normalized` | 경로마다 드라이브·볼륨·이미지 접두어 제거, `\` 구분, 소문자 — 검색·중복 판별용. 여러 경로는 `\|` (앞뒤 공백 무관)로 나눠 각각 정규화한 뒤 ` \| ` 로 잇는다. NTFS ADS 스트림 표기(`:Zone.Identifier`, `:$J`)는 원문 그대로 |
| `volume_ref` | 파서가 준 볼륨 식별자 (`ntfs@오프셋`, `volume0`), 없으면 `-` |
| `source_parser`, `parser_version`, `source_file`, `parse_time_utc` | 어느 파서의 어느 파일에서, 어떤 코드 버전(소스 해시 포함, 줄바꿈 CRLF/LF 차이는 무시)으로, 언제(UTC, 예 `2026-09-21T19:22:46Z`) 나왔는지 |
| `evidence_id`, `evidence_sha256` | 어떤 증거 이미지인지. `evidence_sha256` 은 세그먼트 전체(E01 분할·raw 분할 모두)를 순서대로 이어 계산한 SHA-256 (무결성 대조용). `evidence_id` 는 첫 64MiB 지문(`evidence_quick_fingerprint`)의 앞 16자로, 폴더명 식별자일 뿐 무결성 값이 아니다. `--quick` 이면 `evidence_sha256`='-' |

같은 evidence 재실행 (unified.db)
- 실행 시작 시 한 트랜잭션으로 이전 결과를 지운다. 실패하면 `DB_ERROR` 로 파서를 실행하지 않고 종료코드 3.
  - 전체 실행: 해당 `evidence_id` 의 events/messages 전체를 지우고 이번 결과만 다시 적재
  - `--only a,b`: `evidence_id` + `source_parser` 가 a, b 인 행만 지우고 교체. 실행하지 않은 파서의 결과는 그대로 병합본에 남는다
- `runs` 는 지우지 않는다 (실행 이력·provenance). `runs.status` 에 그 실행의 상태, `runs.violations` 에 오류 목록(JSON).
- 이전 버전이 만든 unified.db 는 처음 열 때 열 이름만 canonical 로 바꾼다 (행·runs 이력 보존, `artifact_path_normalized` 만 현재 규칙으로 다시 계산).

오류 유형 (`integration_report.json` · `runs.violations`, 항목: parser, type, file, row, field, actual, expected, message. row 는 헤더를 1행으로 센 CSV 행 번호)

| 유형 | 상태 | 뜻 |
|---|---|---|
| `PARSER_EXECUTION_ERROR` | failed | 종료코드≠0 · 시간 초과 · 실행 불가 (상세는 `<파서명>\run.log`) |
| `UNSUPPORTED_INPUT` | failed | 레지스트리 `inputs` 에 없는 이미지 확장자. 파서를 실행하지 않고 사유만 run.log 에 남긴다 |
| `OUTPUT_MISSING` | failed | 레지스트리 outputs 의 CSV 가 없음 |
| `CSV_FORMAT_ERROR` | contract_violation | UTF-8 CSV 로 읽히지 않음 |
| `HEADER_MISMATCH` | contract_violation | 헤더가 계약과 다름 (열 위치별, 공백·대소문자 차이 표시) |
| `COLUMN_COUNT_MISMATCH` | contract_violation | 행의 열 수가 계약과 다름 |
| `INVALID_TIMESTAMP` | contract_violation | `YYYY-MM-DD HH:MM:SS.ffffff KST` 또는 `-` 가 아님 |
| `INVALID_VERDICT` | contract_violation | `확정` / `의심` 이 아님 |
| `EMPTY_CELL` | contract_violation | timeline 의 빈 셀 (값이 없으면 `-`) |
| `NORMALIZATION_ERROR` | normalization_error | 통합 쪽 정규화 계산 실패 |
| `DB_ERROR` | db_error | DB 열기·초기화·적재·조회 실패 |
| `OUTPUT_WRITE_ERROR` | — | 병합 CSV·보고서 쓰기 실패 (엑셀 등이 파일을 열고 있는 경우 등) |
| `UNKNOWN_USER_BEHAVIOR` | warning (success 유지) | `user_behaviors.txt` 에 없는 행위명. 적재는 하고 파서 담당자에게 알린다 |

콘솔에는 통합이 만든 요약(`[Evidence] [DB] [Runner] [Timeline] [Report] [Summary]`)만 나온다. 파서 stdout/stderr 는 콘솔에 섞지 않고 `<파서명>\run.log` 에만 남긴다.
실패 시 `[Runner]` 아래에 첫 오류 한 줄과 `detail:` (실행 실패는 run.log, 계약 위반은 integration_report.json) 경로를 보여 준다.

행위 분류 체계 (`user_behaviors.txt`)
- timeline 의 `User_behavior` 에 허용되는 이름 목록. 파서 6개가 같은 행위를 같은 이름으로 부르게 하는 팀 스펙이며, 배포본에 포함된다 (정답지 `validation\scenario_keys\` 는 검증 전용).
- 목록 밖 이름은 `UNKNOWN_USER_BEHAVIOR` **경고**로 `integration_report.json` 과 콘솔에 파서·행·값을 남기되 적재는 한다. 파서 담당자가 이름을 맞추거나, 새 행위면 팀 합의 후 목록에 추가한다.
- 파서들이 이름을 다 맞춘 뒤에는 `ERROR_STATUS["UNKNOWN_USER_BEHAVIOR"]` 를 `contract_violation` 으로 바꿔 위반으로 승격한다.

정답지 대조 (개발·검증 전용, `validation\`)

실제 분석에서는 쓰지 않는다. 실험 이미지처럼 정답 시트가 있을 때 파서 탐지력을 재는 도구이며, `llm_forensic.py` 는 이 폴더를 읽지 않는다.

```
python validation\verify_merged.py --timeline out\<evidence_id>\timeline.csv --key validation\scenario_keys\plain_2026-09-15.csv
```
서비스별 정답지(시트 export, `validation\scenario_keys\*.csv`: model, event_id, action, kst)와 병합 타임라인을 ±120초 창으로 대조해 `verify_report.md` 를 만든다.

규칙
- 파서는 손대지 않는다. 실행 방법은 `parsers.json` 레지스트리에만 적는다.
- 파서가 확장자를 검사해 거절하는 경우에만 레지스트리 `inputs` 에 지원 확장자를 선언한다 (현재 claude_desktop·gemini_web·lmstudio). 선언이 없으면 검사하지 않는다. 담당자가 파서의 허용 목록을 넓히면 이 선언도 같이 갱신한다.
- 입력 이미지: E01 분할(.E01~)과 raw 분할(.001, .002 …)은 첫 세그먼트 경로만 주면 나머지를 모아 결번을 검사한다. `.dd`/`.raw`/`.img` 단일 파일도 된다.
- `[Runner]` 가 `OK events=0 messages=0` 이면 콘솔에 0건 표시가 붙고 보고서의 `artifacts_found` 가 false 다. 흔적이 없는 것인지 파서가 입력을 못 읽은 것인지는 `<파서명>\run.log` 로 구분한다.
- `artifact_path` 는 파서 표기 그대로 두고, 검색·중복 판별은 `artifact_path_normalized` 로 한다 (드라이브 문자 추정 안 함).
- `volume_ref` 는 파서가 준 값만 옮긴다. 우선순위: Artifact_details 의 `volume=` / `partition_offset=` 키 → 경로의 `NTFS@오프셋`·`volumeN` → 레지스트리 `volume_json`(실행 단위 JSON) → `-`.
  현재 chatgpt_desktop·gemini_web 은 행 단위, chatgpt_web 은 실행 단위, lmstudio 는 경로(volume0), claude_desktop·claude_web 은 미제공(`-`).
- 헤더·열 수·Verdict·Timestamp·빈 셀 계약을 어긴 파서 결과는 고쳐 받지 않고 그 파서 결과 전체를 적재하지 않은 채 `contract_violation` 으로 보고한다 (위 오류 유형 표).
- 종료코드 0 전부 성공 / 1 일부 실패·위반 / 2 입력 실패 / 3 통합 DB·병합 출력 오류.

실행 환경: `.venv312` = ChatGPT Desktop·ChatGPT Web·Claude Desktop·Claude Web·Gemini, `.venv314` = LM Studio (`setup.ps1` 참조).
