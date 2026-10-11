# ChatGPT Desktop 파서 (cxparser)

Windows 용 ChatGPT 데스크톱 앱이 남기는 흔적을 디스크 이미지, 추출 폴더, 실행 중인 PC 에서 찾아 사용자 행위 타임라인과 복원 대화를 만든다.

대상은 MS Store 패키지 `OpenAI.Codex_2p2nqsd0c76g0` 다. 이 앱 하나에 ChatGPT 채팅(chat 모드)과 Codex 에이전트(work 모드)가 들어 있고, 두 모드의 흔적은 서로 다른 곳에 남는다.

- work 모드: `~/.codex/` 아래 세션 JSONL, SQLite, 전역 상태 파일. 대화 본문이 평문으로 남는다.
- chat 모드: 패키지 폴더(`AppData\Local\Packages\OpenAI.Codex_…`) 안 채팅창의 HTTP 캐시와 Sentry breadcrumb. 캐시는 앱을 삭제하면 사라지고, 응답을 캐시하지 않는 앱 버전에서는 전송 시각만 남는다.

결과 JSON 에는 대화 원문, 프롬프트, 계정 UUID 가 평문으로 들어간다(토큰 값은 마스킹). 사건 자료와 같이 취급한다.

## 설치와 실행

이미지 입력에는 Python 3.12 와 아래 라이브러리가 필요하다. `libewf-python` 의 Windows 휠이 3.10~3.12 까지만 있다. 폴더 입력과 라이브 분석은 표준 라이브러리만으로 돈다.

| 역할 | 라이브러리 |
|---|---|
| E01 읽기 | libewf (`libewf-python`, `import pyewf`) |
| RAW 읽기, 파티션, NTFS | The Sleuth Kit (`pytsk3`) |
| BitLocker 해제 | `dissect.fve` (BitLocker 볼륨을 만났을 때만 불러온다) |

이 저장소에서는 `../integration/setup.ps1` 이 만드는 `integration/.venv312` 를 그대로 쓴다. 따로 만들려면:

```
uv venv --python 3.12 .venv
uv pip install --python .venv/Scripts/python.exe -r requirements.txt
.venv/Scripts/python.exe run_parser.py -i <image.E01|image.dd|추출폴더> -o out
```

`python -m cxparser` 로 실행해도 같다.

| 옵션 | 설명 |
|---|---|
| `-i`, `--input` | E01(분할 `.E02…` 포함) / RAW `.dd` `.raw` `.img`(분할 `.001` 포함) / 추출 폴더. 분할 이미지는 첫 세그먼트만 준다 |
| `--input-type` | `auto`(기본, 경로를 보고 판별) / `image` / `dir` / `live`. `live` 는 실행 중인 이 PC 를 직접 읽는다. 자동 선택되지 않으며 `--input` 을 생략하면 시스템 드라이브 |
| `-o`, `--out-dir` | 결과 폴더 (기본 `cx_out`) |
| `--format` | `csv`(기본, 공통 CSV 2종) / `json`(`cx_result.json`) / `both` |
| `--kinds` | 파싱할 아티팩트 종류를 쉼표로 고른다 (기본 전체: `rollout,rollout_loose,session_index,global_state,auth,sqlite,prefetch,recent_lnk,webcache,sentry_scope`) |
| `--max-file-mb` | 파일 하나의 크기 상한 (기본 1024). 넘으면 그 파일만 `FILE_TOO_LARGE` 로 건너뛴다 |
| `--no-usn` | `$UsnJrnl:$J` 파싱 생략 (기본은 이미지 입력, 또는 추출 폴더에 `$Extend/$UsnJrnl:$J` 가 있으면 파싱) |
| `--usn-max-bytes` | `$J` 에서 읽을 최대 바이트 (기본 전체) |
| `--max-excerpt` | 근거 발췌 최대 문자 수 (기본 500) |
| `--key-material` | BitLocker 키. `recovery:<48자리 복구 키>` / `passphrase:<암호>` / `bek:<.BEK 경로>` / `fvek:<hex>`. 환경변수 `ERELM_KEY_MATERIAL` 로 줘도 된다. 일시 중단(clear key) 상태는 키 없이 풀린다 |
| `--overwrite` | 출력 폴더에 기존 결과가 있어도 덮어쓴다 (기본은 거부, 종료코드 2) |
| `--quiet` | 콘솔 요약 생략 |

원본 이미지는 읽기 전용으로만 연다. 결과는 `--out-dir` 아래에만 쓴다.

### 출력 파일

`timeline.csv` — 공통 타임라인 형식 7열 `Model, Timestamp, User_behavior, Behavior_details , Verdict, Artifact_path, Artifact_details `. 헤더는 끝 공백까지 공통 형식과 바이트 단위로 같다.

- Model 은 `chatgpt-desktop`, Timestamp 는 `YYYY-MM-DD HH:MM:SS.ffffff KST`
- User_behavior 는 행위 카탈로그의 이름, Behavior_details 는 `<흔적 성격>_<내용>`
- Verdict 는 `확정` / `의심`. 판단 불가와 관찰(NA-00)은 CSV 에 넣지 않고 JSON 에만 남긴다
- Artifact_path 는 `C:\Users\…` 표기. 드라이브 문자는 이미지의 `SYSTEM\MountedDevices` 로 확인한 값이고, 확인하지 못하면 `C:` 로 가정한다
- Artifact_details 는 `[Rollout|SQLite|WebCache|…] 유형=…, 대화 UUID=…, 위치=…, MFT=…, 규칙=E04-01, 패키지=…`

`recovered_conversations.csv` — 공통 대화 형식 10열 `Model, timestamp, conversation_uuid, conversation_title, message_uuid, parent_message_uuid, message order, role, content, Artifact_path`. rollout, SQLite, 웹 캐시의 user/assistant 메시지. 대화별 message order 는 1..n, parent 는 직전 메시지(첫 메시지는 `00000000-0000-4000-8000-000000000000`).

`cx_result.json` (`--format json|both`) — 전체 레코드(판단 불가와 관찰 포함), 스캔 정보, 스키마 관찰, USN 요약, 경고와 오류.

공통 관례: 빈 셀은 `-`, 셀이 `= + - @` 로 시작하면 앞에 `'` 를 붙인다(Excel 수식 방지), 출력 폴더에 기존 결과가 있으면 거부.

## 파싱 대상

| kind | 경로 | 행위 |
|---|---|---|
| `rollout` | `~/.codex/sessions/YYYY/MM/DD/rollout-<시각>-<스레드ID>[_<분기ID>].jsonl` | E03-01 새 대화 생성, E03-03 대화 수정(분기 파일), E04-01 프롬프트 전송, E06-01 이미지 생성 요청(이미지 생성 도구 호출), E09-01 모델 변경(`turn_context.model` 변화), 첨부 업로드(본문의 `# Files mentioned by the user` 목록) |
| `session_index` | `~/.codex/session_index.jsonl` | E03-01 대화 목록 등재 |
| `global_state` | `~/.codex/.codex-global-state.json` | E04-01 프롬프트 이력(`prompt-history`), 계정 UUID 열거(2개 이상이면 E01-03 계정 전환 근거). 선택 모델과 스레드 바인딩은 관찰만 |
| `auth` | `~/.codex/auth.json` | E01-01/02/03 로그인·로그아웃·계정 전환의 근거 (토큰 값은 출력하지 않음) |
| `sqlite` | `~/.codex/state_5.sqlite`, `thread_history_1.sqlite`, `logs_2.sqlite` (+`-wal`/`-shm`) | E03-01/03 대화 생성·수정, E04-01 프롬프트(행마다 시각 있음), E01-02 로그아웃 로그, E08-01/02 앱 실행·종료(`process_uuid` 구간) |
| USN | `$Extend/$UsnJrnl:$J` (이미지, 또는 추출 폴더에 꺼내 둔 경우) | 파일 생성·삭제 시각. 로그인(auth.json 생성), 로그아웃(auth.json 삭제), 계정 전환, 대화 삭제 |
| `prefetch` | `Windows/Prefetch/CODEX.EXE-*.pf`, `CHATGPT.EXE-*.pf` | E08-01 앱 실행 (OS 가 기록한 최근 8회). MAM 압축 해제는 Windows 에서만 |
| `recent_lnk` | `Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk` | E06-02 생성 이미지 다운로드, E05-05 문서 다운로드 |
| 패키지 폴더 | `Program Files/WindowsApps/OpenAI.Codex_*` 의 폴더 시각 | E02-01 앱 설치 |
| `webcache` | 패키지 `LocalCache\Roaming\Codex\web\Codex\Default\Cache\Cache_Data\` | 채팅 모드 대화 전체. E03-01 대화 생성, E04-01 프롬프트(본문·시각), E05-01/03 첨부 업로드, E06-01 이미지 생성, E03-03/04 대화 수정·재시도, E10-01 임시 채팅, E09-01 모델 변경(`default_model_slug` 변화, 의심), E05-05/E06-02 파일 내려받기(`estuary/content?…&fn=`). assistant 응답은 대화 CSV 로 |
| `sentry_scope` | 패키지 `LocalCache\Roaming\Codex\web\Codex\sentry\scope_v3.json` | 채팅 모드의 서버 요청 기록. E04-01 프롬프트 전송(`POST /backend-api/f/conversation` 과 직전 검사 요청), E03-01 새 대화(`conversation/init` 뒤 전송이 이어진 경우). 본문과 파일명은 없고 최근 100개 안팎만 남는다 |

탐색 디렉터리(`locate.SCAN_ROOTS`): `Users/*/.codex`, `Users/*/Documents/Codex`, `Users/*/AppData/Local/Packages/OpenAI.Codex_2p2nqsd0c76g0`, `Program Files/WindowsApps/OpenAI.Codex_*`, `ProgramData/Packages/OpenAI.Codex_2p2nqsd0c76g0`, `Windows/Prefetch`, `Users/*/AppData/Roaming/Microsoft/Windows/Recent`. 이 안에서 표에 없는 파일(나머지 SQLite, IndexedDB 같은 채팅창 저장소, Helium 하이브)은 발견 목록(`artifact_inventory`)에만 적고 파싱하지 않는다.

## 판정 규칙

### 확신도와 Verdict

- `확인`(아티팩트 내용이 행위를 직접 보여 줌)은 CSV 의 `확정`, `추정`(정황)은 `의심`, `미확정` 은 CSV 에서 뺀다.
- 파일의 존재나 부재, 스레드 바인딩, 인증 변경 로그처럼 행위를 특정할 수 없는 근거는 `NA-00` 관찰 레코드로만 남기고 `details.candidate_event` 에 후보 행위를 적는다. 후속 도구가 이를 확정 행위로 올리면 안 된다.

### 시각

- 파일 수정 시각을 메시지 전송 시각으로 쓰지 않는다. MFT 시각($SI/$FN)은 `evidence.location` 에만 두고, `timestamp` 는 아티팩트 내용이나 파일명에서 읽은 값만 쓴다(`timestamp.source` 로 구분).
- 타임존 표기가 없는 값은 UTC 로 단정하지 않는다. rollout 파일명의 `2026-08-29T02-22-56` 같은 값은 `utc: null` 에 원본값과 사유를 남긴다.
- 시각 미상 레코드는 `undated_records` 로 분리하고, CSV 에서는 맨 뒤에 둔다.

### 레코드를 서로 대조해 올리는 행위 (`derive.py`)

- 로그인 E01-01: 앱 로그 `Reloaded auth, changed: true` 와 USN `auth.json FILE_CREATE` 가 ±120초 안에 있으면 확인, 한쪽만 있으면 추정.
- 계정 전환 E01-03: USN 에서 auth.json 삭제 뒤 재생성이 있고 전역 상태에 계정 UUID 가 2개 이상일 때만 추정. UUID 가 1개면 같은 계정 재로그인으로 본다.
- 첨부 업로드 E05-01/03: 프롬프트 본문의 `# Files mentioned by the user` 목록. (행위, 파일명)당 1건, 시각 있는 쪽 우선.
- 앱 실행·종료 E08-01/02: `logs_2.sqlite` 의 `process_uuid` 구간 시작과 끝. 직전 프로세스가 끝난 지 10초 안에 뜬 프로세스는 자동 재시작으로 보고 의심. 앱이 종료 로그를 남기지 않아 정상 종료와 강제 종료는 구분하지 않는다.
- 최근 항목 바로가기로 잡은 문서 저장은 앱 프로세스 구간 안에 있고 Codex 대화에 그 파일명이 언급될 때만 유지하고, 아니면 미확정으로 내린다. 다른 앱이 저장한 파일을 Codex 로 귀속하지 않기 위해서다.

### 아티팩트별 규칙

- 설치 E02-01 = 패키지 폴더의 마지막 수정 시각(패키지 쓰기 완료). 생성 시각(받기 시작)은 근거에 함께 적는다.
- 모델 변경 E09-01 은 바뀐 지점이 보이는 아티팩트로만 판정한다. rollout `turn_context.model` 변화는 확인, 웹 캐시 `default_model_slug` 변화는 추정. 전역 상태의 `chatgpt-last-selected-model-v1` 은 현재 상태값이라 관찰로만 남긴다.
- 최근 항목 바로가기: 대상이 `Codex 이미지 …` 이면 E06-02 확인. 그 밖에는 대상 파일이 바로가기와 같은 시각(±15초)에 새로 생겼을 때만 추정으로 내고, 종류는 확장자와 머리 바이트(PDF, Office, PNG 등)로 판별한다. 종류를 알 수 없으면 E05-05 에 '종류 미확인' 사유를 적는다. 이미지는 앱 명명 규칙이 아니어도 E06-02 추정.
- rollout 의 role=user 라인은 `content_item_kinds` 로 나눈다. `user.text` 는 E04-01 확인, 앱이 자동 주입한 문맥(`plugins.recommendations`, `environments.environment_context`)은 NA-00, `## Referenced ChatGPT conversation` 으로 시작하는 채팅→작업 모드 인계 요청은 E04-01 추정. 라인 구조를 단정하지 않고 관찰된 구조를 `schema_observations` 로 보고하며, 매핑되지 않은 라인은 버리지 않고 미확정 레코드로 남긴다.
- Sentry breadcrumb: 전송 직전 검사 요청(`sentinel/chat-requirements`) 뒤 10초 안에 전송 요청(`f/conversation`)이 있으면 확인, 한쪽만 있으면 추정. `conversation/init` 은 파일 내려받기나 앱 종료 때도 오므로 다음 init 전에 전송이 이어진 경우만 E03-01 추정.
- 대화 목록 응답과 `codex-dev.db` 의 `local_thread_catalog` 는 계정의 서버 대화 목록이라(다른 기기의 대화 포함) 행위 근거로 쓰지 않는다.

### 타임라인 정리 (`output.py`)

- 같은 프롬프트가 rollout, SQLite, 웹 캐시, 전역 상태 여러 곳에 있으면 시각 있는 행 하나에 접고 나머지는 그 행의 Artifact_details 에 적는다.
- 앱 실행: 앱 로그와 Prefetch 가 60초 안에 겹치면 로그 행 하나만. 앱 프로세스 구간 안에서 뜬 Prefetch 실행은 앱이 띄운 보조 프로세스라 타임라인에서 뺀다(JSON 에는 남음).
- 다운로드: 같은 파일이 웹 캐시(내려받기 요청, 확인)와 바로가기(저장된 파일, 추정)에 60초 안에 있으면 웹 캐시 행 하나만.
- 대화 CSV: 같은 (역할, 본문)이 2초 안에 있고 같은 대화 ID 이거나 다른 아티팩트(rollout ↔ SQLite)면 같은 메시지의 사본으로 보고 rollout 1행만 둔다. 같은 아티팩트 안의 다른 대화에 같은 본문이 있으면 별개 메시지다.

### 로컬 흔적이 없어 잡지 못하는 것

공유 링크와 대화 공유, 계정 이름 변경(POST 요청은 캐시되지 않음), 강제 종료(정상 종료와 구분 불가), 앱 삭제(USN 저널이 그 구간을 덮을 때만), 에이전트 모드의 임시 채팅, 채팅 모드 대화 본문(응답을 캐시하지 않는 앱 버전에서는 Sentry 의 전송 시각만).

## 출력 레코드 구조 (`cx_result.json`)

모든 레코드에 `timestamp`, `user_action`, `evidence` 세 항목이 항상 있다. 모르는 값은 `null` 과 사유로 적는다. `details` 의 하위 키는 아티팩트마다 다르다.

```jsonc
{
  "record_id": "R000013",
  "event": {"event_id": "E04-01", "event_name": "사용자 프롬프트 입력/전송"},
  "timestamp": {
    "utc": "2026-08-28T17:23:28.900000Z",
    "original_value": "2026-08-28T17:23:28.900Z",
    "original_format": "ISO8601",
    "meaning": "rollout JSONL 라인에 기록된 메시지 시각",
    "source": "artifact_content",        // artifact_content | artifact_filename | ntfs_mft | none
    "timezone_note": null,
    "null_reason": null
  },
  "user_action": {
    "action": "프롬프트 전송",
    "confidence": "확인",                 // 확인 | 추정 | 미확정
    "rationale": "rollout JSONL 의 role=user 메시지 라인",
    "observed_artifact": null            // 미확정일 때 관찰된 내용
  },
  "evidence": {
    "image": {"image_id": "case.E01 (sha256[prefix]=…)", "image_type": "ewf", "reader": "libewf …"},
    "location": {
      "path": "/Users/<user>/.codex/sessions/2026/08/29/rollout-….jsonl",
      "size_bytes": 1234, "allocated": true,
      "mft_record": 210124, "mft_sequence": 1,
      "partition_index": 0, "partition_offset_bytes": 1048576,
      "ntfs_standard_information": {"created": "…", "modified": "…", "mft_modified": "…", "accessed": "…"},
      "ntfs_file_name": {"created": "…", "modified": "…", "mft_modified": "…", "accessed": "…"}
    },
    "locator": "line=11",                // line=N / json_pointer=… / file
    "artifact_sha256": "…",
    "excerpt": "…"
  },
  "parse": {"status": "ok|partial|error", "errors": [], "notes": []},
  "details": { … }
}
```

## 오류와 종료코드

| 코드 | 의미 |
|---|---|
| `IMAGE_OPEN_FAILED` | 이미지 없음, 권한 없음, E01 열기 실패, E01 첫·끝 섹터 읽기 실패(절단·손상) |
| `SEGMENT_MISSING` | E01 확장자 결번, 마지막 E01 세그먼트 누락(마지막 파일이 `next` 섹션으로 끝남), 분할 RAW 중간 결번 |
| `UNSUPPORTED_FORMAT` | EWF2(.Ex01), L01, VMDK/VHD/QCOW, 읽을 수 있는 NTFS 볼륨 없음 |
| `VOLUME_LOCKED` | BitLocker 볼륨을 풀지 못했고, 읽을 수 있는 볼륨 중에 BitLocker 를 푼 것도 Windows 시스템 볼륨(`\Users`)도 없음. 평문 OS 볼륨이 있으면 중단하지 않고 잠긴 볼륨을 `warnings` 에 남긴다. `context.volumes[].protectors` 에 그 볼륨이 받는 키 종류 |
| (경고) 아티팩트 0건 | 이미지는 읽혔으나 Codex 경로가 없음. 오류가 아니라 0행 결과 + 경고(종료코드 0). 앱을 쓰지 않은 이미지에서 '없음' 이 정상 결과이기 때문 |
| 레코드 단위 | `JSON_DECODE_ERROR`, `READ_FAILED`, `FILE_TOO_LARGE` 등. 해당 레코드만 `status: error`, 같은 파일의 나머지는 계속 파싱 |

종료코드 0 = 오류 없음, 1 = 파일 단위 오류 있음, 2 = 입력 자체 실패. 실패를 빈 결과나 성공으로 숨기지 않는다.

## 지원 범위와 한계

지원

- 이미지: EWF v1 `.E01`(분할 `.E02…/.EAA…`), RAW `.dd/.raw/.img`, 분할 RAW `.001…`
- 파티션: TSK 가 읽는 MBR/GPT, 파티션 테이블 없는 볼륨 이미지
- 파일시스템: NTFS 만. 다른 파일시스템 파티션은 `skipped_partitions` 에 사유와 함께 기록
- BitLocker: clear key(일시 중단, 활성화 대기)와 복호화 완료 상태는 키 없이, 그 외는 `--key-material` 로
- 삭제 파일: 디렉터리 인덱스에 남은 삭제 이름, 그리고 인덱스에서도 지워진 경우 미할당 MFT 엔트리의 `$FILE_NAME` 부모 참조가 탐색 디렉터리와 일치하면 경로 복원(`allocated: false`, `path_source` 기재)

한계

- EWF2(`.Ex01`), L01, VMDK/VHD/QCOW, BitLocker 이외의 암호화 볼륨, TPM 만으로 보호된 BitLocker(복구 키 없이는 풀 수 없다)
- FAT/exFAT/ReFS
- 부모 디렉터리까지 삭제·재할당된 파일은 경로 복원 불가, 클러스터가 덮어써진 삭제 파일은 내용 불일치 가능
- 파일 카빙(미할당 영역 스캔) 없음
- USN 레코드에는 경로가 없다(이름과 부모 MFT 번호뿐). 동명 파일 가능성을 배제하지 못해 최대 추정이고, 저널은 오래된 기록부터 잘리므로 "USN 에 없음" 이 "행위 없음" 은 아니다
- 라이브 분석은 삭제 파일과 USN 을 다루지 않는다. 로그인은 의심까지, 계정 전환과 앱 삭제는 나오지 않는다. 파일시스템이 온전한 실제 BitLocker 이미지로는 아직 검증하지 못했다

## 검증

자체 검사(이미지 없이 실행):

```
python -m cxparser.output
python -m cxparser.vfs
python -m cxparser.derive
python -m cxparser.mounted_devices
python -m cxparser.bitlocker
python -m cxparser.artifacts.sentry_scope
python -m cxparser.artifacts.recent_lnk
```

정답 시트가 있는 실험 이미지는 ARTINEX 통합 실행기의 정답지 대조를 쓴다 (`integration/` 에서):

```
python llm_forensic.py -i <이미지> -o out --only chatgpt_desktop
python validation\verify_merged.py --timeline out\<evidence_id>\timeline.csv --key validation\scenario_keys\plain_nodelete_2026-09-23.csv
```

폴더 입력은 Autopsy 애드온(`../Autopsy_Addon`)이 쓰며, 같은 이미지에서 이미지 입력과 결과가 같은지로 확인한다. 판정 규칙을 바꾸면 시나리오 이미지 3장의 CSV 를 이전 버전과 비교해 바뀐 행이 의도한 것뿐인지 본다.

## 소스 구성

```
run_parser.py          런처 (cxparser.cli.main)
requirements.txt       pytsk3, libewf-python, dissect.fve — 이미지 입력일 때만 필요
cxparser/
  cli.py               명령행 인자, 덮어쓰기 보호, 종료코드
  pipeline.py          입력 열기 → 탐색 → 파싱 → 파생 규칙 → 타임라인. 버전 상수
  image.py             E01(pyewf)/RAW(pytsk3) 열기, 세그먼트 누락·절단 검사
  vfs.py               TSK NTFS 탐색(삭제 파일 경로 복원) / 추출 폴더(+ _host_metadata.json) / 라이브
  bitlocker.py         BitLocker 해제(dissect.fve) → 복호화 스트림을 TSK 이미지로
  mounted_devices.py   SYSTEM 하이브 MountedDevices → 볼륨별 드라이브 문자
  locate.py            탐색 디렉터리(SCAN_ROOTS), 경로 → kind 분류
  usn.py               $Extend/$UsnJrnl:$J — Codex 아티팩트 이름 기준 변경 기록
  derive.py            레코드 간 대조 — 로그인, 계정 전환, 첨부 업로드, 저장 귀속
  events.py            행위 카탈로그 (E01-01 …)
  model.py             레코드 모델 — 시각·사용자 행위·근거
  timeline.py          시각순 정렬, 시각 미상 분리
  output.py            cx_result.json + 공통 CSV 2종, 타임라인 정리 규칙
  util.py              시각 해석, 발췌, 민감정보 마스킹
  errors.py            오류 분류
  artifacts/
    rollout.py           sessions/…/rollout-*.jsonl
    session_index.py     session_index.jsonl
    global_state.py      .codex-global-state.json
    auth.py              auth.json (토큰 값 미출력)
    sqlitedb.py          state_5 / thread_history_1 / logs_2
    webcache.py          채팅창 HTTP 캐시 — Chrome Blockfile 읽기
    webcache_conv.py     캐시 안 ChatGPT API 응답 → 채팅 모드 행위·대화
    sentry_scope.py      sentry/scope_v3.json breadcrumb → 채팅 모드 전송·새 대화 시각
    prefetch.py          CODEX.EXE-*.pf 실행 기록
    recent_lnk.py        최근 항목 바로가기 → 다운로드
    package_install.py   패키지 폴더 시각 → 설치
    jsontree.py          JSON 키 재귀 탐색, JSON Pointer
```
