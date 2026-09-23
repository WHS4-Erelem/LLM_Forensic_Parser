# cxparser — ChatGPT/Codex 데스크톱 앱 아티팩트 파서 (MVP)

E01 / RAW(.dd) 디스크 이미지에서 MS Store 패키지 `OpenAI.Codex_2p2nqsd0c76g0` 의
아티팩트를 찾아 파싱 → 정규화 → 타임라인 → JSON/CSV 로 출력한다.

> **대상 확인 결과**: 분석표 「WHS4 에레렘 아티팩트 분석 (은정2)」(2026-08-29 수집)의
> 경로·파일은 전부 패키지 `OpenAI.Codex_2p2nqsd0c76g0`(버전 26.825.4187.0)의 것이다.
> 이 앱 안에 ChatGPT 채팅(chat 모드)과 Codex 에이전트(work 모드)가 함께 있다.
> 별도 패키지 `OpenAI.ChatGPT-Desktop` 의 경로는 자료에 없으므로 다루지 않는다.

## 0. 인수인계 요약 (파서 통합 담당자용)

**이 저장소가 주는 것**: 이미지/폴더 → Codex Desktop 아티팩트 → 정규화 레코드(JSON/CSV).
통합 쪽에서 쓸 진입점은 두 가지뿐이다.

```python
from cxparser import pipeline
result = pipeline.run(path, input_type="auto", kinds=pipeline.DEFAULT_KINDS,
                      max_excerpt=500, usn=True)   # dict 반환
```
또는 CLI `run_parser.py -i <경로> -o <출력폴더>` (종료코드 0=정상, 1=파일 단위 오류, 2=입력 실패).

**레코드 계약**: 모든 레코드에 `schema_version`(현재 `1.0`), `timestamp` / `user_action` / `evidence`
3항목이 항상 있다(3절). 값을 모르면 `null` + 사유. 통합 시 이 3항목과 `event.event_id`,
`details.artifact` 만 의존하면 안전하다. `details` 하위 키는 아티팩트별로 다르고 늘어날 수 있다.

**확신도 규칙**: `확인`(아티팩트 내용이 행위를 직접 증명) / `추정`(정황) / `미확정`.
파일 존재·부재, 스레드 바인딩, 인증 변경 로그처럼 행위를 특정할 수 없는 근거는 `NA-00` +
`details.candidate_event` 로만 남긴다. **통합 UI 에서 이를 확정 이벤트로 승격하지 말 것.**

**검증 상태**: 합성 테스트 43건 통과. 실제 E01 2개 실행 검증 완료 — `IMG_MRK_VER.E01`(단일, 마커 시나리오)
과 `Scenario_Image.E01~E23`(**23분할**, 평서문 시나리오, 분기 파일 E03-03 포함). 둘 다 저장 해시 일치, 오류 0.
미검증: 삭제 파일 복구·분할 RAW 는 실제 표본에 대상이 없었다. 상세: `verification/`.

**환경 제약**: Python **3.12 고정**(libewf-python 휠), `pytsk3`·`libewf-python` 필요.
테스트 이미지는 저장소에 없다 — `tools/make_test_image.py` 로 생성하며 **WSL(Ubuntu)** 이 필요하다.

**알려진 미해결**(팀 확인 대기): ① 분석표의 E03-04 재시도 기술이 표본과 불일치 ②
시나리오 표 로그인 01:27:25 vs 앱 로그 01:10:46 ③ 계정 전환 26초 차. `CLAUDE.md` 8절 참조.

**출력물 취급**: 결과 JSON 에는 대화 원문·프롬프트·계정 UUID 가 평문으로 들어간다(토큰 값은 마스킹).
사건 자료와 동일하게 취급할 것.

## 1. 설치 / 실행

이미지·파일시스템 판독은 검증된 라이브러리를 쓴다.

| 역할 | 라이브러리 |
|---|---|
| E01 읽기 | libewf (`libewf-python` → `import pyewf`) |
| RAW/분할 RAW 읽기, 파티션, NTFS | The Sleuth Kit (`pytsk3`) |

`libewf-python` 의 Windows 휠이 **Python 3.10~3.12** 만 있으므로 3.12 가상환경을 권장한다.

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/Scripts/python.exe -r requirements.txt
.venv/Scripts/python.exe run_parser.py --input <image.E01|image.dd|추출폴더> --out-dir out
```

| 옵션 | 설명 |
|---|---|
| `--input, -i` | E01(분할 `.E01/.E02…` 포함) / RAW `.dd` `.raw`(분할 `.001` 포함) / 추출 디렉터리 |
| `--input-type` | `auto`(기본) / `image` / `dir` |
| `--out-dir, -o` | 결과 폴더 (기본 `cx_out`) |
| `--format` | `csv`(기본, 팀 공통 CSV 2종) / `json`(cx_result.json 전체 레코드) / `both` |
| `--kinds` | `rollout,rollout_loose,session_index,global_state,auth,sqlite` 중 선택 |
| `--no-usn` | `$UsnJrnl:$J` 파싱 생략 (기본: 이미지 입력이면 파싱) |
| `--usn-max-bytes` | `$J` 에서 읽을 최대 바이트 (기본 전체) |
| `--max-excerpt` | 근거 발췌 최대 문자 수 (기본 500) |

출력 파일

- `timeline.csv` — 팀 공통 ① (2026-09-20 공유본 헤더 그대로): `Model, Timestamp, User_behavior, Behavior_details , Verdict, Artifact_path, Artifact_details `
  - Model=`chatgpt-desktop`, Timestamp=`YYYY-MM-DD HH:MM:SS.ffffff KST`, User_behavior=분석표 카탈로그 행위명, Behavior_details=`<흔적 성격>_<내용>`,
    Verdict=확정/의심 (판단 불가·NA-00 은 JSON 에만), Artifact_path=`C:\Users\…` 표기, Artifact_details=`[Rollout|SQLite|GlobalState|…] 유형=…, 대화 UUID=…, 위치=…, MFT=…, 규칙=E04-01, 패키지=…`
- `recovered_conversations.csv` — 팀 공통 ②: `Model, timestamp, conversation_uuid, conversation_title, message_uuid, parent_message_uuid, message order, role, content, Artifact_path`
  - rollout·thread_items 의 user/assistant 메시지. 같은 (역할, 본문) 이 2초 안에 양쪽에 있으면 rollout 1행만. 대화별 message order 1..n, parent 는 직전 메시지(첫 메시지는 `00000000-0000-4000-8000-000000000000`)
- `cx_result.json` (`--format json|both`) — 전체 레코드(시각·행위·근거 3항목, 판단 불가·NA-00 포함) + 스캔정보 + 스키마 관찰 + USN 요약 + 경고/오류
- 팀 파서 공통 관례: 출력 폴더에 기존 결과가 있으면 거부(`--overwrite`), 셀이 `= + - @` 로 시작하면 `'` 접두(Excel 수식 방지)

**원본 이미지는 읽기 전용으로만 연다.** 결과 파일은 `--out-dir` 아래에만 쓴다.

## 2. 파싱 대상 아티팩트 (분석표 근거)

| kind | 경로 | 분석표 근거 |
|---|---|---|
| `rollout` | `~/.codex/sessions/YYYY/MM/DD/rollout-<시각>-<스레드ID>[_<분기ID>].jsonl` | E03-01 새 대화 생성, E03-03 대화 수정, E04-01 프롬프트 전송 |
| `session_index` | `~/.codex/session_index.jsonl` | E03-01 대화 목록 등재 |
| `global_state` | `~/.codex/.codex-global-state.json` | E04-01 `prompt-history.chatgpt-global`, E09-01 `chatgpt-last-selected-model-v1`, E07-02/03 `client-thread-bindings-v1`, 계정 UUID 열거 |
| `auth` | `~/.codex/auth.json` | E01-01/02/03 (토큰 값은 출력하지 않음) |
| `sqlite` | `~/.codex/state_5.sqlite`(threads) · `thread_history_1.sqlite`(thread_items) · `logs_2.sqlite`(logs) | E03-01/02 대화 생성·보관, E04-01 프롬프트 — **행마다 시각이 있음**, E01-02 `account/logout` 로그 |
| (이미지 전용) | `$Extend/$UsnJrnl:$J` | 파일 생성·삭제 시각 — 분석표의 "로그아웃 지문 = auth.json FILE_DELETE" 등 |
| `prefetch` (0.3.6) | `Windows/Prefetch/CODEX.EXE-*.pf` | E08-01 애플리케이션 실행 — OS 가 기록한 최근 8회 실행 시각. MAM 압축 해제는 Windows 에서만 |
| `recent_lnk` (0.3.6) | `Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk` | E06-02 생성 이미지 다운로드(대상이 `Codex 이미지 …`), E05-05 문서 다운로드(문서 확장자 + 대상이 같은 시각에 새로 생김) |

0.3.5~0.3.6 에 추가된 파생 규칙(`derive.py`, `sqlitedb._logs`): 로그인 = 앱 로그 `Reloaded auth, changed: true` + USN `auth.json FILE_CREATE`(±120s) / 계정 전환 = auth.json 삭제→재생성 + 계정 UUID 2개 이상 /
첨부 업로드 = 프롬프트 본문의 `# Files mentioned by the user` 목록 / 애플리케이션 실행·종료 = `logs_2.sqlite` 의 `process_uuid` 구간 시작·끝 (종료는 정상·강제 구분 불가라 추정).
로컬 흔적이 없어 못 잡는 것: 모델 변경·공유 링크·임시 채팅·계정 이름 변경 (채팅창 Chromium 저장소가 앱 삭제와 함께 사라짐), 설치·삭제 (USN 저널이 그 구간을 덮을 때만 가능).

탐색 디렉터리(`locate.SCAN_ROOTS`): `Users/*/.codex`, `Users/*/Documents/Codex`,
`Users/*/AppData/Local/Packages/OpenAI.Codex_2p2nqsd0c76g0`,
`Program Files/WindowsApps/OpenAI.Codex_*`, `ProgramData/Packages/OpenAI.Codex_2p2nqsd0c76g0`,
`Windows/Prefetch`, `Users/*/AppData/Roaming/Microsoft/Windows/Recent`.
위 표 이외 파일(SQLite, 채팅창 Chromium 저장소, Helium 하이브 등)은
**발견 목록(`artifact_inventory`)에만 기록**하고 아직 파싱하지 않는다.

## 3. 출력 레코드 구조

모든 레코드에 필수 3항목이 항상 들어간다.

```jsonc
{
  "record_id": "R000013",
  "event": {"event_id": "E04-01", "event_name": "사용자 프롬프트 입력/전송"},

  "timestamp": {                         // 1) 타임스탬프
    "utc": "2026-08-28T17:23:28.900000Z",
    "original_value": "2026-08-28T17:23:28.900Z",
    "original_format": "ISO8601",
    "meaning": "rollout JSONL 라인에 기록된 메시지 시각",
    "source": "artifact_content",        // artifact_content | artifact_filename | ntfs_mft | none
    "timezone_note": null,
    "null_reason": null                  // 알 수 없으면 utc=null + 사유
  },

  "user_action": {                       // 2) 사용자 행위
    "action": "프롬프트 전송",             // 특정 불가 시 "미확정"
    "confidence": "확인",                 // 확인 | 추정 | 미확정
    "rationale": "rollout JSONL 의 role=user 메시지 라인 (분석표 E04-01)",
    "observed_artifact": null            // 미확정일 때 관찰된 내용
  },

  "evidence": {                          // 3) 근거 (재확인 가능한 위치)
    "image": {"image_id": "case.E01 (sha256[prefix]=…)", "image_type": "ewf", "reader": "libewf …"},
    "location": {
      "path": "/Users/jej96/.codex/sessions/2026/08/29/rollout-….jsonl",
      "size_bytes": 1234, "allocated": true,
      "path_source": "…",                // 삭제 파일 경로를 MFT 부모 참조로 복원했을 때만
      "mft_record": 210124, "mft_sequence": 1,
      "partition_index": 0, "partition_offset_bytes": 1048576,
      "ntfs_standard_information": {"created": "…", "modified": "…", "mft_modified": "…", "accessed": "…"},
      "ntfs_file_name": {"created": "…", "modified": "…", "mft_modified": "…", "accessed": "…"}
    },
    "locator": "line=11",                // line=N / json_pointer=… / file
    "ordinal": 10,                       // rollout 라인의 ordinal (있을 때만)
    "artifact_sha256": "…",
    "excerpt": "[MRK_E0401] 파이썬으로 …"
  },

  "parse": {"status": "ok|partial|error", "errors": [], "notes": []},
  "details": { … 아티팩트별 상세 … }
}
```

### 시각 처리 원칙 (분석표 지침 반영)

- **파일 수정 시각을 메시지 전송 시각으로 대체하지 않는다.** MFT 시각($SI/$FN)은
  `evidence.location` 에만 보존하고, `timestamp` 는 아티팩트 내용/파일명에서
  확인된 값만 쓴다(`timestamp.source` 로 출처를 구분).
- **타임존 표기 없는 값은 UTC 로 단정하지 않는다.** 예: rollout 파일명의
  `2026-08-29T02-22-56` 은 `utc:null` + `original_value` 보존 + `null_reason` 기재.
- 확인 가능한 시각만 `timeline` 에 정렬하고, 시각 미상은 `undated_records` 로 분리.
- **파일의 존재/부재만으로 전송·삭제·로그아웃을 확정하지 않는다.** `auth.json` 은
  존재하더라도 `user_action = 미확정` 으로 두고 판단 근거 부족 사유를 남긴다.

### 필드 매핑 방침 (추측 금지)

파서는 특정 스키마를 하드코딩하지 않고,

1. `{"timestamp", "type", "payload"}` envelope 형태와 평면 형태를 모두 허용하고,
2. 시각 키(`timestamp/ts/created_at/time/…`), `role`, `content`(문자열 / 리스트 /
   `{type,text}` 요소)를 후보 순으로 탐색하며,
3. 매핑되지 않은 라인은 버리지 않고 `미확정` 레코드로 남기고,
4. **관찰된 실제 구조를 `schema_observations` 로 보고**한다.

**실제 폴더 표본 반영 (WHS4_snap S1~S5, 2026-09-18)** — E01/DD 표본 검증은 아님:

| 관찰 | 처리 |
|---|---|
| 라인 = `{timestamp(Z), ordinal, type, payload}` | `ordinal` → `evidence.ordinal` |
| role=user 인데 `content_item_kinds` 가 `plugins.recommendations`/`environments.environment_context` | 앱 자동 주입 → `NA-00` 미확정 (전문 미수록) |
| `content_item_kinds=user.text` | `E04-01` 확인 (+ 동일 본문 `item_completed(UserMessage)` 교차 확인) |
| 본문 `## Referenced ChatGPT conversation` … `## My request:` | 채팅→작업 모드 인계, `E04-01` **추정** (`details.handoff` 에 참조 대화 ID·제목·캐시된 이전 발화) |
| `session_meta.timestamp`(Z) | 대화 파일 레코드 시각. 파일명 시각은 원본값 + `filename_minus_meta_seconds`(표본 전부 32400) 로만 보고 |
| token_count / turn_context / world_state / reasoning / 중복 item_completed | 개별 레코드 없이 `line_type_counts` 집계 |
| global-state `prompt-history: {global, chatgpt-global}` | 키별 `E04-01` (`details.key`) |
| session_index `{id, thread_name, updated_at}` | updated_at = 최종 갱신 시각(생성 시각 아님) |

## 4. 예외 처리 분류

| 코드 | 의미 |
|---|---|
| `IMAGE_OPEN_FAILED` | 이미지 없음/권한, E01 열기 실패, **E01 첫·끝 섹터 읽기 실패(절단/손상)** |
| `SEGMENT_MISSING` | E01 확장자 결번(.E01 .E02 .E04), **마지막 E01 세그먼트 누락**(마지막 파일이 `next` 섹션으로 끝남), 분할 RAW 중간 결번 |
| `UNSUPPORTED_FORMAT` | EWF2(.Ex01), L01, VMDK/VHD/QCOW, 판독 가능한 NTFS 볼륨 없음 |
| `ARTIFACT_NOT_FOUND` | 이미지는 읽혔으나 대상 경로 0건 (빈 결과와 구분) |
| 레코드 단위 | `JSON_DECODE_ERROR`, `READ_FAILED` 등 → 해당 레코드만 `status:error`, 같은 파일의 나머지 라인은 계속 파싱 |

실패를 빈 결과나 성공으로 숨기지 않는다. CLI 종료코드: 0=오류 없음, 1=파일 단위
오류 있음, 2=입력 자체 실패.

## 5. 지원 범위와 한계

**지원**

- 이미지: EWF v1 `.E01`(분할 `.E02…/.EAA…`) — libewf / RAW `.dd/.raw/.img`, 분할 RAW `.001…` — TSK
- 파티션: TSK 가 판독하는 MBR/GPT, 파티션 테이블 없는 볼륨 이미지
- 파일시스템: **NTFS 만** (TSK). 다른 FS 파티션은 `skipped_partitions` 에 사유와 함께 기록
- 삭제 파일: ① 디렉터리 인덱스에 남은 삭제 이름 ② 인덱스에서도 지워진 경우
  미할당 MFT 엔트리의 `$FILE_NAME` 부모 참조(MFT#+seq)가 탐색 디렉터리와 일치하면 경로 복원
  (`allocated:false`, `path_source` 기재)

**미지원 / 한계**

- EWF2(`.Ex01`), L01, VMDK/VHD/QCOW, BitLocker 등 암호화 볼륨
- FAT/exFAT/ReFS
- 부모 디렉터리까지 삭제·재할당된 파일은 경로 복원 불가 / 클러스터가 덮어써진 삭제 파일은 내용 불일치 가능
- 파일 카빙(미할당 영역 스캔) 미구현
- 채팅창 Chromium 저장소(IndexedDB/Cache), `SystemAppData\Helium\User.dat`, `$LogFile` → 범위 밖
- `~/.codex` 의 나머지 SQLite(goals/memories/queue)는 발견 목록에만 기록
- USN 레코드에는 **경로가 없다** — 이름·부모 MFT# 만 있어 동명 파일 가능성을 배제 못 하므로 최대 `추정`.
  저널은 오래된 기록부터 잘리므로 "USN 에 없음 = 행위 없음"이 아니다.

## 6. 테스트

```bash
.venv/Scripts/python.exe tools/make_test_image.py      # tests/data 생성 (WSL Ubuntu 필요, sudo 불필요)
.venv/Scripts/python.exe -m unittest discover -s tests -v
```

- 테스트 이미지는 WSL 에서 **실제 도구**로 만든다: `mkntfs`/`ntfs-3g` 로 NTFS(MBR) 작성,
  rollout 1개 삭제, `ewfacquire` 로 E01(단일 압축 / 1MiB 6분할), `split` 으로 분할 RAW.
  (`ntfs-3g` 는 `apt-get download` + `dpkg -x` 로 사용자 폴더에 풀어 쓰고,
  사용자 네임스페이스에서 mount 한다.)
- 42개 테스트: DD↔E01↔분할E01↔분할RAW 결과 동일성, 필수 3항목, 라인번호·ordinal·MFT·$SI/$FN 근거,
  자동 주입 user 문맥 제외, 채팅→작업 인계 추정, 상태 라인 집계·미관찰 라인 보존, 중첩 prompt-history,
  분기 파일 E03-03, 깨진 JSON 라인 격리, 비상주 `$DATA`, 삭제 rollout 복구·표시,
  탐색 범위 제한, 토큰 미출력, 타임라인 정렬/시각미상 분리, `--kinds`, 디렉터리 입력,
  예외(경로 없음·VMDK·EWF2·E01 중간/마지막 세그먼트 누락·분할 RAW 결번·E01 절단·FS 없음·아티팩트 없음).

> **검증 상태(중요)**: 이미지 컨테이너(NTFS·E01)는 실제 도구로 만들었지만
> **파일 내용은 합성**이다(라인·키 구조만 실제 폴더 표본에 맞춤). 실제 폴더 표본으로
> 필드 매핑은 반영했지만, 실제 앱 E01/DD 이미지 검증과 분석표 원문 1:1 대조는 남아 있다.

## 7. 소스 구성

```
cxparser/
  image.py     E01(pyewf)/RAW(pytsk3) 열기, 세그먼트 누락·절단 검사
  vfs.py       TSK NTFS 탐색(SCAN_ROOTS, 삭제 파일 경로 복원) / 추출 디렉터리
  artifacts/   rollout.py(주기능)  session_index.py  global_state.py  auth.py  jsontree.py
  locate.py  model.py  timeline.py  output.py  pipeline.py  cli.py  events.py  util.py  errors.py
tools/make_test_image.py(.sh)   tests/test_parser.py   run_parser.py   requirements.txt
  usn.py       $Extend/$UsnJrnl:$J — Codex 아티팩트 이름 기준 변경 기록
  artifacts/sqlitedb.py           state_5 / thread_history_1 / logs_2 SQLite
tools/verify_sheet.py           대조 도구 — 폴더 표본은 `--snap`, 이미지는 `--image --scenario marker|plain`
verification/                   대조 결과 (sheet_check.md, e01_IMG_MRK_VER.md, scenario_check_*.md)
```
