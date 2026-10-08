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
미검증: 삭제 파일 복구·분할 RAW 는 실제 표본에 대상이 없었다.
테스트 코드·테스트 이미지 생성 도구·대조 결과 문서는 이 저장소에 없다(6절).

**환경 제약**: 이미지 입력은 Python **3.12 고정**(libewf-python 휠), `pytsk3`·`libewf-python` 필요 (BitLocker 이미지는 `dissect.fve` 도).
폴더 입력은 표준 라이브러리만으로 돈다(0.3.12).

**알려진 미해결**(팀 확인 대기): ① 분석표의 E03-04 재시도 기술이 표본과 불일치 ②
시나리오 표 로그인 01:27:25 vs 앱 로그 01:10:46 ③ 계정 전환 26초 차.

**출력물 취급**: 결과 JSON 에는 대화 원문·프롬프트·계정 UUID 가 평문으로 들어간다(토큰 값은 마스킹).
사건 자료와 동일하게 취급할 것.

## 1. 설치 / 실행

이미지·파일시스템 판독은 검증된 라이브러리를 쓴다.

| 역할 | 라이브러리 |
|---|---|
| E01 읽기 | libewf (`libewf-python` → `import pyewf`) |
| RAW/분할 RAW 읽기, 파티션, NTFS | The Sleuth Kit (`pytsk3`) |
| BitLocker 볼륨 해제 | `dissect.fve` (BitLocker 이미지일 때만 불러온다) |

`libewf-python` 의 Windows 휠이 **Python 3.10~3.12** 만 있으므로 3.12 가상환경을 권장한다.

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/Scripts/python.exe -r requirements.txt
.venv/Scripts/python.exe run_parser.py --input <image.E01|image.dd|추출폴더> --out-dir out
```

팀 저장소에서는 따로 만들지 않고 `../integration/setup.ps1` 이 만드는 `integration/.venv312` 를 쓴다.
`run_parser.py` 대신 이 폴더에서 `python -m cxparser` 로 실행해도 같다.

| 옵션 | 설명 |
|---|---|
| `--input, -i` | E01(분할 `.E01/.E02…` 포함) / RAW `.dd` `.raw`(분할 `.001` 포함) / 추출 디렉터리 |
| `--input-type` | `auto`(기본, 경로를 보고 image/dir 판별) / `image` / `dir`(추출 폴더) / `live`(실행 중인 이 PC 를 직접 분석. 자동 선택되지 않으며 `--input` 을 생략하면 시스템 드라이브) |
| `--out-dir, -o` | 결과 폴더 (기본 `cx_out`) |
| `--format` | `csv`(기본, 팀 공통 CSV 2종) / `json`(cx_result.json 전체 레코드) / `both` |
| `--kinds` | `rollout,rollout_loose,session_index,global_state,auth,sqlite,prefetch,recent_lnk,webcache` 중 선택 (기본 전체) |
| `--max-file-mb` | 파싱 대상 파일 하나의 크기 상한(MB, 기본 1024). 넘으면 그 파일만 `FILE_TOO_LARGE` 로 건너뛴다 |
| `--no-usn` | `$UsnJrnl:$J` 파싱 생략 (기본: 이미지 입력이면 파싱) |
| `--usn-max-bytes` | `$J` 에서 읽을 최대 바이트 (기본 전체) |
| `--max-excerpt` | 근거 발췌 최대 문자 수 (기본 500) |
| `--key-material` | BitLocker 볼륨의 키: `recovery:<48자리 복구 키>` / `passphrase:<암호>` / `bek:<.BEK 경로>` / `fvek:<hex>`. 일시 중단·활성화 대기(clear key) 상태는 키 없이 풀린다. 환경변수 `ERELM_KEY_MATERIAL` 로 줘도 된다 |
| `--overwrite` | 출력 폴더에 기존 결과 파일이 있어도 덮어쓴다 (기본: 거부, 종료코드 2) |
| `--quiet` | 콘솔 요약 생략 |

출력 파일

- `timeline.csv` — 팀 공통 ① (2026-09-20 공유본 헤더 그대로): `Model, Timestamp, User_behavior, Behavior_details , Verdict, Artifact_path, Artifact_details `
  - Model=`chatgpt-desktop`, Timestamp=`YYYY-MM-DD HH:MM:SS.ffffff KST`, User_behavior=분석표 카탈로그 행위명, Behavior_details=`<흔적 성격>_<내용>`,
    Verdict=확정/의심 (판단 불가·NA-00 은 JSON 에만), Artifact_path=`C:\Users\…` 표기 (드라이브 문자는 이미지의 `SYSTEM\MountedDevices` 로 확인한 값, 0.3.24 — 확인 못 하면 `C:` 가정), Artifact_details=`[Rollout|SQLite|GlobalState|…] 유형=…, 대화 UUID=…, 위치=…, MFT=…, 규칙=E04-01, 패키지=…`
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
| `global_state` | `~/.codex/.codex-global-state.json` | E04-01 `prompt-history.chatgpt-global`, `chatgpt-last-selected-model-v1` 은 NA-00 관찰(선택 모델 상태값, E09-01 근거로 쓰지 않음), E07-02/03 `client-thread-bindings-v1`, 계정 UUID 열거 |
| `auth` | `~/.codex/auth.json` | E01-01/02/03 (토큰 값은 출력하지 않음) |
| `sqlite` | `~/.codex/state_5.sqlite`(threads) · `thread_history_1.sqlite`(thread_items) · `logs_2.sqlite`(logs) | E03-01/02 대화 생성·보관, E04-01 프롬프트 — **행마다 시각이 있음**, E01-02 `account/logout` 로그 |
| (이미지 전용) | `$Extend/$UsnJrnl:$J` | 파일 생성·삭제 시각 — 분석표의 "로그아웃 지문 = auth.json FILE_DELETE" 등 |
| `prefetch` (0.3.6) | `Windows/Prefetch/CODEX.EXE-*.pf` | E08-01 애플리케이션 실행 — OS 가 기록한 최근 8회 실행 시각. MAM 압축 해제는 Windows 에서만 |
| `recent_lnk` (0.3.6) | `Users/*/AppData/Roaming/Microsoft/Windows/Recent/*.lnk` | E06-02 생성 이미지 다운로드(대상이 `Codex 이미지 …` = 확정 / 그 밖의 이미지 = 추정), E05-05 문서 다운로드(문서 확장자·머리 바이트 + 대상이 같은 시각에 새로 생김). 종류를 알 수 없는 저장도 E05-05 로 내고 Behavior_details 에 '종류 미확인' 을 적는다 (0.3.23) |
| `webcache` (0.3.7) | `…\Packages\OpenAI.Codex_…\LocalCache\Roaming\Codex\web\Codex\Default\Cache\Cache_Data\` (index·data_0~3·f_*) | **채팅 모드** 대화 전체 — conversation 응답 JSON: E03-01 대화 생성, E04-01 프롬프트(본문·시각), E05-01/03 첨부 업로드(metadata.attachments 파일명·MIME), E06-01 이미지 생성(image_asset_pointer·image_gen_title), E03-03/04 분기(대화 수정·재시도), E10-01 임시 채팅(is_temporary_chat), E09-01 모델 변경(default_model_slug 변화, 추정), `estuary/content?…&fn=` 요청 = E05-05/E06-02 파일 내려받기. assistant 응답은 recovered_conversations 로. Chrome Blockfile Cache Reader 는 팀 ChatGPT Web 파서(cache.py)를 옮겨 온 것 (`webcache.py`). **앱을 삭제하면 통째로 사라진다** |

0.3.5~0.3.6 에 추가된 파생 규칙(`derive.py`, `sqlitedb._logs`): 로그인 = 앱 로그 `Reloaded auth, changed: true` + USN `auth.json FILE_CREATE`(±120s) / 계정 전환 = auth.json 삭제→재생성 + 계정 UUID 2개 이상 /
첨부 업로드 = 프롬프트 본문의 `# Files mentioned by the user` 목록 / 애플리케이션 실행·종료 = `logs_2.sqlite` 의 `process_uuid` 구간 시작·끝 (종료는 정상·강제 구분 불가라 추정).
2026-08-29 S3 스냅샷(앱 미삭제)으로 검증: 임시 채팅 03:31:36, 이미지 업로드 02:29:41, 문서 업로드 02:32:09, 이미지 생성 03:35:34, 생성 이미지 다운로드 03:40:53, 모델 변경 03:29:17(auto→gpt-5-6), 대화 수정 02:26:47, 재시도 02:27:07 — 8월 분석 보고서의 정답 창과 모두 일치.
타임라인 정리 규칙(`output.py`): 같은 프롬프트가 rollout·SQLite·캐시·global-state 여러 곳에 있으면 시각 있는 행 하나에 접는다. Prefetch 실행 중 앱 프로세스 구간 안의 것은 보조 프로세스 기동이라 타임라인에서 빼고, 60초 안의 여러 .pf 실행은 하나로 접는다(JSON 에는 남음).
0.3.27 (2026-10-08, 설치 시각 정의 — 팀 결정 '설치 = 다운로드(패키지 쓰기) 완료'): 애플리케이션 설치(E02-01)의 시각을 패키지 폴더의 **생성 시각(받기 시작)** 에서 **마지막 수정 시각(패키지 쓰기 완료)** 으로 바꿨다(`package_install.py`). Store 는 받기 시작할 때 폴더를 만들고 다 받으면 폴더 수정 시각이 갱신되며, 패키지 폴더는 설치 뒤 바뀌지 않고 업데이트는 새 버전 폴더를 만들어 수정 시각이 뒤로 밀리지 않는다. 근거(details)에 `download_started_utc`(생성)·`installed_utc`(수정)·`version` 을 함께 적고, 사용자 데이터 폴더 관찰(NA-00)은 "최초 설치(첫 등록) 시점 추정" 으로 표기. image2: 11:27:19 → 11:35:24 (시트 '다운로드 완료' 11:35:30, 6초 차) — 정답 9건 9/0/0. image1: 03:54:19 → 03:57:09 (시트는 첫 실행 04:34:26 을 설치로 적어 여전히 부분) — 12/2/5 그대로. Autopsy 경유(호스트 메타데이터) 출력도 같게 바뀜.

0.3.26 (2026-10-08, image2 검증 — 다운로드 중복 행): 같은 파일 다운로드가 채팅 모드 웹 캐시(내려받기 요청, 확인)와 최근 항목 바로가기(저장된 파일, 추정) 두 행으로 나와 한 행위가 두 건으로 세어졌다(image2 `CD_고객안내_승인대기.pdf` 11:47:34 / 11:47:42). 파일명이 같고(확장자·중복 번호 `(n)` 제외) 60초 안이면 웹 캐시 행 하나만 남기고 바로가기 시각과 저장 파일 생성 시각을 그 행의 `Artifact_details` 에 접는다(`output._fold_downloads`, 앱 실행의 Prefetch 접기와 같은 방식). 바로가기만 있는 경우(에이전트 모드, image1)는 그대로. image1 58행 동일, image2 13 → 12행, 정답 대조 8/1/0 그대로.

0.3.25 (2026-10-08, image2 'LLM 내부정보 유출' E01 Ground Truth 검증에서 발견한 오탐): 전역 상태 파일의 `chatgpt-last-selected-model-v1` 키만으로 내던 **모델 변경(E09-01, 의심, 시각 없음)** 행을 없앴다. 이 키는 "지금 선택된 모델" 상태값이라 바꿨다는 근거가 못 되고, 모델을 바꾸지 않은 image2 에서도 `모델 변경 의심 (gpt-5-6)` 이 나왔다(거짓 양성). 이제 NA-00 관찰(`candidate_event: E09-01`)로만 남기고, 모델 변경은 바뀐 지점이 보이는 아티팩트 — 에이전트 모드 rollout 의 `turn_context.model` 변화, 채팅 모드 웹 캐시의 `default_model_slug` 변화 — 로만 판정한다. 양성 사례: image1(삭제 제외)의 06:01:36 모델 변경(rollout 근거)은 그대로 58행 동일. 음성 사례: image2 는 14행 → 13행(거짓 행 제거), 정답 9건 대조 8/1/0 그대로.

0.3.24 (2026-10-08, 이미지 입력의 실제 드라이브 문자): `Artifact_path` 의 드라이브 문자를 이미지 입력에서도 가정이 아니라 확인한 값으로 쓴다. 파일시스템에는 드라이브 문자가 없고, 부팅한 Windows 가 `SYSTEM` 하이브의 `MountedDevices` 에 `\DosDevices\C:` = 볼륨 식별자(MBR: 디스크 서명+파티션 오프셋, GPT: 파티션 GUID)로 적어 두므로 그 값을 이미지의 파티션과 대조한다(`mounted_devices.py`, 표준 라이브러리 regf 최소 판독). 결과는 `cx_result.json` 의 `filesystem.volumes[].drive` 와 `filesystem.drive_letters`(근거)에 남는다. 하이브가 없거나 문자가 없는 파티션은 종전처럼 `C:` 가정. 추출 폴더·라이브 입력은 변화 없음. 시나리오 이미지 2장은 파티션 2(오프셋 227540992, GPT GUID 대조)가 C: 로 확인돼 CSV 출력 동일 — 통합기 담당자가 같은 이미지에서 MountedDevices 로 확인한 것과 일치. 같이 고친 것: `filesystem.volumes[].scheme` 이 GPT 이미지에서 `"16"` 으로 나오던 버그(TSK 의 GPT 상수는 8 이 아니라 0x10) → `"GPT"`. 통합기 PR #16 리뷰에서 "파서의 C: 는 관찰값이 아니라 가정" 이라고 지적한 것을 해소한다.
0.3.23 (2026-10-08, 행위명 '파일 다운로드' 삭제 — 팀 행위 분류 체계 2026-10-08 합의): `user_behaviors.txt` 에서 '파일 다운로드' 가 빠져 E05-06 을 없앴다. 최근 항목 바로가기로 잡은 저장 중 종류를 확인하지 못한 것(확장자·머리 바이트 모두 단서 없음, zip 등 비문서)은 규칙대로 **문서 다운로드(E05-05, 의심)** 로 내고 Behavior_details 에 '종류 미확인' 사유를 적는다. 이미지(png/jpg 또는 머리 바이트)는 앱 명명 규칙(`Codex 이미지 …`)이 아니어도 **생성 이미지 다운로드(E06-02, 의심)** 로 낸다 — Codex 에서 저장되는 이미지는 생성 이미지뿐이고, 문서로 적는 것보다 사실에 가깝다. 앱 명명 규칙의 E06-02(확정)는 그대로. 시나리오 이미지 두 장에는 해당 행이 없어 출력 동일.
0.3.22 (2026-10-05, 큰 DB 가 건너뛰어지던 문제): 파싱 대상 파일 하나의 크기 상한을 64MB → **1GB** 로 올리고 `--max-file-mb` 옵션으로 바꿀 수 있게 했다. 오래 쓴 PC 에서는 대화 DB 가 64MB 를 넘는다(두 달 사용한 PC 의 `thread_history_1.sqlite` 가 94MB) — 라이브 분석에서 이 파일이 `FILE_TOO_LARGE` 로 빠져 타임라인 1,794행·대화 3,646행만 나오던 것이 2,789행·4,200행으로 늘었다(실행 시간은 같음). 상한은 파싱 대상에만 적용된다(실행 파일 같은 비대상은 원래 읽지 않음). 시나리오 이미지에는 64MB 를 넘는 파싱 대상이 없어 이미지·폴더 입력의 출력은 동일.

0.3.21 (2026-10-05, 라이브 분석 — 실행 중인 앱의 종료 행 제외): 종료(E08-02)는 "그 프로세스의 로그가 끝났다"로 판정하는데, 라이브 분석에서는 **지금 실행 중인 앱**도 마지막 로그가 곧 종료처럼 잡혔다(연속 실행마다 종료 시각이 바뀜). 라이브 분석에서는 `tasklist` 로 실행 중인 Codex/ChatGPT 프로세스의 pid 를 확인해, 로그의 `process_uuid`(pid 포함)와 일치하는 프로세스의 종료 행은 만들지 않고 경고로 알린다. 이미지·폴더 입력은 그대로.

0.3.20 (2026-10-05, 라이브 분석 준비 5/5 — 권한 없는 경로): 일반 권한으로 실행하면 `Windows\Prefetch` 와 `Program Files\WindowsApps` 는 열리지 않는다. 멈추지 않고 건너뛴 뒤 **읽지 못한 탐색 폴더를 경고로 보고**한다(`vfs.denied` → `warnings`; Windows 의 옛 호환용 연결은 제외). 설치(E02-01)는 관리자 권한 없이도 나온다 — WindowsApps 는 목록만 막혀 있고 패키지 폴더 자체는 이름을 알면 열리므로, 현재 사용자 레지스트리(`…\AppModel\Repository\Packages` 의 `PackageRootFolder`)에서 폴더 이름을 얻어 직접 조회한다. 실행 중인 앱이 잠근 파일처럼 읽기에 실패한 파일은 그 파일만 `READ_FAILED` 로 남기고 계속한다. 관리자 권한이면 Prefetch 기반 실행 기록까지 포함된다. 이미지·폴더 입력의 출력은 동일.

0.3.19 (2026-10-05, 라이브 분석 준비 4/5 — 입력 설명): 라이브 분석의 증거 설명(`input`)에 이미지 파일 정보 대신 **어느 PC 를, 언제, 어떤 권한으로 읽었는지**를 남긴다: `hostname`, `os`, `collected_at_utc`, `elevated`(관리자 권한 여부), 그리고 "디스크 이미지가 아니라 같은 결과를 다시 만들 수 없고 읽는 동안 파일이 바뀔 수 있다"는 주의(`LiveVfs.describe_input`). CLI 요약에도 한 줄로 보인다. CSV 출력과 이미지·폴더 입력은 그대로.

0.3.18 (2026-10-05, 라이브 분석 준비 3/5 — 실제 드라이브 문자): 출력의 `Artifact_path` 는 드라이브 문자를 `C:` 로 가정해 왔다. 라이브 분석에서는 실제 드라이브 문자를 쓴다(`location.drive` → `output._winpath`). 최근 항목 바로가기의 대상이 다른 드라이브(`D:` 등)에 있으면 그 드라이브에서 직접 조회한다(`LiveVfs.host_stat`). 드라이브 문자가 없는 시스템(POSIX)은 경로를 그대로 쓴다. 이미지·추출 폴더는 이전처럼 `C:` (파티션→문자 매핑이 없음), 출력 동일.

0.3.17 (2026-10-05, 라이브 분석 준비 2/5 — 라이브 모드): `--input-type live` 를 추가했다. 이미지를 뜨지 않고 실행 중인 PC 의 볼륨 루트(기본: 시스템 드라이브)를 직접 읽는다(`vfs.LiveVfs`). 탐색 폴더만 읽기 전용으로 열고, 파일 시각과 MFT 레코드 번호는 `os.stat` 값(= 원본 파일시스템의 값)을 MFT 근거 자리에 쓴다. 바로가기 대상 파일과 패키지 폴더는 0.3.11 의 호스트 메타데이터 통로(`host_stat`)로 실제 경로를 직접 조회한다. 삭제 파일과 `$UsnJrnl` 은 다루지 않는다(로그인은 의심, 계정 전환·앱 삭제는 나오지 않음). 표준 라이브러리만 쓴다. 이미지·폴더 입력의 출력은 동일.

0.3.16 (2026-10-05, 라이브 분석 준비 1/5 — 폴더 입력의 탐색 범위 제한): 폴더 입력이 루트 아래 전체를 훑던 것을, 이미지 입력과 같은 탐색 폴더(`locate.SCAN_ROOTS`)만 보도록 바꿨다(`vfs.DirectoryVfs.scan_roots`, 대소문자 무시). 볼륨 루트(`C:\` 나 그 사본)를 줘도 디스크 전체를 돌지 않는다. 탐색 폴더가 하나도 없는 부분 추출 트리(`.codex` 폴더만 준 경우 등)는 이전처럼 전체를 본다. Autopsy 경유 출력은 동일. 자체 검사 `python -m cxparser.vfs`.

0.3.15 (2026-10-04): 채팅 모드 첨부 업로드 행의 `Behavior_details` 가 파일명 대신 대화 제목으로 찍히던 문제 수정(`output.py` 의 내용 우선순위에서 파일명을 제목 앞으로). 첨부가 여러 개면 7열이 모두 같은 행이 되어 통합기가 한 행으로 합치던 것도 함께 해결된다. 대화 제목은 `Artifact_details` 에 그대로 남는다. 채팅 모드 첨부가 없는 이미지(삭제 제외)의 출력은 0.3.14 와 동일.

0.3.14 (2026-10-04, 앱 26.928 대응 — `WHS_project_FINAL.E01`, 실험 2026-10-02): 채팅 모드 대화 응답의 주소와 형식이 바뀌어 대화·프롬프트가 0건이던 문제 수정(`webcache_conv.py`). 새 앱은 `conversations/<id>?num_turns=…`(복수형 + 쿼리)로 받고 본문이 `mapping`(트리) 대신 `messages`(목록)다. 주소 패턴을 넓히고 목록을 기존 mapping 형태로 바꿔 넘겨, 대화 생성·프롬프트·첨부 업로드·대화 복원 규칙을 그대로 쓴다. 이 이미지의 정답 9건 대조: 일치 4 → 8 (새 대화 생성 11:44:21, 첨부 2개 프롬프트 11:44:28, 프롬프트 11:45:09 · 11:46:36), 복원 메시지 0 → 6. 설치만 부분(패키지 폴더 생성 11:27:19 vs 시트의 다운로드 완료 11:35:30). 대화 목록 응답과 `~/.codex/sqlite/codex-dev.db` 의 `local_thread_catalog` 는 계정의 서버 대화 목록(다른 기기에서 만든 대화 포함)이라 행위 근거로 쓰지 않는다. 이전 형식 이미지(삭제 제외)의 출력은 0.3.13 과 동일.

0.3.13 (2026-10-04, BitLocker 볼륨 지원 — 팀 Claude Web 파서 `image/volumes.py` 의 방식을 옮김): 파티션 선두가 `-FVE-FS-` 면 `dissect.fve` 로 풀고, 복호화 스트림을 TSK 이미지로 노출해 그 위에 NTFS 를 그대로 읽는다(`bitlocker.py`, `vfs.py`). 해제 순서는 복호화 완료 상태 → clear key(일시 중단·장치 암호화 활성화 대기, 키 불필요) → `--key-material` 로 받은 키. 풀지 못하면 `VOLUME_LOCKED`(종료코드 2)로 끝나고 볼륨의 보호기 종류를 알려 준다 — 복구 파티션 같은 평문 NTFS 만 읽고 "앱 미사용"으로 결론 내리지 않기 위해서다. 키 값은 결과·로그에 남기지 않고, 볼륨 정보(`filesystem.volumes[].encryption` / `unlock_method`)에 해제 방법 이름만 남긴다. `dissect.fve` 의 AES-XTS 복호화는 약 5MB/s 인데 이 파서는 이미지 하나에서 3GB 쯤 읽으므로(미할당 MFT 엔트리·USN) 섹터 묶음 단위 복호화로 바꿔 끼웠다(같은 결과, 약 160MB/s). 검증: `dissect.fve` 공개 테스트 볼륨(일시 중단·암호·복구 키·복호화 완료)에서 해제와 복호화 내용 일치, 삭제 제외 이미지의 NTFS 볼륨을 해제 경로(볼륨 기준 이미지)로 읽혀 출력이 이전과 동일. **파일시스템이 온전한 실제 BitLocker 이미지로는 아직 검증하지 못했다**(공개 테스트 볼륨은 부트 영역만 남긴 것이라 NTFS 로 읽히지 않는다). 암호화되지 않은 이미지의 출력은 0.3.12 와 동일.

0.3.12 (2026-10-03, Autopsy add-on 을 설정 없이 배포하기 위한 변경): 폴더 입력은 **표준 라이브러리만으로 실행**된다. pytsk3·libewf-python 은 이미지 입력일 때만 불러오고(`pipeline.py`, `vfs.py`), 없는 환경에서 이미지를 주면 `UNSUPPORTED_FORMAT` 으로 알린다. brotli·zstandard 는 이전처럼 선택(없으면 웹 캐시 압축 구간만 건너뜀). 출력은 0.3.11 과 동일. 폴더 입력은 확장 길이 경로 접두를 붙여 읽어, Windows 기본 설정(LongPathsEnabled=0)에서도 260자를 넘는 추출 경로를 놓치지 않는다.

0.3.11 (2026-10-03, Autopsy thin adapter PoC — PL 'DFIR 생태계 확장' 문서 기준): 폴더 입력에서 호스트 DFIR 도구가 넘긴 메타데이터를 근거로 쓴다. 추출 폴더 루트에 `_host_metadata.json`(경로별 MFT 시각·레코드 번호, 꺼내지 않은 폴더·바로가기 대상 파일의 시각·크기·첫 8바이트)이 있으면 `DirectoryVfs` 가 읽어 설치(패키지 폴더 생성 시각)·다운로드(바로가기 대상 생성 시각)·MFT 근거를 이미지 입력과 같게 만든다 — 이미지를 다시 읽지 않는다(`vfs.py`, `recent_lnk.py`, `package_install.py`, 약 60줄). 파일이 없으면 이전 폴더 입력과 출력이 동일. 버그 수정: 같은 경로의 **삭제된 옛 `-wal`/캐시 조각이 현존 파일을 덮어쓰던 문제**(이미지 입력에서 logs_2.sqlite 가 옛 WAL 과 짝지어져 최신 트랜잭션이 빠짐) — 현존 파일 우선. 삭제 제외 이미지에서 마지막 프로세스 구간이 14:09:05~14:14:51 → 14:09:34~14:15:23 로 바뀌고(WAL 반영), 정답지 대조는 12/2/5 그대로.

0.3.10 (2026-09-29, PL QA 프레임 적용 — Digital Corpora NPS 이미지로 robustness 확인): Codex 아티팩트가 하나도 없는 이미지는 오류(exit 2)가 아니라 0행 timeline/recovered CSV + 경고(exit 0)로 끝난다. ARTINEX 통합 실행기가 negative control 이미지를 '파서 실패'로 집계하던 문제 해소. 이미지 자체를 못 여는 경우(IMAGE_OPEN_FAILED, UNSUPPORTED_FORMAT)는 그대로 exit 2.

0.3.9 (2026-09-28, 삭제 제외 시나리오 raw 분할 이미지로 검증 — 정답 19건 중 12 일치): 애플리케이션 설치 = `Program Files\WindowsApps\OpenAI.Codex_…` 패키지 폴더의 MFT 생성 시각(`package_install.py`, 확인; 실험 시트의 설치 시각은 첫 실행 시각이라 40분 차이). 최근 항목 저장 규칙이 확장자 없는 대상도 머리 바이트(%PDF, PK, PNG…)로 종류를 판별하고, 문서가 아니면 E05-06 파일 다운로드, 이름 뒤 `(4)` 중복 번호는 떼고 대화 언급과 대조. 검증으로 확인된 이 앱의 한계: 임시 채팅(에이전트 모드는 흔적 없음)·공유 링크·계정 이름 변경(로그·파일 변화 없음)·강제 종료(종료 로그 없음; lockfile·Preferences 는 정상 종료 뒤에도 남아 8월 지문 재현 안 됨)·계정 전환(USN 미커버 + auth.json 삭제됨).
0.3.8 (2026-09-23, 팀원 E01 '삭제 제외 시나리오' 검증): 에이전트 모드 모델 변경 = rollout `turn_context.model` 이 직전 turn 과 달라지는 지점(확인). 이미지 생성 요청 = rollout custom_tool_call 입력에 imagegen/image_gen 도구 탐색·호출(확인). 첨부 업로드 파싱은 `## 파일명: 경로` 줄만 (경로 `/`·`\` 모두). 최근 항목 문서 저장은 Codex 대화·도구 호출에 파일명이 언급될 때만 추정, 아니면 미확정 (다른 앱 다운로드 오귀속 방지 — Claude Desktop PDF 표본).
로컬 흔적이 없어 못 잡는 것: 공유 링크·대화 공유·계정 이름 변경 (POST 요청은 캐시되지 않음), 강제 종료(정상 종료와 구분 불가), 설치·삭제 (USN 저널이 그 구간을 덮을 때만 가능). 앱을 삭제한 이미지에서는 채팅 모드 전체(webcache)가 사라진다.

탐색 디렉터리(`locate.SCAN_ROOTS`): `Users/*/.codex`, `Users/*/Documents/Codex`,
`Users/*/AppData/Local/Packages/OpenAI.Codex_2p2nqsd0c76g0`,
`Program Files/WindowsApps/OpenAI.Codex_*`, `ProgramData/Packages/OpenAI.Codex_2p2nqsd0c76g0`,
`Windows/Prefetch`, `Users/*/AppData/Roaming/Microsoft/Windows/Recent`.
위 표 이외 파일(나머지 SQLite, HTTP 캐시 이외의 채팅창 Chromium 저장소, Helium 하이브 등)은
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
| `VOLUME_LOCKED` | BitLocker 볼륨을 하나도 풀지 못함 (키 없음·키 틀림·`dissect.fve` 미설치). `context.volumes[].protectors` 에 그 볼륨이 받는 키 종류 |
| (경고) 아티팩트 0건 | 이미지는 읽혔으나 Codex 경로 0건. 0.3.10부터 오류가 아니라 **0행 결과 + 경고**로 끝난다(종료코드 0). 앱을 쓰지 않은 음성 대조(negative control) 이미지에서 '없음'이 정상 결과이기 때문. `ARTIFACT_NOT_FOUND` 코드는 라이브러리 사용 시에만 남아 있다 |
| 레코드 단위 | `JSON_DECODE_ERROR`, `READ_FAILED` 등 → 해당 레코드만 `status:error`, 같은 파일의 나머지 라인은 계속 파싱 |

실패를 빈 결과나 성공으로 숨기지 않는다. CLI 종료코드: 0=오류 없음, 1=파일 단위
오류 있음, 2=입력 자체 실패.

## 5. 지원 범위와 한계

**지원**

- 이미지: EWF v1 `.E01`(분할 `.E02…/.EAA…`) — libewf / RAW `.dd/.raw/.img`, 분할 RAW `.001…` — TSK
- 파티션: TSK 가 판독하는 MBR/GPT, 파티션 테이블 없는 볼륨 이미지
- 파일시스템: **NTFS 만** (TSK). 다른 FS 파티션은 `skipped_partitions` 에 사유와 함께 기록
- BitLocker 볼륨: clear key(일시 중단·활성화 대기)·복호화 완료 상태는 키 없이, 그 외는 `--key-material` 로 (0.3.13)
- 삭제 파일: ① 디렉터리 인덱스에 남은 삭제 이름 ② 인덱스에서도 지워진 경우
  미할당 MFT 엔트리의 `$FILE_NAME` 부모 참조(MFT#+seq)가 탐색 디렉터리와 일치하면 경로 복원
  (`allocated:false`, `path_source` 기재)

**미지원 / 한계**

- EWF2(`.Ex01`), L01, VMDK/VHD/QCOW, BitLocker 이외의 암호화 볼륨, TPM 만으로 보호된 BitLocker(복구 키 없이는 풀 수 없다)
- FAT/exFAT/ReFS
- 부모 디렉터리까지 삭제·재할당된 파일은 경로 복원 불가 / 클러스터가 덮어써진 삭제 파일은 내용 불일치 가능
- 파일 카빙(미할당 영역 스캔) 미구현
- 채팅창 Chromium 저장소 중 HTTP 캐시 이외(IndexedDB 등), `SystemAppData\Helium\User.dat`, `$LogFile` → 범위 밖
- `~/.codex` 의 나머지 SQLite(goals/memories/queue)는 발견 목록에만 기록
- USN 레코드에는 **경로가 없다** — 이름·부모 MFT# 만 있어 동명 파일 가능성을 배제 못 하므로 최대 `추정`.
  저널은 오래된 기록부터 잘리므로 "USN 에 없음 = 행위 없음"이 아니다.

## 6. 테스트·검증

이 저장소에는 파서 소스만 있다. 개발 때 쓰던 단위 테스트(`tests/`), 테스트 이미지 생성 도구(`tools/`),
분석표 대조 결과(`verification/`)는 포함되어 있지 않다. 0절의 "합성 테스트 43건"은 그 테스트의 결과다.

저장소 안에서 할 수 있는 검증은 ARTINEX 통합 실행기의 정답지 대조다 (`integration/` 에서 실행, 정답 시트가 있는 실험 이미지 전용).

```powershell
python llm_forensic.py -i <이미지> -o out --only chatgpt_desktop
python validation\verify_merged.py --timeline out\<evidence_id>\timeline.csv --key validation\scenario_keys\plain_nodelete_2026-09-23.csv
```

정답지의 `chatgpt-desktop` 행과 ±120초 창으로 대조해 일치 / 부분 차이 / 불일치를 `verify_report.md` 로 낸다.
폴더 입력 경로는 Autopsy add-on(`../Autopsy_Addon`)이 쓰며, 같은 이미지에서 이미지 입력과 결과가 같은지로 확인한다.

## 7. 소스 구성

```
run_parser.py          어디서든 실행할 수 있는 런처 (cxparser.cli.main 호출)
requirements.txt       pytsk3, libewf-python, dissect.fve — 이미지 입력일 때만 필요
cxparser/
  cli.py               명령행 인자, 덮어쓰기 보호, 종료코드 (__main__.py: python -m cxparser)
  pipeline.py          입력 열기 → 탐색 → 파싱 → 파생 규칙 → 타임라인. 버전 상수
  image.py             E01(pyewf)/RAW(pytsk3) 열기, 세그먼트 누락·절단 검사
  vfs.py               TSK NTFS 탐색(삭제 파일 경로 복원) / 추출 디렉터리(+ _host_metadata.json)
  bitlocker.py         BitLocker 볼륨 해제(dissect.fve) → 복호화 스트림을 TSK 이미지로. 자체 점검: python -m cxparser.bitlocker
  locate.py            탐색 디렉터리(SCAN_ROOTS), 경로 → kind 분류
  usn.py               $Extend/$UsnJrnl:$J — Codex 아티팩트 이름 기준 변경 기록
  derive.py            파생 규칙 — 레코드 간 대조로 로그인·계정 전환·첨부 업로드
  events.py            행위 카탈로그 (E01-01 …)
  model.py             정규화 레코드 — 시각·사용자 행위·근거 3항목
  timeline.py          시각순 정렬, 시각 미상 분리
  output.py            cx_result.json + 팀 공통 CSV 2종, 타임라인 정리 규칙
  util.py              시각 해석, 발췌, 민감정보 마스킹
  errors.py            오류 분류
  artifacts/
    rollout.py           sessions/…/rollout-*.jsonl (주기능)
    session_index.py     session_index.jsonl
    global_state.py      .codex-global-state.json
    auth.py              auth.json (토큰 값 미출력)
    sqlitedb.py          state_5 / thread_history_1 / logs_2 SQLite
    webcache.py          채팅창 HTTP 캐시 — Chrome Blockfile Cache Reader
    webcache_conv.py     캐시 안 ChatGPT API 응답 → 채팅 모드 행위·대화
    prefetch.py          CODEX.EXE-*.pf 실행 기록
    recent_lnk.py        최근 항목 바로가기 → 다운로드
    package_install.py   패키지 폴더 생성 시각 → 설치
    jsontree.py          JSON 키 재귀 탐색, JSON Pointer
```
