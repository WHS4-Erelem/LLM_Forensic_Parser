# Claude Web 단일 스냅샷 포렌식 파서

**하나의 디스크 이미지**(E01 계열 또는 raw/dd)를 분석하여 Windows의 Google Chrome에서 Claude Web 사용자가 무엇을 했는지 보고하는 Python CLI입니다. 모든 결론은 보수적으로 판단하며, 원본 레코드까지 추적할 수 있습니다.

이 도구는 하나의 질문에 답합니다:

> 어떤 Claude 계정이 무엇을, 언제 했으며, 그 판단을 뒷받침하는 아티팩트는 무엇인가?

성공의 기준은 많은 이벤트를 생성하는 것이 아닙니다. 근거 없는 확정 판정을 최소화하고, 다른 조사자가 다시 검증할 수 있는 결과를 만드는 것입니다.

---

## 설치

```bash
python -m pip install -r requirements.lock
```

Python 3.12 이상이 필요합니다(Windows 11 x64의 Python 3.14.2에서 개발 및 검증).  
Python 3.14 이상에서는 표준 라이브러리의 zstd를 사용합니다. 그보다 낮은 지원 Python에서는 `requirements.lock`이 조건부로 `zstandard` fallback을 설치하며, 동일 의존성은 `zstd` optional extra로도 제공됩니다.

> **서드파티 라이선스:** 현재 실행 의존성과 고정 버전은 [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md)에 정리되어 있습니다. 재배포 전에는 각 upstream의 실제 라이선스 원문을 확인하십시오.

## 사용법

```bash
python -m claude_web_forensics analyze --image /evidence/case.E01 --output /results/case01
```

```bash
python -m claude_web_forensics analyze --image /evidence/disk.dd --output /results/case01 --extended-fs
```

### 옵션

| 옵션 | 용도 |
|---|---|
| `--image` | E01 계열 또는 raw/dd 이미지 (**필수**) |
| `--output` | 결과 CSV 2개를 저장할 폴더. 이미지 파일이 속한 디렉터리 트리 밖이어야 하며 이미지 경로의 상위 경로여서도 안 됨 (**필수**) |
| `--partition-offset` / `--partition-index` | 자동 탐색이 모호할 때 파티션 지정 |
| `--windows-user` / `--chrome-profile` | 한 사용자 또는 프로필로 분석 범위 제한 |
| `--key-material` | `recovery:<48자리>`, `bek:<경로>`, `fvek:<hex>`, `passphrase:<text>` |
| `--extended-fs` | `$UsnJrnl:$J`, `$Recycle.Bin` 추가 분석 (Claude 관련성이 검증된 파일만 증거로 사용) |
| `--keep-staging` | 임시 작업 폴더를 삭제하지 않고 유지 |
| `--overwrite` | 이전 실행의 `timeline.csv` / `recovered_conversations.csv`를 교체 |
| `--log-level` | 콘솔 로그 수준: `DEBUG` / `INFO` / `WARNING` / `ERROR` |

파티션/Windows 사용자/Chrome 프로필 선택 옵션은 자동 탐색 결과가 모호할 때 사용합니다. 그 외 옵션은 분석 범위나 출력 동작을 변경합니다. 키 자료는 로그나 CSV에 기록되지 않습니다.

### 종료 코드

| 코드 | 의미 |
|---|---|
| `0` | 분석 완료 — 개별 아티팩트 실패는 콘솔에 기록되며 치명적이지 않음 |
| `1` | 이미지를 열 수 없거나 결과 CSV의 재검증(readback)에 실패함 |
| `2` | 잘못된 인수, 또는 출력 위치 거부(이미지 경로와 안전하지 않은 상하위 관계이거나 `--overwrite` 없이 이전 결과 CSV가 존재) |

## 출력

출력 폴더에는 다음 두 파일만 생성됩니다.

```text
output/
├─ timeline.csv                 확정 / 의심 사용자 행위
└─ recovered_conversations.csv  복구된 Claude 대화 메시지
```

진행 상황과 파싱 상태는 콘솔에만 출력하며 로그 파일은 만들지 않습니다. 아티팩트 staging 사본은 출력 폴더 밖의 임시 작업 폴더에 두고 실행이 끝나면 삭제합니다(`--keep-staging` 사용 시 유지). 파일 바이트는 내보내지 않으며 해시도 계산하지 않습니다.

두 CSV 모두 BOM이 포함된 UTF-8(Excel에서 한글이 깨지지 않음)이며, 인덱스 열이 없고, 표준 CSV quoting을 적용해 값 안의 쉼표·큰따옴표·줄바꿈이 한 셀 안에 유지됩니다. 결과가 0건이어도 헤더는 항상 기록되며, 임시 이름으로 작성 → 재검증 → 이름 변경 순서로 저장합니다. 같은 입력이면 행 순서도 항상 같습니다. `=` `+` `-` `@`로 시작하는 값에는 `'`를 붙여 Excel이 수식으로 실행하지 않게 합니다.

* `timestamp`는 **KST만** 사용하며 형식은 `2026-08-21 07:43:58.056458 KST`입니다. 근거 있는 시각이 없으면 비워 둡니다.
* 대표 시각은 행위를 *직접 입증하는* 레코드의 시각입니다 — 다운로드는 `downloads.end_time`, 휴지통 삭제는 `$I` 삭제 시각, 모델 변경은 `model_selected` 이벤트.
* 마스킹하지 않습니다. 단, 쿠키·토큰 **값**은 출력하지 않고 host, name, path, 시각, flag, 값 길이만 기록합니다.

### timeline.csv

`Model` · `Timestamp` · `User_behavior` · `Behavior_details ` · `Verdict` · `Artifact_path` · `Artifact_details `

두 `…details ` 헤더 끝에는 ASCII 공백이 하나 있으며 참조 CSV와 동일합니다.

`Model`은 항상 `claude-web`입니다. `Verdict`는 `확정`과 `의심`만 출력하며 `판단불가`는 출력하지 않습니다. `User_behavior`에는 판정과 관계없이 아래 24개 고정 행위명 중 하나만 들어갑니다. `Behavior_details `는 `<흔적 성격>_<핵심 내용>` 형식입니다(예: `프롬프트 작성 흔적(전송 미확인)_[MRK_E0505] …`, `이미지 업로드 준비 흔적(전송 불확인)_x.png`, `Export 설정 화면 접근(완료 미확인)_<URL>`).

`Artifact_path`에는 해당 행의 판정에 실제로 사용된 아티팩트의 **디스크 이미지 내부 논리 경로**를 중복 제거 후 `|`로 연결해 기록합니다(예: `C:\Users\<사용자>\AppData\Local\Google\Chrome\User Data\Default\History`, `…\Cache\Cache_Data\data_3`, `…\IndexedDB\https_claude.ai_0.indexeddb.leveldb\000005.ldb`, `C:\$MFT`, `C:\$Extend\$UsnJrnl:$J`, `C:\$Recycle.Bin\<SID>\$I…`, `…\Downloads\a.pdf:Zone.Identifier`). 경로를 확인할 수 없으면 빈 문자열로 두며, 분석 PC의 staging 경로는 절대 기록하지 않습니다. `Artifact_details `에는 기존의 파싱 결과 설명을 유지합니다.

`timeline.csv`에는 실제 UUID를 출력하지 않습니다. 계정·조직·대화·메시지·파일·snapshot UUID는 분석 과정에서 그대로 사용하지만, 출력 직전에 두 상세 열에서 제거합니다(`대화 UUID=…` 같은 라벨 쌍은 통째로 삭제하고, URL·JSON 미리보기 안의 UUID는 `[uuid]`로 대체). 대화 제목, 파일명, 모델명, URL, 다운로드 상태, MIME 등 나머지 정보는 유지하며 사용자가 입력한 리터럴 `<uuid>` 문자열도 그대로 둡니다.

| action_code | User_behavior (고정) |
|---|---|
| E01-01 / E01-02 / E01-03 | 로그인 / 로그아웃 / 계정 전환 |
| E03-01 / E03-02 / E03-03 / E03-04 | 새로운 대화 생성 / 기존 대화 삭제 / 대화 수정 / 대화 재시도 |
| E04-01 | 사용자 프롬프트 입력/전송 |
| E05-01 / E05-02 / E05-03 / E05-04 / E05-05 | 이미지 업로드 / 이미지 업로드 삭제 / 문서 업로드 / 문서 업로드 삭제 / 문서 다운로드 |
| E06-01 / E06-02 / E06-03 | 이미지 생성 요청 / 생성 이미지 다운로드 / 생성 이미지 다운로드 삭제 |
| E07-01 / E07-02 | 대화 데이터 Export / 공유 링크 생성 |
| E09-01 / E09-02 | 모델 변경 / 계정 이름 변경 |
| E10-01 / E10-02 / E10-03 / E10-04 | 임시 채팅 사용 / 브라우저 시크릿 모드 / 방문기록 삭제 / 캐시 삭제 |

제외 항목(Claude 웹 기능이 아니거나 실험에서 수행할 수 없음)은 detector와 catalogue 항목이 없습니다: E02-01, E02-02, E04-02, E07-03, E08-01, E08-02, E08-03, E09-03.

### recovered_conversations.csv

`Model` · `timestamp` · `conversation_uuid` · `conversation_title` · `message_uuid` · `parent_message_uuid` · `message order` · `role` · `content` · `Artifact_path`

`conversation_uuid`, `message_uuid`, `parent_message_uuid` 값과 `content` 원문은 그대로 출력합니다.

* `message order`는 대화마다 1부터 다시 시작합니다. `message_uuid` → `parent_message_uuid` 관계를 루트부터 깊이 우선으로 따라가며, 형제 분기(재시도 등)는 timestamp → `message_uuid` → content 순서를 결정적 tie-break로 사용합니다. 부모가 없는 메시지는 루트로 처리하며, 순환에 걸린 메시지도 결정적인 순서로 뒤에 배치합니다. 각 번호는 중복·누락 없이 한 번씩만 부여됩니다.
* 복구 완전성(`recovery_status()`, `완전 복구` / `부분 복구`)은 내부적으로 계속 계산하지만 열로는 출력하지 않습니다. 삭제 여부가 아니라 복구 완전성을 뜻합니다. `conversation_uuid`, `message_uuid`, 알려진 role(`user`/`assistant`/`system`), 비어 있지 않은 `content`가 모두 복구되고 truncation 표시가 없으면 `완전 복구`, 그렇지 않으면 `부분 복구`입니다. Cache에서 발견되었다는 이유만으로 삭제로 판정하지 않습니다.
* `Artifact_path`에는 해당 메시지를 복구한 레코드의 이미지 내부 논리 경로를 중복 제거 후 `|`로 연결합니다.
* 메시지 하나가 한 행이며 본문 전체가 한 셀에 들어갑니다.

### 출력 폴더

`timeline.csv` 또는 `recovered_conversations.csv`가 이미 있으면 `--overwrite` 없이는 실행을 거부하며, `--overwrite`를 주어도 이 두 파일만 교체합니다. 폴더 안의 다른 파일은 수정하거나 삭제하지 않습니다.

## 판정

| 판정 | 의미 |
|---|---|
| `확정` | 동일한 엔티티의 동일한 행위를 **서로 독립적인** 2개 이상의 아티팩트 계열이 뒷받침하거나, 하나의 명시적 레코드가 해당 행위를 직접 입증하며 그 레코드가 해당 detector의 직접 증거 allowlist에 포함됨 |
| `의심` | 구체적인 양성 흔적이 존재하지만 위 두 조건 중 어느 것도 충족하지 않음 |
| `판단불가` | 증거가 없거나, 필요한 아티팩트가 누락되었거나, 증거가 충돌하거나, 단일 스냅샷만으로 해당 경우를 구분할 수 없음 |

두 개의 레코드가 곧 두 개의 아티팩트 계열을 의미하지는 않습니다. 교차 검증에서는 서로 다른 계열만 계산하며, 아래 각각은 **하나의 계열**로 계산합니다.

* History `downloads` + `downloads_url_chains`
* `$MFT` `$STANDARD_INFORMATION` + `$FILE_NAME`
* 하나의 IndexedDB key에 대한 live + historical 버전
* Cache raw body + decoded body
* 하나의 SNSS 파일 내부에서 반복되는 command

증거의 부재만으로는 이벤트를 생성하지 않습니다. `의심`조차 생성하지 않습니다.

## Detector 매트릭스

catalogue에 정의된 행위 24개마다 등록된 detector가 하나씩 존재합니다.

| Rule | Action | 직접 증거 allowlist | 비고 |
|---|---|---|---|
| `R-E0101` | E01-01 로그인 | token fragment가 포함된 magic-link 인증 URL | 현재 cookie만 있거나 `/new` 방문 1건만 있는 경우는 제외 |
| `R-E0102` | E01-02 로그아웃 | 명시적인 `/logout` 또는 `login?from=logout` | cookie 부재는 절대 사용하지 않음 |
| `R-E0103` | E01-03 계정 전환 | *(없음)* | 2개 이상의 계정 컨텍스트와 재인증/onboarding 흔적이 필요하며, 잔존 UUID만으로는 계정 전환으로 보지 않음 |
| `R-E0301` | E03-01 새로운 대화 생성 | conversation API object + root user message | |
| `R-E0302` | E03-02 기존 대화 삭제 | 명시적인 delete 이벤트 / tombstone | Cache 잔존은 삭제의 증거가 아니며, server-side 영구 삭제라고 부르지 않음 |
| `R-E0303` | E03-03 대화 수정 | 하나의 parent 아래에 ≥2개의 human message UUID | 텍스트가 다르다는 사실만으로 수정으로 보지 않음 |
| `R-E0304` | E03-04 대화 재시도 | assistant branch의 `input_mode=retry` | |
| `R-E0401` | E04-01 사용자 프롬프트 입력/전송 | `created_at`이 있는 user message UUID | draft만 있으면 `의심`이며 `행위_상세`에는 "프롬프트 작성 흔적(전송 미확인)"으로 기록 |
| `R-E0501` / `R-E0503` | E05-01/03 이미지 / 문서 업로드 | 전송된 메시지와 연결된 attachment | draft만 있으면 `의심`이며 `행위_상세`에는 "준비 흔적(전송 불확인)"으로 기록 |
| `R-E0502` / `R-E0504` | E05-02/04 첨부파일 제거 | 명시적인 removal 이벤트 / tombstone | 잔존 metadata는 제거의 증거가 아님 |
| `R-E0505` | E05-05 문서 다운로드 | History `COMPLETE` + target path + Claude URL chain | 중단된 경우: `의심`, "다운로드 시도 흔적(완료 미확인)" |
| `R-E0601` | E06-01 이미지 생성 | user message와 연결된 assistant tool result / output resource | prompt keyword만으로는 절대 충분하지 않음 |
| `R-E0602` | E06-02 생성 이미지 다운로드 | `R-E0505`와 동일하며 image MIME 사용 | |
| `R-E0603` | E06-03 다운로드 파일 삭제 | exact path로 Claude 다운로드와 연결된 `$I` 삭제 metadata | USN은 경로/삭제 정황을 보강할 수 있으나 standalone USN delete 또는 deleted MFT만으로 이벤트를 생성하지 않음 |
| `R-E0701` | E07-01 대화 데이터 Export | export API request / archive / completion object | settings 방문만 있으면: `의심`, "Export 설정 화면 접근(완료 미확인)" |
| `R-E0702` | E07-02 공유 링크 생성 | snapshot→conversation을 매핑하는 snapshot object | |
| `R-E0901` | E09-01 모델 변경 | `previous_model`이 있는 `model_selector.model_selected` | 현재 모델 하나만으로는 변경 이벤트를 생성하지 않음 |
| `R-E0902` | E09-02 계정 이름 변경 | 하나의 account UUID에 대해 시간 순서가 있는 두 개의 display name | 현재 이름 하나는 metadata일 뿐 |
| `R-E1001` | E10-01 임시 채팅 사용 | `is_temporary=true` | Chrome Incognito와 동일하지 않음 |
| `R-E1002` | E10-02 Chrome Incognito | *(없음)* | 고정 `판단불가`: 부재를 근거로 추론하지 않음 |
| `R-E1003` | E10-03 방문기록 삭제 | *(없음)* | record 부재를 사용하지 않음 |
| `R-E1004` | E10-04 캐시 삭제 | *(없음; 최대 `의심`)* | 일치하는 USN Cache 삭제가 50건 이상이면 의심 이벤트를 만들 수 있으며, Cache가 비어 있다는 사실만으로 판단하지 않음 |

## 지원 매트릭스

실제 이미지에서 검증된 항목만 *supported*로 표시합니다.

| 기능 | 상태 | 근거 |
|---|---|---|
| E01 단일 segment | **supported** | 기준 E01, 64 GiB, end-to-end |
| E01 분할 segment | partial | segment 탐색 및 gap 보고 구현됨. 분할 이미지 테스트는 없음 |
| raw/dd MBR | partial | **synthetic fixture에서만 검증** — 실제 dd가 제공되지 않음 |
| raw/dd GPT | partial | **synthetic fixture에서만 검증** |
| 분할 raw (`.001`) | partial | synthetic fixture |
| GPT partition 탐색 | **supported** | 기준 E01 |
| BitLocker clear key | **supported** | 기준 E01(protector 존재, unlock 확인) |
| BitLocker recovery / BEK / FVEK | not_tested | 구현됨. 사용 가능한 fixture 없음 |
| BitLocker key 누락 | partial | signature 탐지 테스트됨. unlock 거부 경로는 테스트되지 않음 |
| NTFS `$MFT`, ADS, data stream | **supported** | 기준 E01 |
| History / Cookies / Cache / IndexedDB / Local Storage | **supported** | 기준 E01 |
| Sessions/Tabs (SNSS) | **partial** | upstream CCL이 partial support로 명시 |
| Chrome SQLite `-wal` / `-shm` | not_tested | 코드에서 처리됨. 기준 이미지에는 `-journal`만 존재 |
| Chrome schema variation | not_tested | schema introspection 구현됨. 한 버전만 관찰 |
| zstd / gzip / deflate / brotli | **supported** | zstd는 실제 환경에서 관찰됨. 나머지는 unit test 완료 |
| content size가 없는 zstd | **supported** | streaming fallback을 사용한 unit test |
| `$UsnJrnl:$J` (V2) | **supported** | 기준 E01; 같은 FRN의 rename/move chain은 모든 hop이 해석될 때 연속 경로로 재구성 |
| USN V3 / 지원되지 않는 버전 | partial | V3 구현됨. skip 경로 unit test 완료 |
| `$Recycle.Bin` `$I` v2 + `$R` | **supported** | 기준 E01 |
| `$Recycle.Bin` `$I` v1 | partial | synthetic `$I`를 사용한 unit test |
| CSV 안전성 (BOM, quoting, 수식 방지, readback) | **supported** | unit test + 매 실행 시 readback validation |

## 알려진 한계

* **단일 스냅샷.** 전/후 비교는 범위 밖입니다. 두 번의 수집 간 변화로만 확인할 수 있는 행위는 `판단불가`로 남습니다.
* **`$UsnJrnl`은 부분적인 기록입니다.** Journal wrap 또는 truncation으로 오래된 레코드가 사라질 수 있습니다. create+delete 쌍은 cross-volume move로 보고하지 않으며, 파일명만으로 파일을 연결하지 않습니다.
* **`$Recycle.Bin`은 Shift+Delete, 비워진 휴지통, 덮어써진 cluster를 포착하지 못합니다.** `$I`는 삭제 metadata이며 파일 바이트는 내보내지 않습니다.
* **CCL은 live 레코드와 old/deleted LevelDB 레코드를 함께 반환할 수 있습니다.** 상태를 `LIVE` / `HISTORICAL_OR_DELETED` / `UNKNOWN`으로 보존하며 "current"로 합치지 않습니다. old와 deleted를 구분할 수 없는 경우에는 어느 쪽이라고도 단정하지 않습니다.
* 설계상 **Login Data는 절대 열지 않습니다**.
* **unallocated carving을 수행하지 않으며**, server-side reconstruction, password 분석, 일반적인 PII masking 또는 Chrome Incognito 사용 여부 추론도 수행하지 않습니다.
* **Cache 잔존만으로 대화가 여전히 존재하거나 삭제되었다는 것을 입증할 수 없습니다.** "Recovered"는 이 이미지에서 복구되었다는 뜻이지 서버에 존재한다는 뜻이 아닙니다.
* **Account UUID는 절대 추측하지 않습니다.** 후보가 여러 개이면 필드를 비워 두며, 후보들 중 하나를 임의로 선택하지 않습니다.
* **raw/dd는 synthetic fixture로만 검증되었습니다.** 이 프로젝트에는 실제 dd acquisition이 제공되지 않았습니다.

## 소스 구조

`src/claude_web_forensics/` 아래 모듈 27개(그 외 `__init__.py` 9개):

| 모듈 | 내용 |
|---|---|
| `cli.py`, `pipeline.py` | 진입점과 실행 흐름 |
| `image/adapters.py` | 이미지 인터페이스, EWF 및 raw/dd reader |
| `image/volumes.py`, `image/acquire.py` | 파티션·BitLocker 처리, 아티팩트 staging |
| `discovery/environment.py` | Windows 설치·사용자, Chrome 프로필 탐색 |
| `decode/content.py` | 압축 해제, 텍스트·JSON 디코딩, 값 암호화 상태 |
| `parsers/history.py`, `cookies.py`, `cache.py` | Chrome SQLite와 Cache |
| `parsers/browser_storage.py` | IndexedDB, Local Storage, Sessions/Tabs |
| `parsers/filesystem.py` | `$MFT`, Zone.Identifier, Downloads |
| `parsers/extended_fs.py` | `$UsnJrnl:$J`, `$Recycle.Bin` |
| `parsers/ccl_adapter.py`, `parsers/common.py` | CCL wrapper와 공통 helper |
| `analysis/rules.py` | 24개 행위 카탈로그와 판정 규칙 |
| `analysis/detectors.py` | 행위별 detector |
| `analysis/accounts.py`, `conversations.py`, `correlator.py`, `summaries.py` | 계정 연결, 대화 트리, 증거 그룹화, 아티팩트 상세 |
| `analysis/claude_scope.py` | 디스크 파일의 Claude 관련성 판정 |
| `analysis/file_analysis.py` | 파일 흔적, 경로 생명주기, USN 최종 경로 확인 |
| `model/entities.py` | 증거·행위·대화·파싱 상태·파일 추적 데이터 클래스 |
| `util/common.py` | 직렬화, 스트림 helper, 시간 변환 |
| `output/csv_export.py` | 결과 CSV 2개 |

## 오류 격리

하나의 parser 또는 detector가 실패해도 나머지 분석은 계속 진행합니다. 이미지/볼륨을 열 수 없거나 결과 CSV 재검증에 실패하면 종료 코드 `1`, 잘못된 인수나 거부된 출력 위치는 종료 코드 `2`를 반환합니다. Stack trace는 콘솔에만 출력하며, Key material과 token 값은 로그에 남기지 않습니다.

## 문서

| 문서 | 내용 |
|---|---|
| [docs/design_review.md](docs/design_review.md) | 현재 구현 검토: 범위, module, pipeline, 제거된 과거 설계 가정 |
| [docs/cli_usage.md](docs/cli_usage.md) | 전체 option reference, 종료 코드, runtime, 안전 동작 |
| [docs/output_schema.md](docs/output_schema.md) | 결과 CSV 2개의 모든 column |
| [docs/detector_rules.md](docs/detector_rules.md) | predicate, allowlist, disqualifier를 포함한 24개 전체 rule |
| [docs/known_limitations.md](docs/known_limitations.md) | 경계, `not_tested` 항목 및 그 이유 |
| [THIRD_PARTY_NOTICES.md](THIRD_PARTY_NOTICES.md) | 현재 서드파티 의존성/버전 고지와 과거 pytsk3/libewf 검토 상태 |

## 개발

```bash
python -m pytest tests/unit -q          # 빠름, 이미지 불필요
python -m pytest tests -q               # integration test 포함
```

`tests/fixtures/synth.py`는 테스트 suite에서 사용하는 synthetic MBR/GPT/split raw 이미지, USN 레코드 및 `$I` 파일을 생성합니다.
