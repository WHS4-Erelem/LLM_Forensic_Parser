# Gemini Web Forensic Parser

Windows Chrome 환경에서 사용된 **Google Gemini Web** 관련 아티팩트를 분석하는 디지털 포렌식 파서이다.

디스크 이미지 또는 수집된 Chrome 파일시스템을 읽어 Gemini 관련 사용자 행위와 복구 가능한 대화 내용을 추출하며, 팀 통합 규격에 맞는 `timeline.csv`와 `recovered_conversations.csv`를 생성한다.

- Parser version: `1.4.8.6-bitlocker-clear-key`
- Output contract: `2026-09-team-v1`
- Model name in final CSV: `gemini-web`

---

## 1. 주요 기능

- DD / RAW / IMG 디스크 이미지 분석
- E01 이미지 분석
- 분할 RAW 이미지(`.001`, `.002` ...) 분석
- 이미지 내부 Clear Key가 존재하는 BitLocker 볼륨 자동 해제
- 수집된 Chrome User Data / Profile 폴더 분석
- Chrome History, Cache, Storage, Sessions, Cookies, Preferences 등 Gemini 관련 아티팩트 분석
- Google Gemini 내부 RPC 구조(`f.req`, `wrb.fr`, `hNvQHb`, `StreamGenerate`) 기반 메시지 복구
- 다운로드 파일 및 `Zone.Identifier` 상관분석
- `$Recycle.Bin` 기반 생성 이미지 삭제 흔적 분석
- Gemini 사용자 행위 Timeline 생성
- 구조적으로 복구된 Gemini 대화 메시지 출력
- 원본 근거와 분석 상태를 보존한 `gemini_results.json` 생성
- 팀 CSV 규격 자동 검증

파서는 분석 대상 파일을 수정하지 않으며, 이미지 분석은 읽기 전용으로 수행한다.

---

## 2. 요구 환경

### Python

Parser 코드는 Python 3.10 이상을 대상으로 하며, 프로젝트 통합 환경에서는 **Python 3.12** 사용을 권장한다.

### 의존성 설치

```bash
pip install -r requirements.txt
```

현재 `requirements.txt`에는 이미지 및 Chromium 아티팩트 분석에 필요한 주요 의존성이 버전 고정되어 있다.

- `pytsk3`
- `libewf-python`
- `ccl-chromium-reader`
- `dissect.fve`
- `dissect.ntfs`
- `dissect.util`
- `dissect.cstruct`
- `pycryptodome`
- `Brotli`
- `zstandard`

E01 분석에는 `libewf-python`이 필요하다.

BitLocker 분석에는 `dissect.fve`와 `dissect.ntfs`가 필요하다.

---

## 3. 지원 입력

Parser는 아래 세 가지 입력 방식을 지원한다.

### Image Mode

지원 확장자:

```text
.dd
.img
.raw
.E01
.001
```

분할 RAW는 첫 번째 segment인 `.001` 파일을 입력한다.

E01은 첫 번째 `.E01` segment를 입력한다.

예시:

```bash
python gemini_parser.py evidence.dd --output output --csv
```

```bash
python gemini_parser.py evidence.E01 --output output --csv
```

```bash
python gemini_parser.py evidence.001 --output output --csv
```

### Folder Mode

수집된 파일시스템 또는 Chrome User Data를 직접 분석할 수 있다.

권장 입력은 Chrome User Data 디렉터리이다.

```bash
python gemini_parser.py ^
  --folder "C:\Users\<USER>\AppData\Local\Google\Chrome\User Data" ^
  --output output ^
  --csv
```

다음과 같은 상위 경로도 입력할 수 있다.

- Chrome User Data
- Chrome Profile
- Windows 사용자 디렉터리
- `Users` 디렉터리
- 수집된 볼륨 루트

Parser가 분석 가능한 Chrome Profile을 탐색하여 처리한다.

### Profile Mode

추출된 단일 Chrome Profile을 직접 분석하는 개발 및 검증용 입력 방식이다.

```bash
python gemini_parser.py ^
  --profile "C:\evidence\Chrome\User Data\Default" ^
  --output output ^
  --csv
```

`--user-root`은 Profile Mode에서만 사용할 수 있다.

---

## 4. 기본 실행 방법

### 최종 CSV 포함

```bash
python gemini_parser.py evidence.dd --output output --csv
```

생성 파일:

```text
output/
├─ gemini_results.json
├─ timeline.csv
└─ recovered_conversations.csv
```

### Coverage 정보 포함

```bash
python gemini_parser.py evidence.dd --output output --csv --debug-output
```

생성 파일:

```text
output/
├─ gemini_results.json
├─ timeline.csv
├─ recovered_conversations.csv
└─ coverage.csv
```

`--debug-output`을 사용하면 `--csv`도 자동으로 활성화된다.

### 출력 경로 생략

`--output`을 지정하지 않으면 현재 작업 디렉터리에 다음 형식의 폴더가 생성된다.

```text
gemini_output_<UTC timestamp>/
```

Parser는 기존 결과 파일을 자동으로 덮어쓰지 않는다. 같은 출력 파일이 이미 존재하면 새 출력 디렉터리를 사용해야 한다.

---

## 5. 분석 대상 아티팩트

Gemini Web Parser는 Chrome Profile에서 다음 아티팩트를 확인한다.

| Artifact | 주요 분석 내용 |
|---|---|
| Chrome History | Gemini 방문 기록, 대화 URL, 로그인/계정 흐름, 다운로드 |
| Chrome Sessions | 탭/세션 상태, Gemini URL 및 일부 구조화 데이터 |
| Chrome Cookies | 인증 및 계정 관련 보조 흔적 |
| Chrome Preferences | 계정/사이트 설정 및 브라우저 상태 |
| Chrome Secure Preferences | 보호된 Chrome 설정의 Gemini/Google 관련 흔적 |
| Chrome Cache | Gemini HTTP 응답, RPC payload, 메시지 및 파일 관련 흔적 |
| Chrome Local Storage | Gemini 상태 데이터 및 구조화된 저장값 |
| Chrome Session Storage | 세션 단위 Gemini 상태 데이터 |
| Chrome IndexedDB | 구조화된 Gemini 저장 객체 |
| Chrome Service Worker | 캐시 및 Service Worker 저장 데이터 |
| Zone.Identifier | 다운로드 파일의 Referrer / Host URL 상관분석 |
| Windows Recycle Bin | Gemini 생성 이미지로 연결 가능한 삭제 흔적 |

단순 문자열 발견만으로 사용자 행위를 확정하지 않는다. 아티팩트의 구조, URL, conversation ID, 메시지 역할, 파일 정보 등 행위별 근거를 함께 확인한다.

---

## 6. Gemini 메시지 복구

Gemini는 일반적인 JSON 대화 객체뿐 아니라 Google 내부 RPC 형식으로 메시지가 남을 수 있다.

Parser는 다음 구조를 대상으로 복구를 시도한다.

```text
f.req
wrb.fr
hNvQHb
StreamGenerate
batchexecute
```

가능한 경우 다음 정보를 복구한다.

- conversation ID
- conversation title
- message ID
- parent message ID
- message order
- role (`user` / `assistant`)
- message content
- message timestamp
- response / choice 식별 정보

### 복구 정책

`recovered_conversations.csv`에는 **구조적으로 메시지 의미가 확인된 데이터만** 출력한다.

다음과 같은 값은 분석 근거로 보존될 수 있지만 대화 본문으로 바로 승격하지 않는다.

- 단순 History 제목
- Cache에서 우연히 발견된 문자열
- 일반 raw string hit
- UI 문구
- 구조가 확인되지 않은 prompt 후보
- Gemini와 관계가 명확하지 않은 Google 공용 RPC 데이터

History 제목은 대화 메타데이터 및 제한적인 conversation ID 상관분석에 사용할 수 있지만, 사용자 메시지 본문으로 생성하지 않는다.

---

## 7. Timeline 사용자 행위

현재 Parser가 프로젝트 범위에서 다루는 사용자 행위는 다음과 같다.

| 분류 | User_behavior |
|---|---|
| 계정 | 로그인, 로그아웃, 계정 전환, 계정 이름 변경 |
| 대화 | 새로운 대화 생성, 기존 대화 삭제, 대화 수정, 대화 재시도 |
| 프롬프트 | 사용자 프롬프트 입력/전송, 사용자 프롬프트 삭제 |
| 업로드 | 이미지 업로드, 이미지 업로드 삭제, 문서 업로드, 문서 업로드 삭제 |
| 다운로드 | 문서 다운로드, 생성 이미지 다운로드, 생성 이미지 다운로드 삭제 |
| 이미지 | 이미지 생성 요청 |
| 공유/Export | 대화 데이터 Export, 공유 링크 생성 |
| 모델 | 모델 변경 |
| 임시/브라우저 | 임시 채팅 사용, 브라우저 시크릿 모드 |
| 삭제 | 방문기록 삭제, 캐시 삭제 |

내부 분석 단계에서는 더 많은 candidate와 supporting finding을 기록할 수 있지만, 최종 `timeline.csv`에는 팀 규격에 맞고 행위 근거가 충분한 항목만 출력한다.

예를 들어 단순 Gemini 페이지 방문은 최종 사용자 행위로 사용하지 않으며, 일반 Chrome 다운로드도 Gemini와의 연관성이 확인되지 않으면 Gemini Timeline에 포함하지 않는다.

---

## 8. 판정 기준

최종 Timeline의 `Verdict`는 다음 두 값만 사용한다.

| Verdict | 의미 |
|---|---|
| `확정` | 해당 사용자 행위를 직접적으로 지지하는 근거가 확인된 경우 |
| `의심` | 관련 흔적은 확인되지만 행위 자체를 확정하기에는 근거가 부족한 경우 |

Raw 문자열, 설정값, 쿠키, 상태 정보 등은 분석 근거로 `gemini_results.json`에 남을 수 있지만, 그 자체를 사용자 행위로 처리하지 않는다.

근거가 부족한 경우 값을 추측하여 채우지 않는다.

---

## 9. 출력 파일

### `gemini_results.json`

Parser의 전체 분석 결과를 보존하는 기본 출력이다.

주요 내용:

- Artifact discovery / analysis 상태
- raw finding
- derived finding
- source path / locator
- evidence level
- analysis status
- structured message finding
- conversation recovery 상태
- BitLocker / partition 상태
- 분석 제한 및 오류 정보

최종 CSV에서 제외된 supporting finding도 JSON에는 남을 수 있다.

### `timeline.csv`

사용자 행위를 시간순으로 정리한 팀 통합용 CSV이다.

정확한 Header:

```text
Model, Timestamp, User_behavior, Behavior_details , Verdict, Artifact_path, Artifact_details 
```

두 `details` 컬럼 이름의 끝 공백은 팀 출력 계약의 일부이다.

Timestamp 형식:

```text
YYYY-MM-DD HH:MM:SS.ffffff KST
```

시각을 신뢰할 수 없거나 복원할 수 없는 경우 `-`를 사용한다.

### `recovered_conversations.csv`

실제로 구조적으로 복구된 Gemini 메시지를 출력한다.

정확한 Header:

```text
Model, timestamp, conversation_uuid, conversation_title, message_uuid, parent_message_uuid, message order, role, content, Artifact_path
```

메시지 한 건이 한 행이다.

대화가 존재했다는 메타데이터만 있고 메시지 본문을 복구하지 못한 경우 임의의 Conversation 행을 만들지 않는다.

### `coverage.csv`

`--debug-output` 사용 시 생성되는 개발/검증용 파일이다.

각 프로젝트 사용자 행위와 관련 아티팩트의 분석 상태를 확인하는 용도로 사용하며, 최종 팀 통합 CSV에는 포함되지 않는다.

---

## 10. BitLocker 지원

Image Mode에서 BitLocker 파티션이 확인되면 `dissect.fve`를 사용해 볼륨을 확인한다.

현재 지원 방식은 **이미지 내부에 Clear Key가 존재하는 BitLocker 볼륨**이다.

처리 흐름:

```text
Disk Image
  ↓
BitLocker signature 확인
  ↓
이미지 내부 Clear Key 확인
  ↓
dissect.fve로 read-only unlock
  ↓
복호화 stream
  ↓
dissect.ntfs로 NTFS 접근
  ↓
Chrome Profile 분석
```

특징:

- 원본 이미지는 읽기 전용으로 사용
- 전체 복호화 이미지를 별도 파일로 생성하지 않음
- 복호화된 partition stream을 직접 NTFS로 연결
- 외부 Recovery Key / Passphrase / FVEK 입력은 지원하지 않음
- Clear Key가 없으면 `BITLOCKER_LOCKED`
- 필요한 dependency가 없으면 `BITLOCKER_UNSUPPORTED`
- 해제 또는 NTFS open 과정이 실패하면 `BITLOCKER_OPEN_ERROR`
- 상태와 원인은 `gemini_results.json`의 partition 관련 레코드에 기록

BitLocker 파티션을 열 수 없는 경우 CLI는 종료 코드 `2`를 반환한다.

---

## 11. Before / After 이미지 비교

Image Mode에서는 `--baseline-image`를 사용해 이전 상태의 이미지와 비교할 수 있다.

```bash
python gemini_parser.py after.dd ^
  --baseline-image before.dd ^
  --output output ^
  --csv
```

Baseline 비교는 단일 이미지에서 확정하기 어려운 상태 변화 분석을 보조하기 위한 기능이다.

예:

- conversation state 변화
- History 변화
- Cache 변화
- 일부 삭제/수정 후보

`--baseline-image`는 Image Mode에서만 사용할 수 있다.

---

## 12. 주요 CLI 옵션

| 옵션 | 설명 |
|---|---|
| `image` | DD / IMG / RAW / E01 / `.001` 이미지 |
| `--folder` | 수집된 파일시스템 또는 Chrome User Data |
| `--profile` | 단일 Chrome Profile |
| `--baseline-image` | Before image 비교 |
| `--user-root` | Profile Mode의 사용자 루트 |
| `--evidence-root` | Folder/Profile Mode의 수집 볼륨 루트 |
| `--output` | 결과 디렉터리 |
| `--csv` | 팀 형식 CSV 2종 출력 |
| `--debug-output` | `coverage.csv` 추가 출력 |
| `--correlation-seconds` | 방문/다운로드 상관분석 시간 범위, 기본 300초 |
| `--max-binary-mib` | 파일별 raw scan 상한. `0`은 전체 스캔 |
| `--max-matches-per-file` | 파일별 문자열/이미지 finding 최대 개수, 기본 200 |
| `--max-files` | binary artifact tree 분석 파일 수 제한. `0`은 무제한 |
| `--max-json-mib` | Preferences JSON 크기 상한, 기본 64 MiB |
| `--temp-root` | 임시 staging 부모 디렉터리 |
| `--keep-temp` | Image Mode의 추출 임시 파일 유지 |
| `--max-extracted-mib` | Image Mode의 Profile별 추출 크기 제한. 기본은 무제한 |

전체 옵션은 다음 명령으로 확인할 수 있다.

```bash
python gemini_parser.py --help
```

---

## 13. 팀 통합

현재 통합 Runner에서는 다음 형태로 Gemini Web Parser를 실행한다.

```text
gemini_parser.py {image} --output {out} --csv
```

통합 설정 기준:

```text
name: gemini_web
model: gemini-web
timeout: 1800 seconds
```

통합에 전달되는 필수 출력:

```text
timeline.csv
recovered_conversations.csv
```

Parser는 CSV 출력 전에 내부적으로 팀 출력 계약을 검증한다.

검증 대상에는 다음 항목이 포함된다.

- Header 이름 및 순서
- Timeline의 빈 cell 여부
- Timestamp 형식
- `Verdict` 값
- `User_behavior` 값
- Conversation ID
- role
- message order
- message content
- 중복 최종 행

---

## 14. 분석 및 보존 원칙

### Read-only

증거 이미지와 수집 아티팩트는 읽기 전용으로 취급한다.

SQLite 기반 파일은 원본에 직접 연결하지 않고 private temporary copy를 만든 뒤 분석한다. WAL 및 rollback journal이 존재하면 함께 복사한다.

### Evidence와 최종 행위 분리

다음 값은 유용한 근거일 수 있지만 그 자체로 사용자 행위를 의미하지 않는다.

- URL 일부
- 일반 문자열
- 설정 값
- Cache 내부 UI label
- Session/Tabs의 주변 문자열
- 서비스와 직접 연결되지 않은 다운로드
- 단순 파일명

따라서 raw evidence는 JSON에 남기고, 충분한 근거를 갖춘 항목만 최종 Timeline 또는 Conversation CSV로 승격한다.

### 추측 금지

확인되지 않은 timestamp, conversation ID, 파일 연관관계 또는 사용자 행위를 임의로 생성하지 않는다.

---

## 15. 알려진 제한사항

### Gemini의 로컬 저장 특성

Gemini의 실제 대화 내용이 항상 Chrome의 영구 저장소에 남는 것은 아니다.

이미지에 Gemini 사용 흔적이나 대화 URL이 존재하더라도 구조화된 메시지 payload가 남아 있지 않으면 `recovered_conversations.csv`가 0행일 수 있다.

### History의 대화 URL

`/app/<conversation-id>` 방문은 해당 대화를 로컬에서 열람했다는 근거가 될 수 있지만, 그 시각이 실제 대화 생성 시각이라는 의미는 아니다.

따라서 **처음 관찰된 History 방문만으로 `새로운 대화 생성`을 확정하지 않는다.**

### Raw prompt

Gemini 관련 문자열과 prompt 형태의 텍스트가 함께 발견되더라도 구조화된 전송 의미가 확인되지 않으면 사용자 전송 메시지로 확정하지 않는다.

### Candidate 행위

업로드, 삭제, 모델 변경, 이미지 생성 등의 UI/static marker만 확인된 경우 supporting candidate로 보존될 수 있으며 최종 Timeline에서는 제외될 수 있다.

### 브라우저 삭제/시크릿 모드

일반적인 문자열 또는 데이터 부재만으로 방문기록 삭제, 캐시 삭제, 시크릿 모드 사용을 확정하지 않는다.

### BitLocker

현재 외부 Recovery Key, Passphrase, BEK, FVEK 입력은 지원하지 않는다. 이미지 내부 Clear Key가 존재하는 볼륨만 자동 해제한다.

### 결과 행 수

`timeline.csv` 또는 `recovered_conversations.csv`의 행 수는 Parser 성능 자체를 의미하지 않는다.

최종 CSV는 로컬에 남아 있는 아티팩트와 근거 수준에 따라 달라지며, 근거가 부족한 항목은 `gemini_results.json`에만 남을 수 있다.

---

## 16. 종료 코드

| Code | 의미 |
|---:|---|
| `0` | 분석 및 출력 정상 완료 |
| `2` | 입력, 이미지, 출력 경로, BitLocker 또는 분석 조건 오류 |
| `130` | 사용자에 의한 실행 중단 |

일부 아티팩트가 없거나 지원되지 않는 경우에는 전체 Parser를 즉시 실패시키지 않고 해당 상태를 결과에 기록할 수 있다.

---

## 17. 디렉터리 구성

```text
Gemini_Web_Parser/
├─ gemini_parser.py
├─ requirements.txt
└─ README.md
```

`gemini_parser.py`에는 현재 Artifact discovery, image handling, Chromium artifact parsing, Gemini protocol recovery, Timeline/Conversation export가 포함되어 있다.

---

## 18. 빠른 실행 예시

### DD / RAW

```bash
python gemini_parser.py "D:\evidence\image.dd" ^
  --output "D:\result\gemini" ^
  --csv
```

### E01

```bash
python gemini_parser.py "D:\evidence\image.E01" ^
  --output "D:\result\gemini" ^
  --csv
```

### BitLocker 이미지

별도의 키 인자는 사용하지 않는다.

```bash
python gemini_parser.py "D:\evidence\bitlocker.dd" ^
  --output "D:\result\gemini" ^
  --csv
```

이미지 내부에 사용 가능한 Clear Key가 존재하면 자동으로 read-only unlock 후 분석한다.

### Chrome User Data

```bash
python gemini_parser.py ^
  --folder "C:\Users\<USER>\AppData\Local\Google\Chrome\User Data" ^
  --output "D:\result\gemini" ^
  --csv
```

### 상세 Coverage 포함

```bash
python gemini_parser.py "D:\evidence\image.dd" ^
  --output "D:\result\gemini_debug" ^
  --debug-output
```

---

## 19. 출력 해석 시 주의사항

- `확정`은 해당 행위에 대한 직접적 또는 충분히 강한 근거가 있다는 의미이다.
- `의심`은 관련 흔적은 있으나 다른 가능성을 완전히 배제하지 못한 경우이다.
- `gemini_results.json`의 finding 수와 `timeline.csv` 행 수는 동일하지 않을 수 있다.
- History URL 수와 실제 사용자 행위 수는 동일하지 않다.
- 복구된 대화 메시지가 없다는 사실만으로 Gemini를 사용하지 않았다고 판단할 수 없다.
- 특정 아티팩트가 없다는 사실만으로 해당 사용자 행위가 없었다고 단정하지 않는다.

최종 판단은 Timeline, Conversation, JSON의 원본 근거와 Artifact path를 함께 확인하는 것을 기준으로 한다.
