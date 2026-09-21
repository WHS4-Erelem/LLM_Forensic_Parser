# ChatGPT Web Artifact Parser

Disk Image(E01 / DD·RAW)에서 **ChatGPT 웹(chatgpt.com) 사용 흔적**을 찾아
**"Timestamp + 사용자 행위 + Evidence"** 와 **복구된 대화 내용**을 출력하는 디지털 포렌식 CLI Parser.
WHS 대학 팀 프로젝트 *"LLM 대화 내용 추출 및 사용자 행위 분석"* 의 ChatGPT Web 담당 산출물.

구현은 `chatgpt_parser` 패키지에 있고, `chatgpt_web_parser.py` 는 기존 CLI 진입점이다.
팀 Controller 에서는 `from chatgpt_parser import analyze_chatgpt_web` 으로 그대로 호출할 수 있다 (→ `docs/INTEGRATION_GUIDE.md`).

---

## 1. 요구 환경

| 항목 | 값 |
|---|---|
| Python | **3.12 / 3.13** (둘 다 전체 테스트 통과 확인) |
| 필수 | 없음 — 표준 라이브러리만으로 폴더 입력 분석이 동작한다 |
| 선택 | `pytsk3`(이미지 입력) · `brotli`(Cache 대화 복구) · `cramjam`(LevelDB `.ldb`) · `libewf-python`(E01) |

```
pip install -r requirements.txt
```

`libewf-python` 은 **`requirements.txt` 에 주석으로만 들어 있다.** cp313 wheel 이 없어 Python 3.13 에는 설치되지 않기 때문이다.
E01 을 다루려면 Python 3.12 환경을 따로 만들어 설치한다.

```
py -3.12 -m venv C:\path\to\venv
C:\path\to\venv\Scripts\pip install -r requirements.txt libewf-python==20240506
```

Python 3.13 에서 E01 을 입력하면 `E01_INPUT_REQUIRES_PYEWF` 로 거부하고, DD/RAW 는 그대로 동작한다.
선택 라이브러리가 없으면 해당 Artifact 만 Coverage 에 `NOT_SUPPORTED` / warning 으로 남고 Parser 전체는 죽지 않는다.

## 2. 실행 (CLI)

```
# DD / RAW 이미지 (기본 실행)
python chatgpt_web_parser.py --image D:\test_image\Scenario_Image.dd --csv-dir out_csv

# E01 (Python 3.12 + libewf-python)
C:\path\to\venv\Scripts\python.exe chatgpt_web_parser.py --image evidence.E01 --csv-dir out_csv

# 마운트된 폴더 / 수집 사본 (Chrome Profile 자동 탐색)
python chatgpt_web_parser.py --dir <폴더> --csv-dir out_csv

# 개발자용 상세 분석 파일이 필요할 때
python chatgpt_web_parser.py --image <이미지> --csv-dir out_csv --debug-output --out out_csv\result.json

# 테스트
python -B -m unittest discover -s tests
```

- `--out` 은 **optional** 이다. 주지 않으면 JSON 을 만들지 않고 정상 종료한다. 주는 경우 입력 폴더 **밖**이어야 한다. 기존 파일을 덮어쓰려면 `--overwrite`.
- 종료 코드: `0` 분석 완료(결과 0건 포함) / `2` 잘못된 인자·입력 / `1` 예상하지 못한 오류.
- 폴더 입력은 `Users/<user>/AppData/Local/Google/Chrome/User Data/` 의 `Default`·`Profile <숫자>`(Chrome Stable)를 자동 탐색한다. 못 찾으면 `CHROME_PROFILE_NOT_FOUND` warning + exit 0.

## 2-1. Python 통합 (팀 Controller 에서 호출)

```python
from chatgpt_parser import analyze_chatgpt_web, write_final_outputs

result = analyze_chatgpt_web(r"D:\CASE\POST", input_type="dir")   # 분석만 한다 (파일을 쓰지 않는다)
# input_type="image" 이면 DD/RAW 또는 E01 이미지

for event in result.events:              # 사용자 행위 판정
    print(event.timestamp_kst, event.action, event.action_status, event.confidence)
for message in result.recovered_messages:  # 복구된 대화 메시지
    print(message.role, message.content)

write_final_outputs(result, r"D:\CASE\out")   # timeline.csv + recovered_conversations.csv
```

- 분석(`analyze_chatgpt_web`)과 출력(`write_final_outputs`)이 분리되어 있다. 분석만으로는 파일이 생기지 않는다.
- 결과는 `result.events` / `result.recovered_messages` / `result.conversations` / `result.records` /
  `result.coverage` / `result.warnings` 로 읽는다. 내부 helper 를 직접 부를 필요가 없다.
- 공개되는 이름은 `chatgpt_parser.__all__` 에 있는 것뿐이다. 인자·필드 설명은 **`docs/INTEGRATION_GUIDE.md`**.

## 3. 출력

기본 실행(`--csv-dir <폴더>`)이 만드는 파일은 **정확히 2개**다.

```
<CSV_DIR>\
├─ timeline.csv
└─ recovered_conversations.csv
```

개발자가 상세 분석 파일이 필요하면 `--debug-output` 을 추가한다 — 위 2개에 더해
`coverage.csv` / `records.csv` / `events.csv` / `conversations.csv` / `messages.csv` 가 생성된다.
`result.json` 은 `--out <경로>` 를 줬을 때만 만들어진다.
`--debug-output` 은 **파일로 내보내는 동작만** 바꾼다. 내부 `ParseResult` / `records` / `events` / `conversations` 는 기본 실행에서도 그대로 사용하며 판정 결과는 같다.
CSV 는 모두 `utf-8-sig` 이며 Excel 수식으로 해석될 수 있는 cell 은 앞에 `'` 를 붙여 무력화한다.

### `timeline.csv` — 사용자가 언제 무엇을 했는가

Event 1건 = 1 row, 시각순 정렬. 컬럼 이름·순서는 **팀 공통 CSV 형식**이며,
`Behavior_details ` / `Artifact_details ` 의 **끝 공백 1개는 팀 샘플에 실제로 있는 문자**다.

| 컬럼 | 의미 |
|---|---|
| `Model` | `chatgpt-web` |
| `Timestamp` | 행위 시각 `YYYY-MM-DD HH:MM:SS[.ffffff] KST`. 원본 precision 을 그대로 쓰고 소수 자리를 만들어 내지 않는다. 시각을 확정할 수 없으면 빈 값 |
| `User_behavior` | 판정한 사용자 행위의 사람이 읽는 이름 (`로그인` · `사용자 프롬프트 입력/전송` …). 이름을 확정할 수 없는 action 은 내부 코드 그대로 |
| `Behavior_details ` | 무엇을 했는가 — Evidence Level + 관찰 note (+ 관찰된 `conversation_id=…`). URL query 의 인증 값은 `REDACTED` |
| `Verdict` | `확정` (행위가 있었다고 판정) / `의심` (흔적은 있으나 다른 설명을 배제하지 못함) |
| `Artifact_path` | **원본 파일 경로만** (이미지·입력 폴더 기준 상대 경로) |
| `Artifact_details ` | 무엇을 근거로 판정했는가 — `artifact_type` · `confidence` · `rule_id` · `rule_verification` · `record`(entry / stream / offset / carving 등 record 상세) |

### `recovered_conversations.csv` — 실제로 복구된 대화 내용

복구된 메시지 1건 = 1 row. 컬럼 이름·순서는 팀 공통 CSV 형식이다
(`message order` 는 underscore 가 아니라 중간에 실제 공백이 들어간 이름이다).

| 컬럼 | 의미 |
|---|---|
| `Model` | `chatgpt-web` |
| `timestamp` | 메시지 시각 `YYYY-MM-DD HH:MM:SS[.ffffff] KST`, 없으면 빈 값 |
| `conversation_uuid` / `conversation_title` | 대화 ID·제목 |
| `message_uuid` / `parent_message_uuid` | 메시지 트리 구조 (분기 보존) |
| `message order` | 대화 안에서의 순서 |
| `role` | Artifact 값 그대로. 모르면 `UNKNOWN` |
| `content` | 복구된 원문 전체 (요약·절단 없음) |
| `Artifact_path` | **그 메시지를 실제로 복구해 온 원본 파일 경로만** (Cache 응답이면 본문이 들어 있는 `data_N` / `f_xxxxxx` 까지). 특정할 수 없으면 경로를 만들어 내지 않는다 |

> 최종 CSV 에서 빠진 `confidence` / `rule_id` / `artifact_type` / `recovery_status` 등 상세 근거는
> 삭제하지 않는다. `--debug-output` 의 `events.csv` · `messages.csv` 와 `--out` JSON 에 그대로 남는다.


**복구하지 못한 메시지는 만들어 내지 않는다.** 복구된 메시지가 하나도 없으면 이 파일은 **header 만 있고 row 는 0건**이다
(예: `Scenario_Image.dd` — Event 9건 / 복구 메시지 0건).
메시지는 현재 Cache 의 대화 API 응답에서만 복구하므로 `conversations[]` 에 메시지가 없다는 것이 "대화에 메시지가 없었다"는 뜻은 아니다.

`--out` 으로 만든 JSON(`result.json`)에는 위 CSV 가 요약한 값의 원본(raw timestamp, UTC/KST, Evidence 전체, Coverage, warnings)이 그대로 들어 있다.

## 4. 판정 값 읽는 법

세 값은 서로 다른 것을 뜻하며 섞어 쓰지 않는다.

- **Evidence Level** — 개별 근거가 그 행위에 얼마나 특이적인가.
  `DIRECT`(그 행위에서만 생기는 흔적) / `SUPPORTING`(행위와 함께 관찰되지만 다른 원인도 가능) / `INFERRED`(정황).
- **action_status** — `DETECTED`(행위가 있었다고 판정) / `CANDIDATE`(흔적은 있으나 다른 설명을 배제하지 못함).
- **confidence** — 최종 판정 신뢰도 `HIGH` / `MEDIUM` / `LOW`. 근거 **개수**로 올리지 않는다.
- **rule_verification** — 그 Rule 자체가 수동 실험으로 얼마나 확인됐는가.
  `VERIFIED` / `PARTIALLY_VERIFIED` / `NOT_VERIFIED`. **confidence 는 rule_verification 을 넘지 않는다** (예: `PARTIALLY_VERIFIED` Rule 은 `HIGH` 를 쓰지 않는다).

행위의 **Device Attribution**(이 PC에서 일어났는가)은 confidence 와 별개다. 서버 캐시·Sync 근거는 `SERVER_SIDE_CACHE` 로 표시하며, 그 이유만으로 confidence 를 자동으로 내리지 않는다.

Rule 별 근거와 한계는 `docs/EVENT_RULES.md`, 코드 구현 상태는 `docs/IMPLEMENTATION_STATUS.md` 에 있다.

## 5. 판정하는 사용자 행위

**직접·강한 근거로 판정하는 행위 (기본 `DETECTED`)**

`LOGIN` · `LOGOUT` · `ACCOUNT_SWITCH` · `CONVERSATION_CREATE` · `CONVERSATION_ACCESS` · `PROFILE_ACCESS` ·
`PROMPT_DRAFT` · `DATA_EXPORT_REQUEST` · `IMAGE_GENERATION_REQUEST` · `FILE_DOWNLOAD` · `TEMPORARY_CHAT` ·
`CONVERSATION_RETRY` · `FILE_UPLOAD`

**보조 근거로만 판정하는 행위 (항상 `CANDIDATE`, `LOW`~`MEDIUM`)**

`CONVERSATION_REMOVED_FROM_LIST` · `PROMPT_SEND` · `FILE_UPLOAD_DELETE` · `SHARE_LINK` · `MODEL_CHANGE` ·
`ACCOUNT_NAME_CHANGE` · `HISTORY_DELETE` · `CONVERSATION_DELETE` · `CACHE_DELETE` · `INCOGNITO`

이 10개는 그 행위에만 생기는 직접 증거가 현재 자료에서 확인되지 않아, 조건·한계를 Rule 안에 적고
`CANDIDATE` 로만 판정한다. 근거 Record 가 없으면 **Event 를 만들지 않는다.**

**Rule 은 구현돼 있으나 `Scenario_Image.dd` 에서는 근거가 없어 Event 가 0건인 행위**

`PROMPT_SEND` · `FILE_UPLOAD_DELETE` · `SHARE_LINK` · `MODEL_CHANGE` · `ACCOUNT_NAME_CHANGE` ·
`CONVERSATION_DELETE` · `INCOGNITO` (그 이미지에 근거가 없다는 뜻이며 **미구현이 아니다**).
같은 이미지에서 `CACHE_DELETE` · `HISTORY_DELETE` 는 CANDIDATE / LOW 로 각각 1건 나왔다.

Rule 별 판정 조건과 한계는 `docs/EVENT_RULES.md` §11, 행위별 구현·탐지 상태는 `docs/IMPLEMENTATION_STATUS.md` 에 있다.

## 6. 원본 보호 (read-only)

- Parser 는 입력 이미지·폴더를 **읽기만 한다.** 원본을 수정·삭제·이동·이름변경하지 않는다.
- SQLite 는 원본 경로로 열지 않고, 읽어 온 bytes 를 메모리로 `deserialize` 해 `query_only` 로 연다.
- 결과 JSON·CSV 는 입력 폴더 **밖**에만 쓴다. 기존 파일은 `--overwrite` 없이는 덮어쓰지 않으며, CSV 는 **이번 실행이 쓰는 이름** 중 하나라도 이미 있으면 아무것도 쓰지 않고 중단한다. 출력 폴더의 다른 파일은 읽지도 지우지도 않는다.
- **쿠키 값 / 세션 토큰 / API Key / OAuth `code`·`state` 는 출력·로그·CSV 에 남기지 않는다.** URL query 의 인증 값은 `REDACTED` 로 치환하며, 허용되는 표현은 키 이름 / 존재·부재 / 길이 / SHA-256 일부뿐이다.
- 계정 이메일 등은 마스킹해 기록한다.

## 7. 문서

| 문서 | 내용 |
|---|---|
| `docs/CHATGPT_ARTIFACTS.md` | Artifact 위치·구조·함정, 수동 분석으로 확인된 행위 |
| `docs/EVENT_RULES.md` | Evidence / Confidence 정책, Rule 별 판정 조건과 한계 |
| `docs/OUTPUT_SCHEMA.md` | 결과 JSON·CSV 구조 (팀 고정 Schema 아님) |
| `docs/IMPLEMENTATION_STATUS.md` | 기능별 구현·테스트 상태, 구현하지 않기로 한 행위와 이유 |
| `docs/TEST_PLAN.md` | 테스트 계획과 실행 결과 |
| `docs/PARSER_REQUIREMENTS.md` | 요구사항, 판정 원칙 |
