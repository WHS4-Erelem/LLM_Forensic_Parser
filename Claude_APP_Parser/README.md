# Claude Desktop 아티팩트 파서

Windows 디스크 이미지(E01 / RAW)에서 Claude Desktop 의 사용자 행위와 대화를 복원한다.
이미지를 마운트하지 않고 읽기 전용으로만 연다.

설치 형태 세 가지를 모두 찾는다.

```
%LOCALAPPDATA%\Packages\Claude_pzs8sxrjxfjjc\LocalCache\Roaming\Claude\   (MSIX)
%APPDATA%\Claude\                                                        (일반 설치)
%LOCALAPPDATA%\Claude\ + %LOCALAPPDATA%\Claude-Data\                     (데이터 분리형)
```

읽는 저장소는 IndexedDB(대화 본문), HTTP 캐시, Local/Session Storage, 설정 파일,
Electron 앱 로그, 프리패치, `$UsnJrnl:$J` 다.

## 설치

Python 3.10 ~ 3.12 (`pytsk3` 와 `libewf-python` 의 Windows 휠이 이 범위에만 있다).

```
python -m pip install --upgrade pip setuptools wheel
python -m pip install -r requirements.txt
```

| 패키지 | 역할 | 없으면 |
| --- | --- | --- |
| `pytsk3` | NTFS 볼륨 열거와 파일 읽기 | 실행되지 않는다 |
| `libewf-python` | E01 열기, 분할 세그먼트 검증 | RAW 이미지만 분석할 수 있다 |
| `ccl-chromium-reader` | IndexedDB 정식 파싱 | 멈추지 않지만 대화의 발화자와 전송 시각을 복원하지 못한다 |
| `zstandard` | HTTP 캐시 응답 압축 해제 | 멈추지 않지만 캐시의 압축 구간 안을 보지 못한다 |

## 실행

```
python run_parser.py --input "D:\case\image.E01" --out-dir "D:\case\out" --format both --verbose
```

분할 E01 은 첫 세그먼트(`.E01`)만 주면 나머지를 자동으로 잇는다. 분할 RAW 는 첫
조각(`.001`)을 준다. 확장자가 아니라 파일 시그니처로 형식을 판별한다.

콘솔 코드 페이지는 파서가 스스로 UTF-8 로 맞춘다. `chcp 65001` 은 필요 없다.

| 옵션 | 역할 |
| --- | --- |
| `--input`, `-i` | E01(분할 포함) / RAW `.dd` `.raw` 이미지 또는 추출 디렉터리 |
| `--out-dir`, `-o` | 결과 폴더 (기본 `cl_out`) |
| `--format` | `csv` CSV 2종 (기본) / `json` 전체 레코드와 근거 / `both` |
| `--input-type` | `auto`(기본) / `image` / `dir` |
| `--kinds` | 파싱할 아티팩트 종류 제한 (쉼표 구분, 기본은 전체) |
| `--max-excerpt` | 근거 발췌 최대 길이 (기본 500자) |
| `--no-usn` | `$UsnJrnl:$J` 분석 생략 |
| `--usn-max-bytes` | `$J` 에서 읽을 최대 바이트 |
| `--overwrite` | 기존 결과가 있어도 덮어쓴다 (기본은 거부) |
| `--verbose`, `-v` | 단계별 진행 상황 출력 |
| `--no-banner` / `--quiet` | 배너 / 요약 생략 |

종료코드 `0` 정상 · `1` 파일 단위 오류 있음 · `2` 입력 실패.

기본이 덮어쓰기 거부인 것은 이전 실행 결과와 새 결과가 한 폴더에 섞이는 것을 막기
위해서다. 같은 폴더에 다시 내려면 `--overwrite` 를 준다.

## 출력

| 파일 | 내용 |
| --- | --- |
| `timeline.csv` | 판정된 사용자 행위 (확정·의심만) |
| `recovered_conversations.csv` | 복원한 대화를 메시지 단위로 |
| `result.json` | 전체 레코드와 판정 근거 (`--format json` 또는 `both`) |

CSV 는 UTF-8 BOM 으로 저장해 엑셀에서 바로 열린다. 시각은 KST, 값이 없는 칸은 `-`.

**timeline.csv** — `Model` · `Timestamp` · `User_behavior` · `Behavior_details ` ·
`Verdict` · `Artifact_path` · `Artifact_details `

`Verdict` 는 `확정`(아티팩트가 그 행위를 직접 증명) 과 `의심`(정황 증거) 두 가지다.
근거를 찾지 못한 행위는 행을 만들지 않는다. `User_behavior` 는 고정된 행위 분류표의
이름만 쓴다 (`parser/events.py` 참조).

**recovered_conversations.csv** — `Model` · `timestamp` · `conversation_uuid` ·
`conversation_title` · `message_uuid` · `parent_message_uuid` · `message order` ·
`role` · `content` · `Artifact_path`

`role` 은 본문이 어디에서 왔는지로 판정한 값이다.

| 값 | 뜻 |
| --- | --- |
| `user` | 사용자가 입력창에 친 말, 파일을 올린 말 |
| `assistant` | 모델 응답 |
| `system` | 앱이 대화에 끼워 넣은 안내 (`<system-reminder>` 등) |
| `tool` | 도구 실행 결과 |
| `unknown` | 역할 표식 없이 저장소에 남아 있던 본문 |

앱은 시스템 안내와 도구 결과도 발화자를 `user` 로 적어 저장한다. 그대로 실으면
사용자가 한 말로 읽히므로 다시 판정한다.

산출물에는 대화 본문이 마스킹 없이 들어간다. 사건 자료로 취급한다.

## 대화를 어떻게 복원하는가

IndexedDB 값은 V8 구조화 복제로 저장된다. 정식으로 역직렬화하면 발화자·전송 시각·대화
UUID·부모 메시지가 기록된 값 그대로 나온다. Claude Desktop 은 대화를 네 곳에 나누어 담는다.

| 데이터베이스 / 스토어 | 형태 | 얻는 것 |
| --- | --- | --- |
| `claude-conversation-store` / `trees` (`product=chat`) | `tree.chat_messages[]` | 발화자, 본문, 순번, 부모 메시지 |
| `claude-conversation-store` / `trees` (`product=cowork`) | `tree.events[].payload.message` | 역할, 본문, 세션 ID, 전송 시각 |
| `keyval-store` / `keyval` (`react-query-cache`) | 대화 목록 | 제목, 생성 시각, 모델, 임시 채팅 여부, 요약 |
| `claude-conversation-store` / `meta` | 열람 기록 | 마지막 열람 시각, 메시지 수 |

같은 부모 메시지 아래에 형제가 둘 이상 있으면 그 자리에서 대화가 갈라진 것이다.
사용자 메시지의 형제는 대화 수정, 모델 응답의 형제는 대화 재시도로 판정한다.

본문이 남지 않은 대화는 목록의 `summary` 필드가 유일한 내용 단서이므로 함께 수집한다.
이 요약은 앱이 생성한 문장이고 사용자가 입력한 말이 아니다. 그래서
`recovered_conversations.csv` 에는 싣지 않고 `result.json` 의 관찰 기록으로만 남기며,
근거 문구에 사용자 발화가 아님을 적는다.

정식 파싱이 닿지 못한 곳(압축 전 `.log` 의 잔존분, 입력창 초안)만 원시 스캔으로 보완한다.
정식 파싱이 이미 읽은 저장소에서 원시 스캔이 다시 집어 올린 본문은 같은 대화의 잘린
조각이므로 `result.json` 에 근거로 남기고 CSV 에는 싣지 않는다 (`superseded_by`).

## 다른 이미지에서는 어떻게 되는가

복원되는 대화의 양은 이미지가 무엇을 갖고 있느냐로 정해진다. 앱은 최근에 연 대화의
트리만 보관하고 나머지는 버린다. 그래서 대화 목록에 수십 건이 있어도 본문을 복원할 수
있는 대화는 몇 건뿐인 경우가 흔하다.

| 이미지 상태 | 결과 |
| --- | --- |
| 앱이 설치돼 있고 최근 대화가 있음 | 본문 + 대화 목록 + 요약 |
| 대화는 많지만 오래됨 | 목록·요약은 나오고 본문은 최근 것만 |
| 앱을 지운 이미지 | 대화 0건. 앱 로그·프리패치로 계정과 실행 흔적만 |
| Windows 사용자가 여럿 | 사용자별로 따로 복원한다 |

무엇을 얻었는지는 결과의 `indexeddb` 로 확인한다.

```
python -c "import json,io;print(json.load(io.open(r'out\result.json',encoding='utf-8'))['indexeddb'])"
```

```
available            ccl-chromium-reader 로 정식 파싱이 됐는지
conversations        확인한 대화 수 (목록 기준)
messages             본문을 복원한 메시지 수
user_messages        그중 사용자가 입력한 것
```

`conversations` 는 큰데 `messages` 가 작다면 파서가 놓친 것이 아니라 그 이미지에 본문이
남아 있지 않은 것이다. `available` 이 `false` 면 대화의 발화자와 전송 시각을 복원하지
못한 상태이므로 보고서에 그 사실을 적는다.

행위 탐지는 이미지에 근거가 있을 때만 행을 만든다. 근거가 없으면 추측해서 채우지 않는다.
결과가 적게 나오는 것과 파서가 실패한 것은 다르며, 후자는 `result.json` 의 `errors` 와
`warnings` 에 남는다.

## 알려진 한계

| 항목 | 내용 |
| --- | --- |
| IndexedDB 정식 파싱 | `ccl-chromium-reader` 가 없거나 역직렬화가 실패하면 원시 스캔으로 대체하고 경고를 남긴다. 이때는 발화자와 전송 시각을 복원하지 못한다 |
| 삭제된 저장소 파일 | 클러스터를 다른 데이터가 덮어쓴 경우 내용을 읽지 않고 그 사실만 기록한다 |
| 대화 본문 보존 범위 | 앱이 최근 대화의 트리만 보관한다. 나머지 대화는 제목·생성 시각·요약만 복원되며 본문은 이미지에 없다 |
| 전체 이미지 해시 | 대용량 이미지 식별을 위해 첫 세그먼트 선두 64MB 만 해시한다. 분석 전후 무결성 증명이 필요하면 `certutil -hashfile` 로 따로 뜬다 |
| 분할 E01 | 마지막 세그먼트가 누락되면 열지 않고 중단한다. 잘린 이미지를 분석해 잘못된 해시를 내지 않기 위해서다 |
| 다운로드 폴더 | 파일 다운로드는 Claude 경로 밖에서 일어나 현재 탐색 범위가 아니다 |
| 다른 제품 | Claude Code(CLI), Claude Web, 이름만 겹치는 다른 앱의 경로는 제외하고 건수를 경고로 남긴다 |
| NTFS 압축 | 압축 속성이 켜진 `$DATA` 는 해제하지 않는다 |

## 구조

```
run_parser.py          실행 진입점
parser/
  cli.py               인자 해석, 콘솔 UTF-8 설정, 덮어쓰기 보호
  pipeline.py          증거 열기 → 경로 탐색 → 파싱 → 중복 정리 → 교차검증
  image.py             E01(분할 검증 포함) · RAW 열기
  vfs.py               NTFS 볼륨 열거와 파일 읽기 (삭제 엔트리 포함)
  locate.py            설치 형태별 경로 식별
  events.py            사용자 행위 분류표
  model.py             레코드 구조 — 시각 · 사용자 행위 · 근거
  timeline.py          시각순 정렬과 시각 미상 분리
  output.py            result.json · CSV 2종
  usn.py               $UsnJrnl:$J 해석
  util.py              시각 변환 · 발췌 · 민감정보 마스킹
  artifacts/
    idbtree.py         IndexedDB 정식 파싱 — V8 역직렬화
    idbstore.py        파싱 결과를 레코드로 — 발화자 판정, 분기 감지
    idb.py             저장소 원시 스캔 — 입력 초안, 잔존분
    v8text.py          V8 문자열 이중 인코딩 해독
    misc.py            캐시 · 설정 파일 · 프리패치
    applog.py          Electron 로그, 타임존 보정
```

다른 LLM 서비스를 붙일 때는 `locate.py` 에 경로를, `artifacts/` 에 저장소 리더를 더한다.
파이프라인과 출력은 건드리지 않는다.
