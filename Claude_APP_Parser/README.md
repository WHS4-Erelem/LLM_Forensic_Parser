# Claude Desktop 아티팩트 파서

Windows 디스크 이미지(E01 / RAW)에서 Claude Desktop 의 사용자 행위와 대화를 복원한다.
이미지를 마운트하지 않고 읽기 전용으로만 연다. BitLocker 로 암호화된 볼륨은 키를 받아
풀어서 읽고, 이미지 없이 실행 중인 Windows PC 를 직접 분석(라이브)할 수도 있다.

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
| `dissect.fve` | BitLocker 볼륨 해제 (`pycryptodome` 이 함께 설치된다) | BitLocker 파티션만 `VOLUME_LOCKED` 로 멈춘다. 일반 이미지·라이브 입력은 그대로 동작한다 |

## 실행

```
python run_parser.py --input "D:\case\image.E01" --out-dir "D:\case\out" --format both --verbose
```

분할 E01 은 첫 세그먼트(`.E01`)만 주면 나머지를 자동으로 잇는다. 분할 RAW 는 첫
조각(`.001`)을 준다. 확장자가 아니라 파일 시그니처로 형식을 판별한다.

콘솔 코드 페이지는 파서가 스스로 UTF-8 로 맞춘다. `chcp 65001` 은 필요 없다.

| 옵션 | 역할 |
| --- | --- |
| `--input`, `-i` | E01(분할 포함) / RAW `.dd` `.raw` 이미지, 추출 디렉터리, 또는 (라이브) 볼륨 루트 |
| `--out-dir`, `-o` | 결과 폴더 (기본 `cl_out`) |
| `--format` | `csv` CSV 2종 (기본) / `json` 전체 레코드와 근거 / `both` |
| `--input-type` | `auto`(기본) / `image` / `dir` / `live` (라이브는 자동 선택되지 않는다) |
| `--key-material` | BitLocker 키: `recovery:<48자리>` / `passphrase:<암호>` / `bek:<.BEK 경로>` / `fvek:<hex>`. 환경변수 `ERELM_KEY_MATERIAL` 로도 받는다 |
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

### BitLocker 이미지

```
set ERELM_KEY_MATERIAL=recovery:123456-123456-123456-123456-123456-123456-123456-123456
python run_parser.py --input "D:\case\image.E01" --out-dir "D:\case\out"
```

파티션 선두의 `-FVE-FS-` 로 BitLocker 를 알아보고 `dissect.fve` 로 푼 뒤, 복호화된
볼륨을 일반 NTFS 와 같은 경로로 읽는다 (MFT·삭제 엔트리·`$UsnJrnl` 포함). 키 형식과
환경변수 이름은 팀의 다른 파서(Claude Web · ChatGPT)와 같다.

| 볼륨 상태 | 결과 |
| --- | --- |
| clear key (보호 일시 중단 등) · 복호화 완료 | 키 없이 열린다 |
| 복구 키 · 암호 · BEK · FVEK 를 줌 | 그 키로 연다 |
| 키가 없거나 틀림 | `VOLUME_LOCKED` (종료코드 2). 볼륨의 키 보호자 목록을 함께 출력한다 |
| 평문 볼륨 + 잠긴 볼륨 | `VOLUME_LOCKED`. 복구 파티션 같은 평문 볼륨만 읽고 "아티팩트 없음" 으로 끝내지 않는다 |

키는 명령행 기록에 남지 않게 환경변수로 주는 것을 권한다. 키 값은 콘솔·로그·결과
파일 어디에도 쓰지 않고, 어떤 방법으로 풀었는지(`unlock_method`)만 `result.json`
의 `filesystem.volumes` 에 남긴다. 무차별 대입이나 우회는 하지 않는다.

### 라이브 분석 (실행 중인 PC)

```
python run_parser.py --input-type live --out-dir "D:\out"
```

이미지를 뜨지 않고 지금 이 PC 의 `C:\`(시스템 드라이브)에서 Claude Desktop 저장 경로를
찾아 읽는다. 다른 드라이브나 마운트 폴더는 `--input D:\` 로 준다.

- 이미지 분석과 **같은 탐색 경로**(설치 형태 세 가지 + 앱 로그 + 프리패치)만 본다.
  디스크 전체를 훑지 않는다. 판정 규칙도 이미지와 같다.
- 원본은 **읽기 전용**으로만 연다. 복사본이나 임시 파일을 원본 경로에 만들지 않고,
  출력 폴더가 탐색 경로 안이면 실행을 거부한다.
- 실행 중인 앱이 잡고 있는 파일(HTTP 캐시 등)도 다른 프로세스와 공유하는 읽기로 연다.
  그래도 못 읽은 파일은 `filesystem.read_failures` 와 경고로 남긴다.
- 관리자 권한이 아니면 `C:\Windows\Prefetch` 와 `C:\Program Files\WindowsApps` 를 볼 수
  없다. 열지 못한 폴더는 `filesystem.denied` 에 남는다.
- 파일 시각·MFT 번호는 `os.stat` 값이고, 그 출처를 근거의 `time_source` 에 적는다.
  `Artifact_details` 에는 `수집=live` 가 붙는다.

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

`Artifact_path` 의 드라이브 문자는 가정이 아니라 실측이다. 이미지 입력은 `HKLM\SYSTEM\MountedDevices`
를 읽어 각 NTFS 볼륨이 원래 PC 에서 어떤 문자(`C:` 등)였는지 확인한다(`parser/mounted_devices.py`,
MBR=디스크 서명+파티션 오프셋 / GPT=파티션 GUID 로 대조). SYSTEM 하이브가 없거나 문자가 없는
파티션(복구·예약)은 종전대로 `C:` 로 표기한다. 근거는 `result.json` 의 `filesystem.drive_letters` 에 남는다.

`Behavior_details ` 는 `<행위>_<짧은 라벨>` 꼴의 요약만 담는다. 로그 원문·타임스탬프
같은 긴 텍스트는 넣지 않는다 (원문은 `result.json` 의 `details`·`evidence.excerpt` 에 남는다).
팀 공통 양식에 맞춘 것이다.

한 번의 앱 실행이 하위 프로세스마다 Prefetch 를 남겨도 timeline 에는 한 행으로 합친다
(가장 이른 것을 대표로, 라벨 `prefetch_run=1/N`, 합쳐진 시각은 `Artifact_details ` 의 `병합=`
과 `result.json` 에 남는다). 서로 떨어진 실행은 각각 별개 행으로 둔다.

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

`role=unknown`(발화자·순서를 확인하지 못한 바이트 스캔 조각)은 CSV 에 싣지 않는다 —
팀 공통 양식은 발화자가 확인된 메시지만 담는다. 이 조각들은 `result.json` 에만 남는다.

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

## USN 저널(`$UsnJrnl:$J`)을 어떻게 쓰는가

파일 자체가 남지 않은 행위(지워진 첨부, 처음 실행, 설치·삭제)의 시각을 보조로 잡는다.
USN 레코드에는 경로가 없고 이름과 부모 참조(MFT#·순번)만 있어서, 아래 기준으로만 고른다.

| 고르는 기준 | 설명 |
| --- | --- |
| 부모가 Claude 탐색 폴더 | 이미지에서 훑은 Claude 폴더의 MFT 번호를 **순번까지** 맞춘다. MFT 엔트리가 재사용되면 순번이 달라져 다른 파일을 Claude 것으로 잡지 않는다. 저널 기간에 그 아래 새로 생긴 폴더(첨부 저장소 등)도 따라간다. 프리패치·WindowsApps 폴더 자체는 다른 프로그램 파일이 대부분이라 뺀다 |
| 이름만으로 Claude 것 | Claude 실행 파일 프리패치(`CLAUDE*.EXE-xxxxxxxx.pf`), WindowsApps 의 Claude 패키지 폴더, Packages 의 Claude 데이터 폴더 |

| USN 기록 | 판정 |
| --- | --- |
| Claude 실행 파일 프리패치 생성 | 애플리케이션 실행 **의심** |
| Claude 설치 프로그램 프리패치 생성 · WindowsApps Claude 패키지 폴더 생성 | 애플리케이션 설치 **의심** |
| WindowsApps Claude 패키지 폴더 삭제 | 관찰(NA-00) — 버전 업데이트도 옛 버전 폴더를 지우므로 앱 삭제로 단정하지 않음 |
| `Packages\Claude_pzs8sxrjxfjjc` 데이터 폴더 삭제 | 애플리케이션 삭제 **의심** |
| IndexedDB 첨부 저장소(`*.indexeddb.blob`) 파일 생성 / 삭제 | 관찰(NA-00), 후보 E05-01/E05-03 · E05-02/E05-04 — 이미지·문서 구분 불가 |
| 그 밖의 변경 | 폴더별 요약 관찰(NA-00) |

교차검증: USN 시각은 저널 기록 시각이라 행위 시각과 같다고 단정하지 않는다. 그래서 USN
행은 다른 저장소(앱 로그 등)에 의해 확정될 수는 있지만, 다른 행을 확정으로 올리는 근거로는
쓰지 않는다. 같은 프리패치 파일의 파일 시각과 USN 생성 기록은 같은 계보라 서로를 독립 근거로
세지 않는다.

## 설정 파일 `claude_desktop_config.json`

MCP 서버(외부 도구 연결)와 앱 기본 설정이 들어 있다. 팀 행위 분류표에 대응 행위가 없어
관찰(NA-00)로만 남긴다. MCP 서버는 이름과 실행 프로그램 이름만 남기고 인자·환경변수(토큰·경로)
값은 싣지 않는다. 계정 UUID 는 `preferences` 의 `...ByAccount` 키에서만 읽어 근거로 남기며,
로그인 행은 만들지 않는다 (같은 앱 상태의 식별자로 `config.json` 의 로그인과 중복되므로).

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

## 테스트

```
python -m unittest discover -s tests -v
```

| 파일 | 확인하는 것 |
| --- | --- |
| `tests/test_bitlocker.py` | 해제 방식별(복구 키·암호·BEK·clear key·복호화 완료) 열기, 키 없음·틀린 키·형식 오류의 잠김 처리, 키 값 비노출, 평문 이미지 결과 불변 |
| `tests/test_usn.py` | USN 선택 기준(순번 대조·새 하위 폴더·Codex 이름·다른 프로그램 프리패치 제외), 판정(실행·설치·삭제·첨부), 폴더 요약, USN 이 다른 실행을 확정으로 올리지 않음·같은 계보 제외 |
| `tests/test_desktop_config.py` | `claude_desktop_config.json` 수집, MCP 인자·토큰·경로 비노출, 로그인 중복 행 없음, 깨진 JSON |
| `tests/test_live.py` | 라이브 결과가 이미지 입력과 같은 행위·시각·판정인지, 원본 불변, 탐색 범위, 증거 안 출력 거부, 실행 중인 앱이 잡은 파일 읽기, 독점 잠금 파일 보고 |
| `tests/test_output_format.py` | 팀 공통 양식 — Behavior_details 는 짧은 라벨만(로그 원문 제외), 대화 CSV 는 발화자 확인된 것만(unknown 제외), 같은 실행의 Prefetch 를 한 행으로 병합(먼 실행은 분리) |
| `tests/test_mounted_devices.py` | SYSTEM\\MountedDevices 로 볼륨별 드라이브 문자 확인, GPT/MBR 볼륨키 대조, 하이브 없을 때 C: 폴백, `_winpath` 가 확인된 문자 우선 사용 |

BitLocker 시험은 처음 실행할 때 `dissect.fve` 저장소의 BitLocker 테스트 볼륨(고정
커밋, AGPL-3.0 데이터라 저장소에는 넣지 않음)을 `tests/_data/bde/` 로 내려받는다.
그 볼륨은 데이터 영역이 비어 있어서, `tests/_data/claude_ntfs.img.gz`(합성 Claude
아티팩트, `tests/make_ntfs_fixture.sh` 로 생성)를 그 볼륨의 키로 암호화해 채운 뒤
분석한다 (`tests/bde_fixture.py`). 오프라인이면 해당 시험만 건너뛴다.

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
| BitLocker | AES-XTS(Windows 10 이후 기본)는 빠른 복호화 경로를 쓰고, 그 외 방식은 `dissect.fve` 기본 경로라 느리다. 실제 BitLocker 시나리오 이미지(68.7GB, clear key)에서 Claude 아티팩트 152개 전부를 독립 구현(`dissect.fve` 기본 복호화 + `dissect.ntfs`)과 해시 대조해 일치를 확인했다 |
| 초기화 크기(VDL) | 미리 할당된 파일(캐시 `data_N` 등)은 초기화 크기 뒤를 NTFS 규칙대로 0 으로 읽는다. 그 뒤에 디스크에 남은 옛 바이트(잔존 데이터)는 파일 내용으로 보지 않으며 현재 분석하지 않는다 |
| 라이브 분석 재현성 | 실행 중인 시스템을 읽으므로 같은 결과를 다시 만들 수 없고, 읽는 동안 앱이 파일을 바꿀 수 있다. 증거 보존이 필요하면 이미지를 뜬다 |
| 라이브 분석 범위 | 삭제 파일과 `$UsnJrnl:$J` 는 다루지 않는다 (볼륨을 원시로 열지 않는다). MFT 변경 시각은 얻을 수 없어 비워 둔다. 마지막 접근 시각은 운영체제 설정에 따라 갱신될 수 있다 |
| USN 저널 범위 | 저널은 크기 제한으로 오래된 기록부터 지워진다. 저널 기간 전에 지워진 Claude 폴더 아래 기록은 부모를 알 수 없어 고르지 못한다. 첨부 저장소 기록으로 업로드 시각은 알 수 있지만 파일 종류·내용은 알 수 없다 |

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
