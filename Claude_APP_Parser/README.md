# AIFP — Claude Desktop 포렌식 파서

디스크 이미지에서 Claude Desktop 사용 흔적을 읽어 **사용자 행위 타임라인**을 만든다.
살아 있는 시스템을 분석하지 않고, 이미지를 마운트하지도 않는다.

![Python](https://img.shields.io/badge/python-3.11%2B-3776AB?logo=python&logoColor=white)
![Platform](https://img.shields.io/badge/target-Windows%20NTFS-0078D6?logo=windows&logoColor=white)
![Image formats](https://img.shields.io/badge/image-dd%20%7C%20E01-555)
![Dependencies](https://img.shields.io/badge/core-stdlib%20only-success)

```bash
python aifp_parse.py --image D:\case\disk.dd --out D:\case\result
```

---

## 목차

- [무엇을 하는 도구인가](#무엇을-하는-도구인가)
- [설치](#설치)
- [사용법](#사용법)
- [어디에서 무엇을 읽나](#어디에서-무엇을-읽나)
- [무엇이 나오나](#무엇이-나오나)
- [판정 규칙](#판정-규칙)
- [설계 노트](#설계-노트)
- [프로젝트 구조](#프로젝트-구조)
- [확장하기](#확장하기)
- [파이썬에서 직접 쓰기](#파이썬에서-직접-쓰기)

---

## 무엇을 하는 도구인가

획득이 끝난 디스크 이미지를 입력으로 받아, 그 안에서 Claude Desktop의 흔적을 찾아
"언제 무엇을 했는가"를 근거와 함께 복원한다.

| | |
| --- | --- |
| **입력** | `.dd` (RAW 디스크 이미지) · `.E01` (EnCase Evidence File) |
| **출력** | `timeline.csv` · `recovered_conversations.csv` 두 파일 |
| **접근 방식** | 읽기 전용 · 마운트 없음 · 관리자 권한 불필요 · 분석 전후 해시 비교 |
| **대상 탐지** | 사용자 계정마다, 설치 형태(스토어/일반)마다, NTFS 볼륨을 훑어 스스로 찾는다 |

라이브 시스템을 분석하면 파일을 여는 순간 접근 시각이 갱신되고, 앱이 실행 중이면
캐시 인덱스와 lockfile이 잠겨 읽히지 않는다. 그래서 입력은 이미지다.

---

## 설치

파이썬 3.11 이상이면 코어는 표준 라이브러리만으로 동작한다.

```bash
git clone <repo-url>
cd aifp-parser
python aifp_parse.py --version
```

아래 패키지는 선택이다. 없어도 파서는 돌아가며, 빠진 기능은 결과에 사유와 함께 기록된다.

| 패키지 | 없을 때 | 설치 |
| --- | --- | --- |
| `zstandard` | 대화 본문(zstd) 해제 불가 | `pip install zstandard` |
| `ccl_chromium_reader` | 캐시 인덱스·IndexedDB 구조 파싱 생략 | `pip install git+https://github.com/cclgroupltd/ccl_chromium_reader.git` |
| `pyewf` | E01만 읽지 못함 | 환경별 libewf 바인딩 |

> `ccl_chromium_reader`는 PyPI에 없다. 위 주소로 설치해야 한다.

---

## 사용법

```bash
# 기본
python aifp_parse.py --image D:\case\disk.dd --out result

# E01
python aifp_parse.py --image D:\case\disk.E01 --out result

# 파일 삭제·이동·이름 변경과 휴지통 경로까지 추적
python aifp_parse.py --image D:\case\disk.dd --out result --extended-fs

# 볼륨을 직접 지정
python aifp_parse.py --image D:\case\disk.dd --volume 2 --out result
```

입력은 `.dd` 와 `.E01` 두 가지뿐이다. 다른 확장자는 인자를 받는 자리에서 거절하므로
분석이 시작되지도 않는다.

| 옵션 | 설명 |
| --- | --- |
| `--image` | 증거 이미지 (`.dd` 또는 `.E01`) — 필수 |
| `--out` | 결과 폴더 |
| `--rules` | 판별 규칙 파일 (기본 `rules/claude_desktop.json`) |
| `--volume N` | 분석할 파티션 번호. 미지정 시 대상 흔적이 있는 NTFS 볼륨을 자동 선택 |
| `--extended-fs` | `$UsnJrnl:$J` 와 `$Recycle.Bin` 을 추가로 분석 |
| `--resume` | 중단된 분석을 체크포인트부터 이어서 실행 |
| `--keep-work` | 작업 사본 보존. 기본은 덮어쓰고 삭제 |
| `--verbose` | 단계별 진행 출력 |

시각은 항상 KST로 적는다. 대화 본문은 마스킹하지 않는다.

종료 코드 — `0` 정상 / `1` 오류 발생 / `2` 입력 문제로 중단 / `130` 사용자 중단

분석한 이미지로 전체 검증을 돌릴 수도 있다. 결과 수치를 대조하는 것이 아니라
무결성 검증 통과, 모든 이벤트에 근거, 시각에 출처, 작업 사본 삭제, 재현성, 재개처럼
어떤 이미지에서도 참이어야 하는 성질을 확인한다.

```bash
python tests/verify_all.py D:\case\disk.dd
```

---

## 어디에서 무엇을 읽나

| 저장소 | 읽는 것 |
| --- | --- |
| HTTP 캐시 | 대화 본문이 실제로 남는 곳. 키는 `chat_conversations/<uuid>`, 본문은 zstd |
| IndexedDB | 대화·첨부·입력 초안 흔적. UTF-8과 UTF-16LE를 동시에 훑는다 |
| Local Storage | LevelDB 원시 스캔. 삭제 표시(tombstone)와 압축 전 `.log` 잔존분까지 |
| Blob | IndexedDB blob 실물 — 계정 프로필 |
| 설정 파일 | 계정·조직 UUID, 종료 직전 재작성 시각, 약 5분 간격 사용 기록 |
| 앱 로그 | 로그인·로그아웃·계정 전환·종료·모델·계정/조직 UUID. 패키지 밖에 있어 앱을 지워도 남는다 |
| 파일 메타 | lockfile·캐시 파일의 NTFS 4시각, 앱 삭제 여부 판정, Prefetch 실행 시각 |
| 변경 저널 | 파일 생성·변경·삭제·이름 변경. 부모 참조로 경로를 되살려 제품까지 가른다 |
| 휴지통 | 원래 경로와 삭제 시각 |

시각은 FILETIME·WebKit·Unix 초/밀리초를 자동 판별한다. 저장값은 항상 UTC이고 표시만 바꾼다.

앱 로그는 시간대 표시 없이 그 PC의 현지시각으로 적힌다. 파일 수정시각(UTC)과 마지막
줄을 견줘 오프셋을 추정해 환산하며, 추정했다는 사실은 실행 기록에 남긴다.

이름에 claude 가 들어갔다고 전부 이 앱의 흔적은 아니다. 변경 저널 기록은 경로를 보고
Claude Desktop · Claude Web · Claude Code(CLI) · 다른 앱으로 가른다. 다른 앱 것은 표에서
빼고 몇 건을 뺐는지 기록에 남긴다.

---

## 무엇이 나오나

`--out` 폴더에 **두 파일만** 만든다. 둘 다 UTF-8 BOM이라 엑셀에서 바로 열린다.

### timeline.csv

흔적이 확인된 사용자 행위를 시간순으로. 미검출 행위는 싣지 않는다.

| 열 | 내용 |
| --- | --- |
| `service` | 분석 대상 서비스 (`claude-desktop`) |
| `timestamp` | 행위를 대표하는 시각 (KST). 근거 있는 시각이 없으면 **비워 둔다** |
| `user_action` | 사전에 정의된 행위명 |
| `action_detail` | 증거 상태와 핵심 내용 |
| `verdict` | `확정` — 독립 아티팩트 2계열 교차검증 또는 직접 증거<br>`의심` — 흔적은 있으나 확정 기준 미달 |
| `account_uuid` | 확정할 수 있을 때만 |
| `conversation_uuid` | 특정 대화와 연결될 때만 |

### recovered_conversations.csv

복원한 대화를 **메시지 단위**로.

| 열 | 내용 |
| --- | --- |
| `service` | `claude-desktop` |
| `timestamp` | 메시지 생성 시각 (KST) |
| `conversation_uuid` / `conversation_title` | 대화 식별자와 제목 |
| `message_uuid` / `parent_message_uuid` | 메시지 식별자와 부모 — 수정·재시도 분기를 보존한다 |
| `message_order` | 부모·자식 관계로 재구성한 순서. 대화마다 1부터 |
| `role` | `user` / `assistant` / `system` / `unknown` (`human`은 `user`로 변환) |
| `content` | 본문 전체. 마스킹하지 않고 한 셀에 넣는다 |
| `recovery_status` | `완전 복구` — UUID·역할·내용이 모두 있고 잘림 없음<br>`부분 복구` — 일부가 없거나 잘림 |

---

## 판정 규칙

로그인, 대화 생성·열람·삭제, 프롬프트 입력과 전송, 모델 응답, 파일 업로드,
앱 실행과 정상 종료, 애플리케이션 삭제, 모델 변경, 임시 채팅, 캐시 삭제 등
17가지를 직접 증거와 보조 증거로 나누어 판정한다.

규칙은 코드가 아니라 `rules/claude_desktop.json`에 있다. 앱이 업데이트되어 경로나 키가
바뀌면 이 파일만 고치면 된다. 어떤 규칙으로 판정했는지는 `--log` 로 남기는 실행 기록에 규칙 버전으로 적힌다.

```json
{
  "id": "E02-02",
  "name": "애플리케이션 삭제",
  "category": "install",
  "evidence_level": "direct",
  "require": [{ "kind": "app_removed", "source": "fsmeta" }],
  "per_record": true,
  "time_from": "context",
  "explain": "왜 이것이 그 행위의 근거인지 적는다 — 보고서에 그대로 인용된다"
}
```

대상 경로도 규칙 파일이 선언한다. 설치 형태가 여럿이면 후보를 나열하면 된다.

```json
"app_root": {
  "relative": "AppData/Local/Packages/Claude_pzs8sxrjxfjjc/LocalCache/Roaming/Claude",
  "alternatives": ["AppData/Roaming/Claude"],
  "marker_files": ["config.json"],
  "marker_dirs": ["IndexedDB"]
}
```

---

## 설계 노트

### 1. 이중 인코딩 검색은 선택이 아니다

`chat-draft` 같은 키는 IndexedDB 안에 UTF-16LE로만 존재하고 UTF-8로는 한 번도
나타나지 않는 경우가 있다. UTF-8로만 찾으면 입력 초안이 통째로 안 보인다.
그래서 모든 검색을 두 인코딩으로 동시에 한다.

### 2. 파일 시각을 그대로 믿으면 안 된다

Chromium은 종료할 때 밀린 쓰기를 한꺼번에 flush한다. 캐시 파일의 수정 시각이
전부 "앱을 끈 시각"으로 수렴한다. 파서는 이 수렴을 감지해 신뢰도를 낮추고 경고를 붙인다.

| 시각 출처 | 신뢰도 |
| --- | --- |
| 앱 로그 · API 응답 · `$UsnJrnl` | 높음 |
| 설정 파일 · 파일명에 박힌 시각 | 중간 |
| `$MFT` 타임스탬프 | 낮음 |

### 3. "흔적 없음"과 "못 읽음"은 다르다

| 결과 | 의미 |
| --- | --- |
| `not_detected` | 찾아봤는데 없었다 — 확인한 경로를 함께 기록 |
| `not_applicable` | 기능 자체가 없다 (데스크톱 앱에는 시크릿 모드가 없다) |
| `deleted_recovered` | 삭제 엔트리에서 본문까지 복원 |
| `deleted_metadata_only` | 클러스터가 재할당되어 이름·시각만 남음 |

### 4. 확신도는 독립 채널 수로 매긴다

```text
직접 증거 60점 / 보조 증거 35점에서 출발
  + 서로 다른 저장소에서 같은 행위가 확인될 때마다 +15
  − 시각 신뢰도가 낮으면 −10
```

같은 저장소에서 근거가 여러 개 나오는 것은 교차 검증이 아니다. 채널 수는 늘지 않는다.
독립 채널의 기준은 `Storage` 열거형(`cache` `indexeddb` `localstorage` `blob`
`configfile` `applog` `filesystem` `registry`)이다.

### 5. 앱을 지워도 파일시스템은 기억한다

`--extended-fs` 를 켜면 `$UsnJrnl:$J` 에서 Claude 관련 파일의 생성·삭제·이름 변경을,
`$Recycle.Bin` 의 `$I` 파일에서 삭제된 파일의 **원래 전체 경로와 삭제 시각**을 읽는다.
같은 파일에 수십 건씩 쌓이는 기록은 파일 단위로 묶어 처음·마지막 시각과 횟수만 남긴다.

### 6. 이미지가 온전하지 않을 수 있다

파티션 표가 말하는 디스크 크기보다 파일이 작으면 잘린 이미지로 보고 누락량을 알린다.
볼륨 하나가 BitLocker나 손상으로 열리지 않아도 나머지 볼륨은 계속 본다.
불량 섹터는 0으로 채우고 진행하되, 그 사실을 `issues.csv`에 남긴다.

---

## 프로젝트 구조

```text
aifp-parser/
├── aifp_parse.py              CLI 진입점
├── rules/
│   └── claude_desktop.json    판별 규칙 — 코드가 아니라 여기를 고친다
├── aifp/
│   ├── pipeline.py            오케스트레이션 (증거 → 수집 → 판정 → 출력)
│   ├── evidence/
│   │   ├── container.py       RAW/dd · E01 → read(off, n)
│   │   ├── vfs.py             NTFS를 마운트 없이 pathlib처럼 읽는 읽기 전용 VFS
│   │   ├── _ntfs.py           $MFT 파서
│   │   └── _vmdk.py           VMDK sparse 체인 리더
│   ├── sources/               저장소별 리더 + 네임스페이스 레지스트리
│   │   ├── cache_store.py     HTTP 캐시 (대화 본문)
│   │   ├── leveldb_store.py   IndexedDB · Local Storage · blob
│   │   ├── config_store.py    설정·상태 파일
│   │   ├── fsmeta_store.py    앱 로그 · 파일 메타
│   │   └── fsextra_store.py   $UsnJrnl:$J · $Recycle.Bin (--extended-fs)
│   ├── actions.py             규칙 평가 + 교차 검증
│   ├── schema.py              통합 이벤트 스키마 + 확신도
│   ├── provenance.py          근거(ArtifactRef) + 수집 매니페스트
│   ├── timeutil.py            시각 변환 + 출처/신뢰도 + flush 수렴 감지
│   ├── masking.py             민감정보 가림
│   ├── errors.py              예외 계층 + ErrorCollector
│   ├── checkpoint.py          재개 — 중단 지점부터 이어서
│   ├── report.py              집계 + 타임라인 구성
│   ├── csvout.py              출력 — timeline.csv · recovered_conversations.csv
│   └── banner.py              CLI 배너
└── tests/
    ├── verify_all.py          전체 검증 (분석할 이미지를 인자로 준다)
    └── compare_runs.py        두 실행 결과 비교
```

---

## 확장하기

다른 AI 서비스를 붙일 때 **코어는 건드리지 않는다.** 규칙 파일이 대상 경로와 쓸 리더를
모두 선언하고, 리더만 새로 쓴다.

```json
{
  "service_key": "chatgpt-desktop",
  "target": {
    "service": "ChatGPT",
    "client": "desktop",
    "app_root": {
      "relative": "AppData/Local/Packages/OpenAI.../LocalCache/Roaming",
      "marker_files": ["auth.json"],
      "marker_dirs": ["sessions"]
    },
    "sources": ["jsonl", "sqlite", "config", "fsmeta"]
  },
  "rules": []
}
```

리더는 `locate()`와 `read()` 둘만 구현하면 된다.

```python
from aifp.provenance import ArtifactRef, Storage
from aifp.sources.base import Record, Source


class SessionSource(Source):
    name = "jsonl"
    display = "세션 기록"

    def locate(self) -> list:
        d = self.root / "sessions"
        return sorted(d.glob("*.jsonl")) if d.is_dir() else []

    def read(self) -> list[Record]:
        out = []
        for f in self.locate():
            data = self.safe_bytes(f)          # 실패해도 예외를 던지지 않는다
            if data is None:
                continue
            out.append(Record(
                source=self.name, kind="conversation", key=f.stem,
                value={"uuid": f.stem},
                ref=ArtifactRef(path=str(f), storage=Storage.FILESYSTEM.value),
            ))
        return out
```

등록은 한 줄이다. 리더는 `<service_key>.<name>`으로 등록되므로 서비스마다
`cache`·`config` 같은 같은 이름을 써도 충돌하지 않는다.

```python
# aifp/sources/__init__.py 의 _bootstrap()
register("chatgpt-desktop", SessionSource)
```

```bash
python aifp_parse.py --image D:\case\disk.dd --rules rules/chatgpt_desktop.json --out result
```

그대로 재사용되는 계층 — `evidence/` · `errors` · `timeutil` · `provenance` ·
`masking` · `schema` · `actions` · `report` · `checkpoint` (전부 서비스 무관)

---

## 파이썬에서 직접 쓰기

CLI를 거치지 않고 파이프라인을 직접 부를 수 있다.

```python
from pathlib import Path
from aifp.pipeline import Pipeline

from aifp.csvout import (rows_from_reporter, write_conversations,
                          write_timeline)

reporter = Pipeline(
    Path(r"D:\case\disk.dd"),
    Path("rules/claude_desktop.json"),
    out_dir=Path("result"),
    tz="KST",
    unmask=True,
    extended_fs=True,          # $UsnJrnl:$J · $Recycle.Bin 까지
).run()

timeline, conversations = rows_from_reporter(reporter)
write_timeline(timeline, Path("result/timeline.csv"))
write_conversations(conversations, Path("result/recovered_conversations.csv"))
print(len(timeline), len(conversations))
```

자세한 실행 절차와 확인 항목은 [TESTING.md](TESTING.md)에 있다.
