# LM Studio Forensic Parser

Windows LM Studio 아티팩트에서 사용자 행위와 대화 원문을 복구하는 통합 파서의 LM Studio 모듈입니다. 알려진 JSON 구조의 기준은 LM Studio 0.4.21 Build 2입니다.

## 통합 실행

환경 설정, 실행 명령, 병합 결과 및 오류 확인은 [통합 실행기 README](../integration/README.md)를 따릅니다. [파서 레지스트리](../integration/parsers.json)의 등록명은 `lmstudio`이며, 통합기는 Python 3.14 환경(`.venv314`)에서 `lmstudio_parser.py <image> --output <out>`을 호출합니다. 파서의 진단 출력은 통합 결과의 `lmstudio/run.log`에 기록됩니다.

이미지 입력은 DD/RAW/IMG, EWF(`.e01`, `.ex01`, `.s01`, `.l01`), 분할 RAW/DD(`.001`)를 지원합니다. 분할 이미지는 첫 segment를 지정해야 하며, 분할 RAW/DD의 중간 segment 입력이나 결번은 거부합니다. 이미지와 NTFS/SQLite 근거는 읽기 전용으로 처리합니다.

## 주요 근거와 판정

| 영역 | 주요 아티팩트와 해석 |
|---|---|
| 대화 | `*.conversation.json`, `conversation-config.json`, 연결된 로그·NTFS history. 생성에는 config 연결과 생성 근거가 필요하며, 수정은 명시적 edited marker를 사용합니다. 재시도는 assistant versions 구조를 확인합니다. |
| 계정 | `local-identity.json`, `user-profile.json`, `lmstudio-hub.json`, 계정 상태 cache. 현재 로그인 상태와 실제 로그인/로그아웃 행위를 구분합니다. 단순 modify history나 재인증 문구로 계정 전환을 확정하지 않습니다. |
| 첨부 | `user-files/*.metadata.json`, 실제 conversation attachment link와 생성·삭제 history. 이미지와 문서 타입을 구분하며 업로드 시각은 원본 NTFS creation 또는 정확히 연결된 단일 생성 history에서 얻습니다. |
| 모델·다운로드 | `model-data.json`, `download-jobs-info.json`, `single-downloads-info.json`, GGUF와 관련 history/ADS. URL이나 부분 다운로드 파일만으로 완료를 확정하지 않습니다. 완료 시각이 없으면 실제 시작 시각을 사용하고 시작 시각 출처를 표시합니다. |
| 실행·종료·설치·삭제 | 프로그램 파일·shortcut·Prefetch·runtime state·명시적 로그와 history. 설치 폴더 존재, lock 잔존물, 정상 종료 근거의 부재만으로 행위를 확정하지 않습니다. |
| Export | 알려진 LM Studio Markdown signature와 독립 생성 history. 일반 Markdown/JSON 파일을 Export로 판단하지 않습니다. |

21개 Rule은 명시적 직접증거 또는 서로 다른 Evidence Family와 실제 Source Lineage의 교차 근거로 판정합니다. 같은 JSON field나 같은 레코드를 여러 Fact로 나누어 독립증거를 늘리지 않습니다. `확정`/`의심`만 timeline에 출력하며, `미확정` 후보는 내부 Context와 진단 로그에 남습니다. 실험 폴더명, MRK 문자열, 정답 label, 파일명의 숫자로 행위나 시각을 생성하지 않습니다.

대화·첨부 삭제에는 실제 삭제/rename 또는 연결된 제거 근거가 필요합니다. Assistant-only 상태나 현재 파일 부재만으로 삭제를 판단하지 않습니다. 동일 대상의 명시적 이전 snapshot을 사용하는 `--before` 분석은 별도 개발용 옵션이며, 통합기의 기본 호출에는 포함되지 않습니다.

## 출력 해석

공통 CSV 계약은 [통합 실행기 README](../integration/README.md)를 참조합니다. 이 모듈은 `Model=lmstudio`로 `timeline.csv`(7열)와 `recovered_conversations.csv`(10열)를 출력합니다. 원본 timeline의 `Behavior_details `와 `Artifact_details ` 헤더 끝 공백은 정확히 한 개입니다.

`Behavior_details`는 발견 근거와 핵심 대상을 표시하며, Prompt/수정 메시지는 첫 줄만 표시합니다. `Artifact_path`는 정렬된 원본 근거 경로이고, `Artifact_details`는 `[아티팩트명] 설명`을 ` | `로 연결합니다. 위치에는 JSON pointer, log line, USN offset, MFT locator 등을 사용합니다.

반복된 `[$UsnJrnl]` history 근거는 알려진 이벤트와 대상 경로가 있을 때, 같은 Candidate의 **Fact type(이벤트), 전체 대상 경로, source image, 원본 Artifact 경로**별로 표시를 묶습니다. 두 개 이상이면 대표 위치와 원래 Fact 수를 표시하고, 단일 근거는 기존 형식을 유지합니다. 대표 위치는 기존 설명 문자열의 사전식 정렬상 첫 번째 위치이며, offset의 숫자 최솟값을 의미하지 않습니다.

```text
[$UsnJrnl] 대상=A.conversation.json, 이벤트=수정, 위치=offset 0x100, 동일 근거=663건
```

그룹화는 `Artifact_details` 직렬화에만 적용합니다. `candidate.facts`의 모든 근거·locator와 판정은 유지하며, 다른 대상·이벤트·Fact type·source는 합치지 않습니다. Conversation, $MFT, Download Record, Model Data 등에는 이 그룹화를 적용하지 않습니다. 문자열 강제 절삭이나 표시 내부 줄바꿈을 추가하지 않으며, 그 외 근거는 동일한 설명 문자열만 제거합니다.

복구 CSV는 모든 retry version, 실제 role과 원문을 보존하고 원본 배열 순서대로 `message order`를 부여합니다. `conversation_uuid`는 명시적 식별자를 우선하고 없으면 실제 대화 파일 basename을 사용하며, 표시값의 `.conversation.json` suffix를 제거합니다. `message_uuid`/`parent_message_uuid`는 실제 식별자만 사용합니다. 메시지 시각은 해당 메시지/버전에 연결된 검증된 값만 쓰고, 불명확하면 `-`를 출력합니다.

Credential/token/private key와 preview Base64는 비대화 출력·로그에 노출하지 않습니다. 실제 Prompt/Response 원문은 복구 CSV에 보존하며, CSV 직렬화 시 formula injection 방어를 적용합니다.

## 분석 한계

- 단일 snapshot으로 과거 계정 전환·삭제·종료를 모두 복구할 수 없습니다.
- USN wrap/누락, 손상 레코드, non-resident 본문 부재는 과거 근거와 삭제 복구를 제한합니다. 삭제 resident JSON은 실제 연결된 대화·첨부만 선택 복구합니다.
- edited/retry history에 여러 시각이 있으면 임의로 하나를 선택하지 않습니다. timezone이 불명확한 시각은 UTC로 가정하지 않습니다.
- Direct log 판정은 scoped `.lmstudio/server-logs/*.log`의 제한된 명시적 성공/종료 문법만 지원하며, 버전별 모든 로그 형식을 보증하지 않습니다.
- Prefetch 바이너리의 모든 run timestamp는 해석하지 않습니다. 실행 행위에는 기존 runtime/log 시각과 제한적 filesystem mtime fallback을 사용합니다.
- BitLocker, 손상 filesystem, 지원하지 않는 disk layout/EWF variant 등은 분석을 제한할 수 있습니다.

## 개발 검증

`lmstudio_parser.py`에 179개 self-test가 내장되어 있습니다. USN 663개 synthetic Fact의 표시 압축·원본 보존, 21개 Rule의 양성/음성 결과, CSV 계약 및 결정적 출력을 검증합니다. 실제 64GB 이미지는 self-test에 포함하지 않습니다.

저장소 루트에서 통합 환경으로 실행합니다.

```powershell
integration\.venv314\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py --self-test
```

별도 이미지 회귀 검증에는 파서의 `--validate`를 사용할 수 있습니다. 이 옵션은 같은 Evidence를 재분석해 두 CSV의 byte equality와 이미지 size/mtime 불변을 검사하며, 통합기의 기본 호출에는 포함되지 않습니다.
