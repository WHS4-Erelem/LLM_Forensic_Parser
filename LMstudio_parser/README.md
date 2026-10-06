# LM Studio Forensic Parser

Windows LM Studio 아티팩트에서 사용자 행위와 대화 원문을 복구하는 통합 파서의 LM Studio 모듈입니다. 알려진 JSON 구조의 기준은 LM Studio 0.4.21 Build 2입니다.

## 통합 실행

통합 실행 명령, 병합 결과 및 오류 확인은 [통합 실행기 README](../integration/README.md)를 따릅니다. [파서 레지스트리](../integration/parsers.json)의 등록명은 `lmstudio`이며, `lmstudio_parser.py <image> --output <out>` 호출을 유지합니다. 파서의 진단 출력은 통합 결과의 `lmstudio/run.log`에 기록됩니다. 이 모듈의 개발·회귀 검증 기준은 저장소 루트의 Python 3.12 `.venv312`입니다.

이미지 입력은 DD/RAW/IMG, EWF(`.e01`, `.ex01`, `.s01`, `.l01`), 분할 RAW/DD(`.001`)를 지원합니다. 분할 이미지는 첫 segment를 지정해야 하며, 분할 RAW/DD의 중간 segment 입력이나 결번은 거부합니다. 이미지와 NTFS/SQLite 근거는 읽기 전용으로 처리합니다.

## Supported Inputs와 Python 환경

- DD/RAW/IMG: disk image의 partition들을 조사하며, partition table이 없으면 volume image로 시도합니다.
- Split RAW/DD: 연속된 `.001`, `.002`, …를 `SegmentedRawStream`으로 읽습니다. 전체 DD로 합치지 않습니다.
- EWF: container를 연 후 내부 raw stream의 partition을 조사합니다.
- Directory: `.lmstudio`, 사용자 profile, `Users`를 포함한 Windows root, 집중 추출 artifact directory를 지원합니다. 단일 artifact 파일 입력도 유지합니다.
- Windows Live: 현재 PC의 로컬 profile과 LM Studio Home을 직접 읽습니다.

이미지 filesystem 접근은 `dissect.volume.disk.Disk`와 `dissect.ntfs.NTFS`를 사용합니다. 현재 모듈에는 pytsk3 분석 경로가 없으며, pytsk3 설치나 adapter는 필요하지 않습니다. LM Studio 범위의 dependency는 다음과 같이 설치할 수 있습니다. 공통 Runner/dependency 파일은 변경하지 않습니다.

```powershell
uv pip install --python .\.venv312\Scripts\python.exe dissect.ntfs dissect.volume dissect.evidence "dissect.fve==4.6"
```

## Windows Live Mode

```powershell
.\.venv312\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py --live --output C:\ForensicOutput\lmstudio_live
```

`SystemDrive\Users`와 `USERPROFILE`을 동적으로 확인하고 `Default`, `Default User`, `Public`, `All Users`를 제외합니다. `--live-root <WindowsRoot>`로 `Users`를 포함한 다른 로컬 Windows root를 지정할 수도 있습니다. Windows 이외 OS에서는 `--live`를 거부합니다. 사용자명은 하드코딩하지 않습니다.

Live와 Directory는 공통 profile/Home 탐색기를 사용합니다. `%USERPROFILE%\.lmstudio`와 UTF-8 plain path인 `.lmstudio-home-pointer`의 대상 Home을 함께 확인하고, 중복 root는 한 번만 수집합니다. 상대 pointer는 해당 profile 기준으로 해석합니다. UNC/network pointer는 거부합니다. Offline Directory의 pointer는 지정한 evidence directory 밖으로 따라가지 않습니다. NTFS image의 기존 Home 탐색은 `Users\<profile>\.lmstudio` 경로를 유지합니다.

Home의 conversations/models/hub/server-logs/`.internal`/retrieval/cache 등 파일은 기존 artifact core로 전달합니다. 재배치 Home의 server log도 동일한 로그 문법으로 분석합니다. profile의 프로그램, updater, Start Menu, Recent/LNK, Desktop/Downloads/Documents와 Windows Prefetch도 기존 범위에서 탐색합니다. 파일이 수집되었다고 모든 cache 형식의 본문을 해석한다는 의미는 아닙니다.

내용은 `rb`로 제한된 크기만 읽으며, 변경·삭제·잠금·권한 오류는 `live_artifact_changed`, `live_artifact_not_found`, `live_artifact_locked`, `live_permission_denied` 등으로 보고하고 다른 파일을 계속 분석합니다. 읽기 전후 size/mtime/ctime이 바뀐 파일의 본문은 사용하지 않습니다. directory reparse point/junction과 file link는 Live 순회에서 제외합니다. 프로세스 종료, lock 해제, cache 삭제, registry/config/volume 수정은 수행하지 않습니다.

출력은 지정한 directory에만 작성하며 수집 대상 Home/문서/프로그램/Prefetch와 겹치는 output은 거부합니다. 예를 들어 수집 대상 Desktop 아래에 output을 지정하면 거부될 수 있습니다. Live는 snapshot이 아니므로 파일 사이의 시점 일관성이나 완전한 변경 탐지를 보장하지 않습니다. `--before`, `--validate`, positional image input, BitLocker credential 옵션은 Live와 함께 사용할 수 없습니다. raw `$MFT`, `$UsnJrnl`, 삭제 파일 복구나 offline filesystem history는 생성하지 않습니다. 현재 권한으로 읽을 수 없는 profile/Prefetch/locked 파일은 분석 범위에서 제한됩니다.

## BitLocker-encrypted forensic image

E01 자체를 복호화하지 않습니다. DD/RAW/IMG, EWF에서 얻은 raw disk stream 또는 Split RAW stream의 **각 내부 volume**을 공식 `dissect.fve.bde.is_bde_volume()`으로 판별하고, `BDE`로 해제한 `BitlockerStream`을 기존 `dissect.ntfs.NTFS`에 직접 연결합니다. `-FVE-FS-` 문자열만으로 판별하지 않습니다. backend가 없을 때 이 OEM 값은 설치가 필요한 보조 indicator로만 보고합니다. 전체 decrypted DD를 생성하거나 volume을 mount하지 않습니다.

Python 3.12에 새로 설치한 `dissect.fve 4.6`에서 다음 실제 API를 확인했습니다. [Dissect BDE 공식 API](https://docs.dissect.tools/en/latest/api/dissect/fve/bde/bde/).

| Authorized material | CLI | Backend API |
|---|---|---|
| 실제 clear-key protector | 별도 옵션 없음 | `has_clear_key()` → `unlock_with_clear_key()` |
| Recovery Password | `--bitlocker-recovery-prompt` | `unlock_with_recovery_password(str)` |
| User Passphrase | `--bitlocker-passphrase-prompt` | `unlock_with_passphrase(str)` |
| BEK file | `--bitlocker-bek <file>` | `unlock_with_bek(BinaryIO)`; 파일은 `rb`로 읽음 |
| Raw binary FVEK | `--bitlocker-fvek <file>` | `unlock_with_fvek(bytes)`; 16/32/64-byte raw key |

```powershell
.\.venv312\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py evidence.E01 --bitlocker-recovery-prompt --output C:\ForensicOutput\lmstudio
.\.venv312\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py evidence.dd --bitlocker-passphrase-prompt --output C:\ForensicOutput\lmstudio
.\.venv312\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py evidence.001 --bitlocker-bek C:\AuthorizedKeys\volume.bek --output C:\ForensicOutput\lmstudio
.\.venv312\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py evidence.raw --bitlocker-fvek C:\AuthorizedKeys\volume.fvek --output C:\ForensicOutput\lmstudio --validate
```

Credential 옵션은 상호 배타적이며 forensic image 입력에서만 사용합니다. Recovery/passphrase는 `getpass`로 입력하고, echo 없는 입력이 불가능하면 안전하게 중단합니다. 비밀값을 command argument로 받는 옵션이나 `recovery:` 같은 custom prefix syntax는 없습니다. Clear key는 protector가 실제 존재할 때만 시도하며, suspended volume이 항상 key 없이 열린다고 가정하지 않습니다.

키가 없으면 `bitlocker_credential_missing`, 해제 실패는 `bitlocker_unlock_failed`, encryption metadata 손상은 `bitlocker_metadata_failed`, 해제 후 읽기 실패는 `bitlocker_stream_error`로 해당 partition을 건너뜁니다. 다른 partition 분석은 계속합니다. 모든 volume에서 지원 NTFS를 열지 못하면 최종 `ntfs_not_found` fatal로 종료하고 앞선 partition 진단을 함께 표시합니다. 성공 상태도 evidence diagnostic에만 기록하며 LM Studio 행위 Candidate/timeline은 생성하지 않습니다.

Raw FVEK는 API 호출 성공만으로 인증되지 않으므로 복호화된 NTFS boot header도 확인합니다. 잘못된 FVEK와 손상된 header/비지원 filesystem을 완전히 구분할 수는 없습니다. hex text, Dislocker/libbde key container, VMK/TPM secret, cracking/guessing/bypass는 지원하지 않습니다. 이 기능은 사용자 제공 authorized credential 또는 volume 내부 clear-key protector만 사용합니다.

원본과 segment는 읽기 전용으로 열고, 기존 `$MFT`/`$UsnJrnl`·대화·모델·다운로드·삭제 분석을 그대로 사용합니다. credential은 access 함수에만 전달하며 Context, CSV, validation JSON, SQLite, 진단·backend 로그, exception message에 저장하지 않습니다. 재분석 `--validate`에도 같은 credential을 메모리로 전달합니다. Python 문자열/bytes의 완전한 memory wipe는 보장하지 않습니다.

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
- 해제할 수 없는 BitLocker protector, 손상 filesystem, 지원하지 않는 disk layout/EWF variant 등은 분석을 제한할 수 있습니다. Drive-letter 기반으로 재배치된 image Home의 자동 매핑은 지원하지 않습니다.

## 개발 검증

총 225개 self-test(기존 179개, Windows Live 18개, BitLocker 28개)가 있습니다. 기존 테스트와 기대값을 유지했습니다. USN 663개 synthetic Fact의 표시 압축·원본 보존, 21개 Rule의 양성/음성 결과, CSV 계약 및 결정적 출력을 검증합니다. 신규 테스트는 synthetic profile, access error, 변경된 파일, credential API mock, 실제 공식 GUID 판별, 실제 BitlockerStream의 합성 sector 복호화와 read-only 동작, DD/EWF/Split RAW stream 연결 및 partition 실패 격리를 확인합니다. 실제 BitLocker Windows VM DD/E01의 전체 NTFS→LM Studio end-to-end fixture는 포함하지 않습니다.

저장소 루트에서 Python 3.12 환경으로 실행합니다. 보호된 함수의 AST hash 테스트는 Python 3.12에서 기존 기대값과 일치하며, 기대값을 변경하지 않았습니다.

```powershell
.\.venv312\Scripts\python.exe -m py_compile LMstudio_parser\lmstudio_parser.py
.\.venv312\Scripts\python.exe -B LMstudio_parser\lmstudio_parser.py --self-test
```

별도 이미지 회귀 검증에는 파서의 `--validate`를 사용할 수 있습니다. 이 옵션은 같은 Evidence를 재분석해 두 CSV의 byte equality와 이미지 size/mtime 불변을 검사하며, 통합기의 기본 호출에는 포함되지 않습니다.
