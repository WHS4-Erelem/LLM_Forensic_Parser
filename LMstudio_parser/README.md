# LM Studio Forensic Parser

Windows LM Studio Evidence를 읽기 전용으로 분석하여 사용자 행위와 대화 원문을 복구합니다. 분석 구조는 Artifact → ObservedFact → CandidateEvent → CSV입니다. Ground Truth label, 실험 폴더명, MRK 문자열, 실험 시각으로 행위를 생성하지 않습니다.

## 실행 환경과 라이브러리

Python 3.14 환경에서 검증했습니다. 알려진 JSON 구조의 기준은 LM Studio 0.4.21 Build 2이며, 모든 버전/로그 형식을 지원한다는 의미는 아닙니다.

Directory 분석은 Python 표준 라이브러리(json, csv, sqlite3, pathlib, datetime 등)를 사용합니다. 이미지/standalone MFT 분석에는 low-level Dissect를 사용하며 dissect.target은 사용하지 않습니다.

```powershell
python -m pip install dissect.evidence==3.13 dissect.ntfs==3.16 dissect.volume==3.18
```

## 지원 입력과 실행

- 추출된 .lmstudio directory
- Windows User Profile
- 추출된 Windows filesystem root
- DD / RAW / IMG
- E01 및 reader가 지원하는 segmented EWF 입력
- 관련 JSON, listing, MFTECmd/FileSystem CSV, LogTracker SQLite, standalone MFT가 포함된 추출 directory

최종 실행 위치는 프로젝트 root입니다.

```powershell
# Parser가 있는 프로젝트 폴더에서 실행합니다.
cd "C:\path\to\LM_Studio Parser"

# DD/E01 등 이미지 Evidence
python lmstudio_parser.py "C:\path\to\evidence\disk-image.dd" --output ".\test_output\analysis"

# 추출된 LM Studio Evidence
python lmstudio_parser.py "C:\path\to\evidence\.lmstudio" --output "C:\path\to\output\LMStudio"
```

동일 대상의 실제 이전 snapshot이 있으면 선택적으로 --before를 지정할 수 있습니다. 단일 DD/E01 분석에 필수인 인자가 아닙니다.

```powershell
python lmstudio_parser.py "C:\path\to\evidence\After" --before "C:\path\to\evidence\Before" --output "C:\path\to\output\comparison"
```

Before/After의 시간 순서와 동일 사용자/대상 여부는 분석자가 확인해야 합니다. 폴더명이나 label로 순서를 추측하지 않습니다.

## Evidence 읽기 전용 정책

이미지와 raw NTFS 파일은 읽기 전용 stream으로 열며 mount-write하지 않습니다. SQLite는 URI mode=ro로 엽니다. Evidence 안에 분석 결과를 쓰지 않습니다.

입력 Evidence directory 내부와 Evidence 보존용 directory 내부에는 출력할 수 없습니다. 출력 파일의 symlink/외부 경로/hardlink도 거부합니다. 기존 출력 파일은 같은 이름만 덮어쓰며, 다른 파일은 지우지 않습니다.

`--validate`는 분석 전후 DD/E01의 size·mtime을 비교하고, CSV 계약과 반복 분석 결과를 검사합니다. 전체 이미지 SHA-256이나 별도의 Research directory manifest를 자동 계산하는 기능은 아닙니다.

## NTFS 및 Windows Artifact 수집

- Directory 전체 무차별 carve 대신 관련 LM Studio/profile/program/document 경로를 선택합니다.
- $MFT: 원본 $STANDARD_INFORMATION creation/modified와 record/sequence locator를 사용합니다.
- standalone $MFT: MFTECmd index가 있으면 관련 record를 선택하고 resident 본문만 복구합니다. Non-resident 본문은 volume data 없이는 읽지 않습니다.
- $UsnJrnl:$J: 관련 filename/path와 실제 reason, offset, FRN segment/sequence를 보존합니다. 개별 malformed record는 건너뛰고 후속 수집을 계속합니다. Iterator 자체 오류는 AnalysisIssue에 남깁니다.
- 삭제 record: 실제 연결된 LM Studio conversation/attachment resident JSON만 선택 복구합니다. live/reused record, 임의 파일 carve, credential 삭제 복구는 제외합니다.
- Zone.Identifier: GGUF 등 실제 연결 파일의 ADS 출처를 보강합니다. URL만으로 다운로드 완료를 판정하지 않습니다.
- Prefetch: LM Studio 실행 Artifact 및 원본 NTFS 시각을 사용합니다. Prefetch 바이너리 내부의 모든 run timestamp를 해석하는 기능은 아닙니다.
- FileSystem/MFTECmd CSV와 read-only LogTracker DB의 실제 create/modify/delete/rename 기록을 수집합니다.
- Directory host stat은 수집 metadata이며 일반 행위 시각으로 사용하지 않습니다. 아래 E08-01의 기존 제한적 예외만 유지합니다.

## LM Studio 주요 Artifact와 분석

### Conversation

conversations/*.conversation.json, conversation-config.json, window/global state, 실제 연결 로그/파일 history를 사용합니다.

명시적 edited marker, assistant versions/currentlySelected, 실제 user text, generation metadata, attachment link를 구분합니다. non-empty 대화도 원본 NTFS creation/history와 같은 profile의 config 연결이 있으면 생성 후보를 만들 수 있습니다. 파일 존재나 empty 대화 하나만으로 생성 확정은 하지 않습니다.

실제 user/assistant/tool 및 기타 role의 문자열을 복구합니다. 모든 retry version과 text/step 부분을 보존하고 원본 message/version/content 배열 순서에 따라 message_order를 1부터 결정적으로 부여합니다. message_order는 순서일 뿐 message_id가 아닙니다.

Prompt 삭제는 실제 Before user 내용, After 제거, 정확히 연결된 rewrite가 있으면 강한 근거로 사용합니다. 단일 이미지의 assistant residual + 과거 user activity + write context는 삭제를 확정하지 않고 미확정으로 유지할 수 있습니다. Assistant-only/현재 파일 부재만으로 삭제하지 않습니다.

### Account

local-identity.json, user-profile.json, lmstudio-hub.json의 실제 key object/null, lm-link-account-status-cache.json 등을 분석합니다. Credential 원문은 출력하지 않고 필요한 식별자는 안전한 fingerprint로 연결합니다.

로그인 상태와 coordinated reset은 행위 자체의 직접증거와 구분합니다. 현재 profile 하나, null 하나, 단순 modify history, 재인증 문구만으로 계정 전환을 확정하지 않습니다. --before 연결은 실제 상태 및 식별자 변화를 요구합니다.

### Attachment

user-files/*.metadata.json의 originalName, fileIdentifier, MIME/type, size/hash와 conversation attachment link를 연결합니다. 실제 image 타입과 문서 타입을 구분합니다. preview.data는 출력하지 않습니다.

업로드 발생 시각은 원본 DD/E01 NTFS creation 또는 정확히 연결된 단일 creation history에서 얻습니다. 이 시각 추가로 판정 상태를 승격하지 않습니다. 삭제에는 실제 delete history가 필요합니다.

### Model / Download

model-data.json의 identifier와 검증된 load timestamp, conversation model context, 명시적 model-load 로그를 구분합니다.

download-jobs-info.json 및 single-downloads-info.json의 실제 download record, 상태/크기/경로, 최종 GGUF와 ADS/history를 연결합니다. filesystem history를 model_state family로 재포장하지 않습니다. URL 또는 .part만으로 완료 확정은 하지 않습니다.

E09-03은 명시적 completedTimestamp 우선, 없으면 실제 record의 startedTimestamp fallback을 유지합니다. Start fallback을 완료 시각으로 표현하지 않으며 Artifact_details에 provenance를 표시합니다.

### Runtime / Application / Export

LM Studio program components, shortcut, Prefetch, runtime/server state 및 scoped log를 분석합니다. 설치 directory 존재만으로 설치 확정하지 않습니다.

http-server.json + pid lock 잔존물이나 정상 종료 evidence 부재만으로 강제 종료 후보를 생성하지 않습니다. 실제 positive termination record가 필요합니다.

Export는 알려진 LM Studio Markdown signature를 확인하고 독립 생성 history를 보강합니다. 일반 Markdown/JSON 또는 Documents의 새 파일이라는 이유만으로 Export로 판단하지 않습니다.

## Verdict, Evidence Family, Source Lineage

내부 status는 confirmed / suspected / indeterminate입니다.

- 해당 Rule에서 허용하는 명시적 direct_tag가 있는 직접 행위 레코드 1개이면 confirmed가 가능합니다.
- 간접증거는 서로 다른 Evidence Family와 서로 다른 실제 Source Lineage가 동일 행위를 지지할 때 교차 검증합니다.
- 같은 JSON field들을 여러 Fact로 나누거나 같은 log line/materialized record를 재사용하여 독립증거를 늘리지 않습니다.
- Rule별 conflict/forced guard가 우선하며 모든 단일 Fact를 confirmed로 승격하지 않습니다.

주요 family는 account_state, conversation_state, attachment, model_state, lmstudio_log, runtime_state, filesystem, windows_os, final_file입니다. Field pointer는 같은 JSON의 독립 source가 아니며, log line/USN offset/CSV·DB record locator는 실제 레코드 경계를 나타냅니다.

CSV에서는 confirmed → 확정, suspected → 의심만 출력합니다 (팀 공통 판정값). indeterminate는 Context에 남기고 터미널에 미확정/CSV 제외로 표시합니다.

### 21개 Rule의 Direct Evidence 검토

아래 표는 현재 실제 생성/사용 경로를 요약합니다. Rule 계약에 tag가 선언되어 있어도 producer가 검증하지 않은 tag를 발급하지는 않습니다.

| Rule / 행위 | 직접증거 또는 보수적 판정 조건 |
|---|---|
| E01-01 로그인 | scoped 명시적 성공 로그 단일 record 허용; 단일 account state 불허 |
| E01-02 로그아웃 | scoped 명시적 성공 로그 단일 record 허용; 단일 null 불허 |
| E01-03 계정 전환 | 단순 switch/re-auth 문구에 Direct tag 미발급; 실제 Before/After 식별자 필요 |
| E02-01 설치 | 검증된 installer 완료 schema 없음; 실제 설치 구조/생성 교차 검증 |
| E02-02 삭제 | 실제 core 삭제 + corroboration; uninstaller create/open을 execution으로 취급하지 않음 |
| E03-01 대화 생성 | 파일 존재 단독 불허; create와 config 연결 |
| E03-02 대화 삭제 | 실제 delete/rename history; 보수적 추정, 부재 단독 불허 |
| E03-03 대화 수정 | 실제 explicit edited marker 허용 |
| E03-04 재시도 | version count 단독 확정 불허 |
| E04-01 Prompt 입력/전송 | 실제 user text; ID-linked inference 보강. 일반 inference 문구 단독 Direct tag 미발급 |
| E04-02 Prompt 삭제 | Before/After + rewrite 또는 미확정 context; assistant-only 불허 |
| E05-01 이미지 업로드 | metadata와 실제 attachment link/history 교차 검증 |
| E05-02 이미지 삭제 | 실제 deletion과 관련 metadata/link, 부재 단독 불허 |
| E05-03 문서 업로드 | 실제 metadata와 conversation link/history |
| E05-04 문서 삭제 | 실제 deletion record, 부재 단독 불허 |
| E07-01 Export | 알려진 signature, 독립 history; 같은 Markdown stat은 독립 보강 아님 |
| E08-01 실행 | 기존 Prefetch execution 근거 및 runtime corroboration 유지 |
| E08-02 정상 종료 | scoped 명시적 종료 record 허용; lock 부재 불허 |
| E08-03 강제 종료 | scoped 명시적 forced termination record 허용; residue-only 불허 |
| E09-01 모델 변경 | 검증된 load state 또는 scoped 명시적 model load record |
| E09-03 다운로드 | 실제 record/최종 파일/history 조합; start/URL/.part 단독 완료 확정 불허 |

### 직접 로그의 제한된 문법

Direct tag는 .lmstudio/server-logs/*.log의 전체 event 문구에만 부여합니다. 선택적 ISO timestamp와 INFO prefix 뒤 다음 문구를 허용합니다.

- login succeeded / logged in / signed in
- logout succeeded / logged out / signed out
- normal exit / graceful shutdown / shutdown complete / clean shutdown
- forced termination / terminated forcibly
- model loaded / model load succeeded (선택적 : model-identifier)

인용문, prompt= 값, 실패/요청 suffix, 일반 substring 매칭은 Direct Evidence로 승격하지 않습니다. 일반 .txt와 Research listing은 Direct log가 아닙니다. 실제 Research log body의 버전별 형식은 충분히 확보되지 않았으므로 이 문법은 제한된 코드 계약과 synthetic 양성/음성 테스트로 검증하며 모든 버전의 의미를 보증하지 않습니다.

## 터미널 출력

CLI는 [1/7] 입력 검증 → [2/7] 수집 → [3/7] 아티팩트 분석 → [4/7] Fact 생성 → [5/7] 행위 판정 → [6/7] 대화 복구 → [7/7] CSV 출력을 표시합니다.

Artifact/ObservedFact/Candidate 수, volume/JSON/USN 통계, fatal/non-fatal AnalysisIssue, 각 Candidate의 내부 status·Rule·family·Direct 여부·limitation·최대 3개 주요 locator를 출력합니다. 최종 CSV 건수와 경로도 표시합니다.

미확정 후보는 [미확정/CSV 제외]로 확인합니다. 실제 user/assistant 본문이나 raw log line을 터미널에 무조건 출력하지 않습니다. 라이브러리 analyze()는 기본적으로 조용하며 선택적 progress callback과 report_analysis()를 제공합니다.

## timeline.csv — 정확히 7 columns

```text
Model,Timestamp,User_behavior,"Behavior_details ",Verdict,Artifact_path,"Artifact_details "
```

사용자가 어떤 행동을 수행했고 어떤 포렌식 증거가 이를 지지하는지 보여줍니다.

| Column | 계약 |
|---|---|
| Model | lmstudio |
| Timestamp | 행위 시각, `YYYY-MM-DD HH:MM:SS.ffffff KST` (팀 공통 표기) 또는 - |
| User_behavior | 21개 Rule의 한국어 행위명 |
| Behavior_details | 실제 Prompt/수정 메시지, 원본 파일명, 모델 identifier, 대화/응답 정보 또는 안전한 상태 설명 |
| Verdict | 확정 / 의심 |
| Artifact_path | 실제 원본 Artifact 경로를 정렬하여 path1 \| path2로 결합 |
| Artifact_details | Rule, Evidence Family, Direct 여부, conversation_id, JSON pointer/log line/USN offset/MFT locator, Fact 유형, timestamp 출처, limitation |

Behavior_details는 decision_reason을 그대로 복사하지 않습니다. 실제 user_message/수정 메시지 본문은 요약·절삭하지 않습니다. Artifact_details는 관련 provenance이며 전체 JSON이나 credential dump가 아닙니다. 전송 확인 근거가 없는 Prompt는 전송 여부 미확인을 표시합니다.

## recovered_conversations.csv — 정확히 10 columns

```text
Model,timestamp,conversation_uuid,conversation_title,message_uuid,parent_message_uuid,message order,role,content,Artifact_path
```

conversation_uuid, message order, role, message_uuid, parent_message_uuid를 통해 사용자와 AI의 전체 메시지 흐름을 복원합니다.

| Column | 계약 |
|---|---|
| Model | lmstudio |
| timestamp | 메시지/버전/해당 text에 연결된 시각(`… KST`), 없으면 - |
| conversation_uuid | 명시적 conversationId/conversationIdentifier → scoped config/UI identifier → 실제 전체 conversation 파일 basename → - |
| conversation_title | 실제 제목 또는 검증된 동일 대화 보완값 |
| message_uuid / parent_message_uuid | Artifact에 실제 존재하는 식별자만 사용 |
| message_order | 원본 message/version/content 순서의 결정적 1-based 순번 |
| role | 실제 role 보존 |
| content | Prompt/Response 원문; metadata-only이면 - |
| Artifact_path | 해당 메시지를 복구한 실제 Conversation Artifact 경로 |

실제 basename fallback은 CSV 표현용이며 cross-snapshot correlation의 임의 ID로 사용하지 않습니다. 숫자 stem/hash/array index로 message ID나 parent ID를 생성하지 않습니다.

## Timestamp와 CSV 안전 계약

- UTC absolute/명시적 timezone이 있는 시각만 KST UTC+09:00으로 정규화합니다.
- YYYY-MM-DD HH:MM:SS, 소수초 절삭, 반올림 금지입니다.
- timezone 불명 값은 UTC로 가정하지 않고 -를 출력합니다.
- filename 숫자, nearest timestamp, Ground Truth 시각으로 채우지 않습니다.
- Conversation createdAt이나 filesystem mtime을 메시지 시각으로 복사하지 않습니다. 검증된 role-last fallback은 마지막 해당 role의 단일 version에만 제한합니다.
- E08-01은 이미 생성된 Event에서 검증된 runtime/log 시각 → 기존 명시적 시각 → 기존 runtime filesystem mtime fallback을 유지합니다. 이 예외를 다른 행위에 일반화하거나 Direct Evidence로 승격하지 않습니다.
- 두 CSV의 모든 data cell은 non-empty이며 결측값은 정확히 -입니다.
- UTF-8-SIG BOM, CRLF record ending, 결정적 정렬을 사용합니다. 메시지 내부 원본 줄바꿈은 유지합니다.
- 정확히 - 하나는 결측값이므로 그대로 저장합니다. =, +, -, @로 시작하는 다른 실제 문자열에는 apostrophe를 붙여 spreadsheet formula injection을 방어합니다.
- Artifact_path에는 원본 Evidence 위치만 사용하며 materialized/temp path는 출력하지 않습니다.

## 민감정보 정책

Credential, access/refresh token, private key, passkey, secret, preview.data, raw Base64 image는 비대화 출력과 터미널에 노출하지 않습니다. 로그는 raw line 대신 의미가 확인된 Fact와 locator를 저장합니다. 계정 식별자는 필요한 경우 fingerprint로 표시합니다.

실제 User Prompt/Assistant Response는 포렌식 원문 예외입니다. recovered content 및 해당 실제 Prompt/수정 내용은 요약·번역·keyword redaction하지 않습니다. Formula 방어는 직렬화 시점에만 적용합니다.

## 검증

```powershell
cd "C:\path\to\LM_Studio Parser"
python -c "import lmstudio_parser; print(lmstudio_parser.__file__)"
python -m py_compile lmstudio_parser.py
python lmstudio_parser.py --self-test
python lmstudio_parser.py "C:\path\to\evidence\disk-image.dd" --output ".\test_output\validated" --validate
```

검증 기능과 152개 회귀 테스트는 `lmstudio_parser.py`에 내장되어 있습니다. 별도의 validator/test Python 파일은 필요하지 않습니다.

`--self-test`는 detector, Direct Evidence, Source Lineage, timestamp, CSV, 민감정보 및 오탐 방지 회귀 테스트를 실행합니다. `--validate`는 정상 분석 후 같은 Evidence를 다시 분석하여 두 CSV의 byte equality를 확인하고 다음을 검사합니다.

- 정확한 7/10-column schema
- 빈 cell 0개와 `-` 결측값
- Verdict `확정`/`추정` 제한 및 미확정 터미널 유지
- UTF-8-SIG, CRLF, formula injection 방어
- credential/preview 비노출
- DD/E01 size·mtime 불변
- USN 통계와 AnalysisIssue

검증 결과는 지정한 출력 directory의 `validation.json`에 저장합니다.

서로 다른 출력 directory를 지정하면 기존 분석 결과를 덮어쓰지 않습니다. DD와 E01이 동일 획득본이라는 확인 없이 두 이미지의 equality를 요구하지 않습니다.

## Known limitations

- 현재 snapshot만으로 과거 로그인/로그아웃/계정 전환/삭제/종료를 모두 복구할 수 없습니다.
- USN wrap/누락, 손상 record, non-resident 본문 부재는 Historical Evidence를 제한합니다.
- Standalone MFT의 non-resident profile/export 본문은 복구하지 않습니다. 직접 확인하지 못한 Export format/signature는 추가하지 않습니다.
- ID-linked edit/retry history가 여러 시각이면 임의로 하나를 선택하지 않습니다.
- 일반 텍스트 로그의 모든 LM Studio 버전별 grammar를 지원하지 않습니다.
- Synthetic Direct Evidence 테스트 PASS는 실제 Evidence에 그 로그가 존재한다는 뜻이 아닙니다.
- Prefetch 내부 last-run 구조를 전부 해석하지 않으므로 기존 실행 fallback 시각의 출처를 별도로 검토해야 합니다.
- 파일 누락은 행위 부재를 뜻하지 않으며 미확정 후보를 CSV에서 제외해도 Context/터미널에는 남습니다.
- BitLocker, 손상 filesystem, unsupported disk layout/EWF variant 등은 분석을 제한할 수 있습니다.

## 최종 프로젝트 구조

```text
<project-directory>\LM_Studio Parser
├── lmstudio_parser.py
├── README.md
└── test_output
    └── validated
        ├── timeline.csv
        ├── recovered_conversations.csv
        └── validation.json
```

배포와 실행에 필요한 Python 파일은 `lmstudio_parser.py` 하나입니다.
