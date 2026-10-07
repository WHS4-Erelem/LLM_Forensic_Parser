# ARTINEX

Windows 디스크 이미지(E01 / raw)에서 LLM 서비스 6종의 사용 흔적을 찾아
**사용자 행위 타임라인**과 **복구된 대화 내용**을 뽑아내는 포렌식 파서 모음과, 그 6개를 한 번에 돌리는 ARTINEX 통합 실행기.
ARTINEX 는 이 통합 파서 전체의 이름이다 (저장소: `LLM_Forensic_Parser`).

WHS4 팀 프로젝트 「LLM 대화 내용 추출 및 사용자 행위 분석」 산출물.

## 구성

| 폴더 | 대상 | 진입점 | 실행 환경 |
|---|---|---|---|
| `ChatGPT_APP_Parser` | ChatGPT / Codex 데스크톱 앱 (MS Store `OpenAI.Codex`) | `run_parser.py` | Python 3.12 · pytsk3 · libewf-python |
| `ChatGPT_Web_Parser` | chatgpt.com (Chrome) | `python -m chatgpt_parser.cli` | Python 3.12 · pytsk3 · brotli · cramjam |
| `Claude_APP_Parser` | Claude 데스크톱 앱 | `run_parser.py` | Python 3.12 · pytsk3 · libewf-python · ccl-chromium-reader · zstandard |
| `Claude_Web_Parser` | claude.ai (Chrome) | `python -m claude_web_forensics` | Python 3.12 · dissect · ccl-chromium-reader |
| `Gemini_Web_Parser` | gemini.google.com (Chrome) | `gemini_parser.py` | Python 3.10+ · pytsk3 · libewf-python |
| `LMstudio_parser` | LM Studio (로컬 LLM) | `lmstudio_parser.py` | Python 3.12 · dissect |
| `integration` | ARTINEX 통합 실행기 — 위 6개를 순서대로 실행·검증·병합 | `llm_forensic.py` | 표준 라이브러리만 (파서는 공용 `.venv312`) |

파서마다 자세한 사용법과 판정 규칙은 각 폴더의 README 에 있다.

## 공통 출력 계약

모든 파서는 같은 형식의 CSV 두 개를 낸다. 통합기는 이 계약을 어긴 결과를 적재하지 않는다.

- `timeline.csv` 7열: `Model, Timestamp, User_behavior, Behavior_details, Verdict, Artifact_path, Artifact_details`
- `recovered_conversations.csv` 10열: `Model, timestamp, conversation_uuid, conversation_title, message_uuid, parent_message_uuid, message order, role, content, Artifact_path`
- `Verdict` 는 `확정` 또는 `의심`, 시각은 `YYYY-MM-DD HH:MM:SS.ffffff KST`, 빈 값은 `-`
- `User_behavior` 는 팀 행위 분류 체계 `integration/user_behaviors.txt` 의 이름만 쓴다 (서비스명 없이). 목록 밖 이름은 통합기가 경고로 보고한다

## 빠른 시작 (ARTINEX 통합 실행)

[uv](https://docs.astral.sh/uv/) 가 필요하다.

```powershell
cd integration
powershell -ExecutionPolicy Bypass -File setup.ps1        # 최초 1회: .venv312 생성
python llm_forensic.py -i <이미지.E01|.dd> -o out          # 파서 6개 실행 → out\<evidence_id>\
python validation\verify_merged.py --timeline out\<evidence_id>\timeline.csv --key validation\scenario_keys\plain_2026-09-15.csv   # 개발 검증 전용 (정답 시트가 있을 때만)
```

결과는 `out\<evidence_id>\` 에 병합 `timeline.csv` · `recovered_conversations.csv` · `unified.db`(SQLite) ·
`evidence_manifest.json`(세그먼트별 SHA-256) · `integration_report.json`(파서별 상태·오류 목록) · 파서별 원본 결과 폴더로 남는다.
종료코드 0 전부 성공 / 1 일부 파서 실패·계약 위반 / 2 입력 실패 / 3 통합 DB·출력 오류. 자세한 내용은 `integration/README.md`.

## 규칙

- **분석 결과는 커밋하지 않는다.** `out/`, 병합 CSV, `unified.db`, 디스크 이미지는 `.gitignore` 로 막혀 있다. 복원된 대화 원문과 계정 식별자가 그대로 들어 있기 때문이다.
- 통합기는 파서 코드를 수정하지 않는다. 파서 실행 방법은 `integration/parsers.json` 에만 적는다.
- 파서가 쓴 원본 값은 덮어쓰지 않고, 정규화·출처(provenance) 열을 뒤에 덧붙인다.
