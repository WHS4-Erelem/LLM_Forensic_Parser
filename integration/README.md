# LLM 파서 통합 실행기

이미지 하나를 주면 파서 6개를 순서대로 실행하고, 결과 CSV 계약(헤더·판정·시각·빈 셀 `-`)을 검사한 뒤
SQLite 에 적재하고 병합 `timeline.csv` / `recovered_conversations.csv` 를 만든다.

```
powershell -ExecutionPolicy Bypass -File setup.ps1            # 최초 1회: .venv312 / .venv314 생성
python llm_forensic.py -i <이미지.E01|.dd> -o out              # 전체 실행
python llm_forensic.py -i <이미지> -o out --only chatgpt_desktop,lmstudio
python llm_forensic.py --self-test
```

결과: `out\<evidence_id>\`
- `<파서명>\` 파서별 원본 결과(그대로 보존, 같은 이미지로 재실행하면 그 파서 폴더만 새 결과로 교체) + `run.log`(파서 버전·python·명령·시작 시각·stdout/stderr)
- `timeline.csv`, `recovered_conversations.csv` 병합본 — 팀 7열/10열은 파서가 쓴 값 그대로, 그 뒤에 provenance 열
- `unified.db` — evidence / runs / events / messages
- `evidence_manifest.json` — 세그먼트별 `{file, size_bytes, sha256}` 매니페스트 + 전체 `evidence_sha256`. 분석 종료 후 같은 명령으로 다시 계산해 대조한다

provenance 열 (병합 CSV·DB 공통, 원본 열을 덮어쓰지 않고 덧붙임)

| 열 | 뜻 |
|---|---|
| `Timestamp` / `timestamp`, `Artifact_path` | 파서가 쓴 원본 값 (timestamp_raw, artifact_path_raw) |
| `timestamp_utc` | 원본 KST 표기를 UTC ISO 로 환산한 정규화 시각 (정렬용) |
| `artifact_path_normalized` | 드라이브·볼륨 접두어 제거, `\` 구분, 소문자 — 검색·중복 판별용 |
| `volume_ref` | 파서가 준 볼륨 식별자 (`ntfs@오프셋`, `volume0`), 없으면 `-` |
| `source_parser`, `parser_version`, `source_file`, `parse_time` | 어느 파서의 어느 파일에서, 어떤 코드 버전(소스 해시 포함)으로, 언제 나왔는지 |
| `evidence_id`, `evidence_sha256` | 어떤 증거 이미지인지. `evidence_sha256` 은 세그먼트 전체를 순서대로 이어 계산한 SHA-256 (무결성 대조용). `evidence_id` 는 첫 64MiB 지문(`evidence_quick_fingerprint`)의 앞 16자로, 폴더명 식별자일 뿐 무결성 값이 아니다. `--quick` 이면 `evidence_sha256`='-' |

정답지 대조

```
python verify_merged.py --timeline out\<evidence_id>\timeline.csv --key scenario_keys\plain_2026-09-15.csv
```
서비스별 정답지(시트 export, `scenario_keys\*.csv`: model, event_id, action, kst)와 병합 타임라인을 ±120초 창으로 대조해 `verify_report.md` 를 만든다.

규칙
- 파서는 손대지 않는다. 실행 방법은 `parsers.json` 레지스트리에만 적는다.
- `Artifact_path` 는 파서 표기 그대로 두고, 검색·중복 판별은 `artifact_path_normalized` 로 한다 (드라이브 문자 추정 안 함).
- `volume_ref` 는 파서가 준 값만 옮긴다. 우선순위: Artifact_details 의 `volume=` / `partition_offset=` 키 → 경로의 `NTFS@오프셋`·`volumeN` → 레지스트리 `volume_json`(실행 단위 JSON) → `-`.
  현재 chatgpt_desktop·gemini_web 은 행 단위, chatgpt_web 은 실행 단위, lmstudio 는 경로(volume0), claude_desktop·claude_web 은 미제공(`-`).
- 헤더·Verdict·Timestamp·빈 셀 계약을 어긴 파서 결과는 적재하지 않고 "계약 위반" 으로 보고한다.
- 종료코드 0 전부 성공 / 1 일부 실패·위반 / 2 입력 실패.

실행 환경: `.venv312` = ChatGPT Desktop·ChatGPT Web·Claude Desktop·Claude Web·Gemini, `.venv314` = LM Studio (`setup.ps1` 참조).
