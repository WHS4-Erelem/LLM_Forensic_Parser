# ARTINEX Integration Runner

[English](README.md) · [한국어](README.ko.md)

ARTINEX is a forensic parser that bundles the parsers for six LLM services (ChatGPT Desktop, ChatGPT Web, Claude Desktop, Claude Web, Gemini Web, LM Studio) into one. This folder is its integration runner.

Given one disk image, it runs the six parsers in order, checks that each result CSV follows the common format (header, verdict, timestamp, empty cells), loads them into SQLite, and produces the merged `timeline.csv` / `recovered_conversations.csv` and the run summary `integration_report.json`. It uses only the standard library.

## Running

```
powershell -ExecutionPolicy Bypass -File setup.ps1            # first time only: create .venv312 (installs uv first if missing)
python llm_forensic.py -i <image.E01|.dd> -o out               # full run
python llm_forensic.py -i <image> -o out --only chatgpt_desktop,lmstudio
python llm_forensic.py -i <image> -o out --quick               # skip the full image hash (for development)
python llm_forensic.py --self-test
```

| Option | Description |
|---|---|
| `-i`, `--image` | E01 (split `.E01~`), raw (`.dd` `.raw` `.img`, split `.001~`). For split images, give only the first segment. The rest are collected and checked for missing segments |
| `-o`, `--out` | Result folder. Results are written under `<evidence_id>\` inside it |
| `--registry` | Parser registry (default `parsers.json`) |
| `--only a,b` | Run only the given parsers. Previous results of the other parsers stay in the DB and are included in the merged output as is |
| `--quick` | Skip the SHA-256 calculation over all segments. `evidence_sha256` becomes `-` and cannot be used for integrity checks |

Exit codes: 0 all succeeded / 1 some parsers failed or violated the contract / 2 input failure / 3 DB or merged output error.

The console shows only the summary produced by the integration runner (`[Evidence] [DB] [Runner] [Timeline] [Report] [Summary]`). Parser stdout/stderr is kept only in `<parser_name>\run.log`. On failure, the first error line and a `detail:` path (run.log for execution failures, integration_report.json for contract violations) are shown under `[Runner]`. When run directly in a terminal, elapsed time is updated every second on the same line during hash calculation and parser runs (`[Runner] claude_desktop (3/6)  42s 실행 중...`, where 실행 중 means "running"), and the line is replaced by the result line when done. This display does not appear when output is redirected to a file or when run from the GUI.

## Results (`out\<evidence_id>\`)

| File | Content |
|---|---|
| `<parser_name>\` | Each parser's original results and `run.log` (parser version, python, command, start time, stdout/stderr, exit code). Rerunning on the same image replaces only that parser's folder with new results. Only `timeline.csv`, `recovered_conversations.csv` and `run.log` are integrated; parser-specific files such as `result.json` and `cx_result.json` are not read |
| `timeline.csv`, `recovered_conversations.csv` | Merged output. The original 7/10 columns keep the headers and values exactly as the parsers wrote them, followed by provenance columns. Only when writing the merged CSV, empty values become `-` and cells starting with `=` `+` `-` `@` get a leading `'` (prevents Excel formulas). `unified.db` holds the original values unchanged |
| `unified.db` | SQLite. evidence / runs / events / messages |
| `integration_report.json` | Status per parser (`success` / `failed` / `contract_violation` / `normalization_error` / `db_error`), number of loaded rows, list of errors |
| `evidence_manifest.json` | `{file, size_bytes, sha256}` per segment and the overall `evidence_sha256`. After the analysis, recompute with the same command and compare |

The integration runner never rewrites `<parser_name>\*.csv`.

### Column Names

A parser CSV is accepted only if its header is byte-for-byte identical to the common header (including trailing spaces, as in `Model`, `Behavior_details `). Otherwise it is rejected as `HEADER_MISMATCH` and not corrected.

Canonical names are used only inside the integration (unified.db): leading and trailing spaces removed, lowercase, spaces replaced with `_`. The merged CSV headers stay as the originals.

- timeline: `model, timestamp, user_behavior, behavior_details, verdict, artifact_path, artifact_details`
- recovered_conversations: `model, timestamp, conversation_uuid, conversation_title, message_uuid, parent_message_uuid, message_order, role, content, artifact_path`

### Provenance Columns (shared by the merged CSV and the DB, appended after the original columns)

| Column | Meaning |
|---|---|
| `timestamp`, `artifact_path` | Original values written by the parser |
| `timestamp_utc` | (DB only) The original KST notation converted to UTC ISO. Used to sort the merged CSV |
| `artifact_path_normalized` | Path with the drive, volume and image prefixes removed, `\` separators and lowercase. Used for search and duplicate detection. Multiple paths are split on `\|`, normalized individually, and joined with ` \| `. NTFS ADS notation (`:Zone.Identifier`, `:$J`) is kept as is |
| `volume_ref` | Drive letter of the volume the evidence was on. See below |
| `source_parser`, `parser_version`, `source_file`, `parse_time_utc` | Which parser and which file it came from, with which code version (including a source hash), and when (UTC) |
| `evidence_id`, `evidence_sha256` | Which image. `evidence_sha256` is the SHA-256 computed over all segments concatenated in order; `evidence_id` is the first 16 characters of a fingerprint of the first 64 MiB, only an identifier for folder names and not an integrity value |

`volume_ref` distinguishes values confirmed by the parser from guesses made by the integration runner.

- A path where the parser gave a drive letter (`C:\…`) keeps that letter: `C:`.
- A volume the parser refers to only as `volumeN:` or `::NTFS@offset/`, and root-relative paths without a volume (`Users/…`), are guessed to be the system volume only when the same parser's results contain a `Users\` or `Windows\` path on that volume, and are written as `C: (추정, volume0)` / `C: (추정, ntfs@227540992)` / `C: (추정)` (추정 = estimated). The value in parentheses is the volume identifier given by the parser (from the path, or otherwise from `volume=ntfs@offset` in `Artifact_details`).
- Anything else (recovery or data partitions, no path) is `-`.
- Confirm values marked `(추정)` with `SYSTEM\MountedDevices` or similar before using them. In images where both volumes have `Users` (dual boot, an old Windows partition), both are guessed as `C:`, and a data volume with only a backup `Users` folder is also guessed as `C:`. Relative paths without a volume are all treated as one volume within one parser's results, so `Recovery/…` and `$Recycle.Bin/…` are also guessed as `C:`.

## Rerunning the Same Image

- At the start of a run, previous results are deleted in one transaction. If this fails, it exits with code 3 as `DB_ERROR` without running any parser.
  - Full run: deletes all events/messages of that `evidence_id` and loads only this run's results.
  - `--only a,b`: deletes and replaces only rows whose `evidence_id` matches and whose `source_parser` is a or b. Results of parsers that were not run stay in the merged output.
- `runs` is the run history and is never deleted. `runs.status` holds the status of that run and `runs.violations` the list of errors (JSON).
- A `unified.db` created by an older version has only its column names changed to canonical names the first time it is opened. Rows and the runs history are kept, and only `artifact_path_normalized` is recomputed with the current rules.

## Error Types

Entries in `integration_report.json` and `runs.violations` have parser, type, file, row, field, actual, expected and message. row is the CSV row number counting the header as row 1 (the same number Excel shows).

| Type | Status | Meaning |
|---|---|---|
| `PARSER_EXECUTION_ERROR` | failed | Exit code not 0, timeout, or could not run. Details in `<parser_name>\run.log` |
| `UNSUPPORTED_INPUT` | failed | Image extension not listed in the registry `inputs`. The parser is not run and only the reason is written to run.log |
| `OUTPUT_MISSING` | failed | A CSV listed in the registry outputs is missing |
| `CSV_FORMAT_ERROR` | contract_violation | Cannot be read as a UTF-8 CSV |
| `HEADER_MISMATCH` | contract_violation | Header differs from the common format (whitespace and case differences shown per column position) |
| `COLUMN_COUNT_MISMATCH` | contract_violation | A row has a different number of columns |
| `INVALID_TIMESTAMP` | contract_violation | Not `YYYY-MM-DD HH:MM:SS.ffffff KST` or `-` |
| `INVALID_VERDICT` | contract_violation | Not `확정` (confirmed) / `의심` (suspected) |
| `EMPTY_CELL` | contract_violation | Empty cell in the timeline (use `-` when there is no value) |
| `NORMALIZATION_ERROR` | normalization_error | Normalization calculation on the integration side failed |
| `DB_ERROR` | db_error | Failed to open, initialize, load or query the DB |
| `OUTPUT_WRITE_ERROR` | — | Failed to write the merged CSV or the report (for example, when Excel has the file open) |
| `UNKNOWN_USER_BEHAVIOR` | warning (stays success) | Behavior name not in `user_behaviors.txt`. Rows are loaded, and the parser, row and value are recorded in the report and the console |

A parser result that violates the format is not corrected; none of that parser's results are loaded, and it is reported as `contract_violation`. This keeps invalid rows out of the merged output.

If `[Runner]` shows `OK events=0 messages=0`, the console marks it as 0 results and `artifacts_found` in the report is false. Use `<parser_name>\run.log` to tell whether there were no traces or the parser could not read the input.

## Behavior Taxonomy (`user_behaviors.txt`)

The list of names allowed in the timeline `User_behavior` column. It is the common specification that makes the six parsers call the same behavior by the same name, and it is included in the distribution. Names outside the list are reported as `UNKNOWN_USER_BEHAVIOR` warnings but still loaded. Once all parsers use matching names, `ERROR_STATUS["UNKNOWN_USER_BEHAVIOR"]` will be changed to `contract_violation` to promote it to a violation.

## Parser Registry (`parsers.json`)

The parsers are left untouched; only how to run them is written in the registry. For each parser it holds the python, working folder, arguments (with `{image}` `{out}` substitution), output file names, time limit, and how to get the version (CLI or a source constant). A hash of the whole source (`code=`) is always appended to `parser_version`.

`inputs` declares supported extensions only for parsers that check the extension and reject others (currently gemini_web, lmstudio). Without a declaration, no check is done. If a parser's allowed list grows, update this declaration too.

## Answer Key Comparison (development and validation only, `validation\`)

Not used in real analysis. It is a tool for measuring parser detection on test images that have an answer sheet; `llm_forensic.py` does not read this folder.

```
python validation\verify_merged.py --timeline out\<evidence_id>\timeline.csv --key validation\scenario_keys\plain_2026-09-15.csv
```

It compares the per-service answer keys (`validation\scenario_keys\*.csv`: model, event_id, action, kst) with the merged timeline in a ±120-second window and produces `verify_report.md`.

## Runtime Environment

`setup.ps1` installs uv with the official install script first if it is missing, then creates a single `.venv312` (Python 3.12) and installs the requirements of all six parsers and the GUI's `gui/requirements.txt` (PyQt6). If `.venv312` already exists, it is not recreated; only the packages are brought up to date, and setup stops immediately if any installation fails. Python is pinned to 3.12 because Windows wheels for `pytsk3` and `libewf-python` exist only up to 3.12, and the zstd used by the Claude Web parser requires an MSVC build on 3.14. The Autopsy add-on (`../Autopsy_Addon`) uses the same environment.
