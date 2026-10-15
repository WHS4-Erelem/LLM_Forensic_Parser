# ARTINEX GUI

[English](README.md) · [한국어](README.ko.md)

**ARTINEX** is the name of the whole integrated LLM forensic parser. This folder (`gui/`) is the **PyQt6 desktop interface that
runs ARTINEX and shows the analysis results**.

The GUI calls the integration Runner (`integration/llm_forensic.py`) and the six parsers **without modifying them**.
The GUI itself is not a forensic parser and does not produce verdicts or findings. Every value on screen is read from the
`timeline.csv` / `recovered_conversations.csv` / `integration_report.json` produced by the integration Runner.

```
E01 / DD  →  PyQt6 GUI  →  integration/llm_forensic.py  →  parsers registered in parsers.json  →  common schema
          →  timeline.csv · recovered_conversations.csv · unified.db · integration_report.json  →  shown in the GUI
```

The GUI runs **only the integration Runner**. It does not run individual parsers directly and does not hard-code parser
commands — the source of truth for the parser list and how to run them is `integration/parsers.json`. When a new parser is
registered, it appears in the selection list without changing the GUI.

**No plugin features are included.** Even though the repository contains `Autopsy_Addon/`, the GUI does not import or run it
and adds no buttons or menus for it (`gui/tests/test_gui_integration.py::PluginIsolationTest` enforces this).

### The result folder is `<output folder>\<evidence_id>`

The integration Runner writes results **not directly under** the output folder the user picks, but under `<out>\<evidence_id>\`
(`evidence_id` = the first 16 characters of the SHA-256 of the first 64 MiB of the first segment). The GUI does not compute this
path; it takes it from the Runner's `[Report]` output path. Only if it missed that line does it scan the output folder for the result folder.

```
<out>\<evidence_id>\
├─ timeline.csv · recovered_conversations.csv      ← merged results (team columns + provenance columns)
├─ unified.db · integration_report.json · evidence_manifest.json
└─ <parser_name>\                                  ← each parser's original results + run.log
```

## Running

Open PowerShell in the folder where you got the repository (where `integration`, which contains `llm_forensic.py`, and `gui`
are side by side) and type:

```powershell
powershell -ExecutionPolicy Bypass -File integration\setup.ps1   # first time only: creates .venv312, shared by the parsers and the GUI (PyQt6)
integration\.venv312\Scripts\python.exe gui\main.py
```

If you do not have the repository yet, get it first and move into that folder.

```powershell
git clone https://github.com/WHS4-Erelem/LLM_Forensic_Parser.git
cd LLM_Forensic_Parser
```

`gui\main.py` can be run from any folder, but the relative paths in the example above assume the repository root.

`setup.ps1` installs uv first if it is missing, then installs the dependencies of the six parsers and `gui\requirements.txt` into the same `.venv312`.
The GUI starts the integration Runner with the Python that launched it. You can also launch the GUI from another Python with only PyQt6
installed, but the parsers always run in `.venv312`, so that environment must exist. Without the virtual environment, the integration Runner
records each parser as `PARSER_EXECUTION_ERROR` and continues to the end, and the GUI shows those failures in the Errors tab.

## Screen Flow

| Step | Content |
|---|---|
| 1. Case Setup | Case name / case number / analyst / notes. **새 분석 시작** (start new analysis) or **기존 분석 불러오기** (load existing analysis) |
| 2. Evidence Setup | Evidence image (E01·DD) · result folder · Run All / Manual Selection (`--only`) · `--quick` · input validation |
| 3. Analysis Progress | Status per module, live stdout/stderr log, **분석 중단** (stop analysis) button. Progress is indeterminate because the Runner does not report a percentage |
| 4. Results Workspace | Overview on the left · Overview/Timeline/Conversations/Artifacts/Errors in the center · evidence details on the right |

Selecting a Timeline row immediately updates the **근거 상세** (evidence details) panel on the right with that row's values
(behavior · Verdict · Timestamp · Behavior Details · Artifact Path · Artifact Details · provenance).
The Errors / Artifacts tables use the same panel.

**분석 중단** (stop analysis) kills the running Runner process. Result files the Runner has already written up to that point
remain, and the GUI does not delete them — results of a stopped run may be incomplete.

The **evidence and integrity** panel in Overview shows only the values recorded in `evidence_manifest.json` / `integration_report.json`.
The GUI does not recompute hashes. If the run used `--quick`, `evidence_sha256` is `-`, and the panel shows the reason why this is a normal result.

## Files

| Path | Role |
|---|---|
| `gui/main.py` | Entry point. QApplication · applies the QSS |
| `gui/requirements.txt` | Python dependencies needed to run the GUI |
| `gui/main_window.py` | TopBar + four-step screens, three-pane results workspace, details panel |
| `gui/integration_runner.py` | Runs the integration Runner with `QProcess`, parses stdout (module status · result folder) |
| `gui/result_loader.py` | Read-only loader for the result folder (CSV · report → metrics · sessions · artifacts · errors) |
| `gui/case_manager.py` | Saves and reads `case_info.json` |
| `gui/styles.qss` | Dark DFIR theme (teal accent). Colors drawn directly by delegates use the same values as `main_window.DARK` |
| `gui/tests/test_gui_integration.py` | GUI ↔ integration contract regression tests (CLI arguments · console parsing · result loading · plugin isolation) |

Run the tests with the same interpreter as the GUI (`.venv312` with PyQt6 installed).

```powershell
$env:QT_QPA_PLATFORM = "offscreen"
integration\.venv312\Scripts\python.exe -B -m unittest discover -s gui/tests
```

## Integration Runner Contract (what the GUI conforms to)

| Item | Content |
|---|---|
| Run | `python -u integration/llm_forensic.py -i <IMAGE> -o <OUT> --registry <parsers.json> [--only a,b] [--quick]` |
| Parser selection | GUI checkboxes → `--only` (when everything is selected, `--only` is not added) |
| `--quick` | **Skips only the full and per-segment integrity hash calculation.** It does not skip parsers or artifacts. `evidence_sha256` staying `-` in this case is normal, and the GUI does not show it as an error |
| Exit codes | `0` all succeeded / `1` some parsers failed or violated the contract / `2` input failure / `3` integration DB or merged output error |
| `exit=1` | **Not a total failure.** The successful parsers' `timeline.csv` etc. exist, so the GUI opens the results screen and shows only the failed parsers under Errors & Limitations |
| `exit=2/3` | Even without merged CSVs, if `integration_report.json` exists the GUI opens the results screen to show the errors |
| console | `[Evidence]` · `[Runner]` · `[DB]` · `[Timeline]` · `[Report]` · `[Summary]`. `[DB] FAILED` means no parser could be run, so it is shown on screen immediately |
| Parser status | Uses the report's `success` / `failed` / `contract_violation` / `normalization_error` / `db_error` / `output_error` as is. The GUI does not invent states that do not exist |
| warning | Warnings such as `UNKNOWN_USER_BEHAVIOR` are only warnings — a single warning does not turn a parser into Failed |
| `--only` rerun | Previous results for the same `evidence_id` can remain in the merged output. The GUI reads `preserved_from_previous_runs` from the report, shows those rows as "rows left from a previous run", and does not count them as successes of this run |

### Loading Existing Results

Both a folder that is itself `<out>\<evidence_id>` and an `<out>` containing several `<evidence_id>` folders can be opened
(`find_result_dirs`). Existing results are **only read**.

## Forensic Safety

- The evidence image is **only read**. It is never copied, converted, renamed or deleted
  (input validation reads only the first 8 bytes to check the E01 signature).
- New files are created only in the result folder. The only extra file the GUI writes is `case_info.json`;
  Runner outputs (`timeline.csv`, `recovered_conversations.csv`, `unified.db`,
  `integration_report.json`, `evidence_manifest.json`) are never rewritten.
- CSV headers (including trailing spaces) and values are not changed. Only the table column names are tidied for display.
- Values the Runner does not provide (progress %, automatic service detection results, artifact classification) are not made up;
  they are shown as `-` or indeterminate.

## Current Limitations

- The integration Runner has **no automatic service detection** → only Run All / Manual Selection are provided.
- The Runner does not report a progress ratio → the current step text + an indeterminate bar instead of a percentage.
- Input accepts **image files only** (`-i`). The Runner does not support artifact folder input.
- Export is limited to **결과 폴더 열기** (open result folder) and per-value **복사** (copy to clipboard) in the details panel.
  There is no feature to re-save as CSV/XLSX/HTML/PDF — the original CSVs remain in the result folder.
- **근거 파일 위치 열기** (open evidence file location) is enabled only when the path actually exists on this PC
  (most Artifact Paths are paths inside the image, so being disabled is normal).
