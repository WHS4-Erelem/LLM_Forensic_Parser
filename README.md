# ARTINEX

[English](README.md) · [한국어](README.ko.md)

A set of forensic parsers that find traces of six LLM services in Windows disk images (E01 / raw) and extract
a **user behavior timeline** and **recovered conversations**, plus the ARTINEX integration runner that runs all six at once.
ARTINEX provides a command-line integration runner, a GUI, and an Autopsy add-on.
ARTINEX is the name of the whole integrated parser (repository: `LLM_Forensic_Parser`).

Deliverable of the WHS4 team project "LLM Conversation Extraction and User Behavior Analysis".

## Components

| Folder | Target | Entry point | Runtime |
|---|---|---|---|
| `ChatGPT_APP_Parser` | ChatGPT / Codex desktop app (MS Store `OpenAI.Codex`) | `run_parser.py` | Python 3.12 · pytsk3 · libewf-python |
| `ChatGPT_Web_Parser` | chatgpt.com (Chrome) | `python -m chatgpt_parser.cli` | Python 3.12 · pytsk3 · brotli · cramjam |
| `Claude_APP_Parser` | Claude desktop app | `run_parser.py` | Python 3.12 · pytsk3 · libewf-python · ccl-chromium-reader · zstandard |
| `Claude_Web_Parser` | claude.ai (Chrome) | `python -m claude_web_forensics` | Python 3.12 · dissect · ccl-chromium-reader |
| `Gemini_Web_Parser` | gemini.google.com (Chrome) | `gemini_parser.py` | Python 3.10+ · pytsk3 · libewf-python |
| `LMstudio_parser` | LM Studio (local LLM) | `lmstudio_parser.py` | Python 3.12 · dissect |
| [`integration`](integration/README.md) | ARTINEX integration runner : runs, validates and merges the six parsers above in order | `llm_forensic.py` | Standard library only (parsers use the shared `.venv312`) |
| [`gui`](gui/README.md) | ARTINEX GUI : select input, run analysis, and inspect results | `main.py` | Shared Python 3.12 environment · PyQt6 |
| [`Autopsy_Addon`](Autopsy_Addon/README.md) | Autopsy add-on : run parsers and register results in Autopsy | `setup.ps1` (installation) | Tested on Autopsy 4.23.1 · external Python 3.12 |

Detailed usage and detection rules for each parser are in the README of its folder.

## Download and Setup Preparation

Autopsy users should download and fully extract the Autopsy distribution ZIP from [Releases](https://github.com/WHS4-Erelem/LLM_Forensic_Parser/releases), following the instructions for that version. For source development, download or clone the repository. Start the commands below from the distribution or repository root containing `integration` and `Autopsy_Addon`.

- [Repository](https://github.com/WHS4-Erelem/LLM_Forensic_Parser)
- [Releases](https://github.com/WHS4-Erelem/LLM_Forensic_Parser/releases) : Autopsy distribution packages and version-specific installation instructions.

The installation instructions use Windows PowerShell. Initial setup requires network access to download uv, Python, and dependencies. The setup script prepares a Python 3.12 virtual environment.

## Common Output Contract

Every parser produces the same two CSV files. The integration runner does not load results that violate this contract.

- `timeline.csv`, 7 columns: `Model, Timestamp, User_behavior, Behavior_details, Verdict, Artifact_path, Artifact_details`
- `recovered_conversations.csv`, 10 columns: `Model, timestamp, conversation_uuid, conversation_title, message_uuid, parent_message_uuid, message order, role, content, Artifact_path`
- `Verdict` is `확정` (confirmed) or `의심` (suspected), timestamps are `YYYY-MM-DD HH:MM:SS.ffffff KST`, and empty values are `-`
- `User_behavior` uses only names from the team behavior taxonomy `integration/user_behaviors.txt` (without the service name). The integration runner reports names outside the list as warnings

## Quick Start (ARTINEX integration run)

`setup.ps1` installs [uv](https://docs.astral.sh/uv/) first with WinGet (`astral-sh.uv`) if it is missing, then creates `.venv312`, shared by the six parsers and the GUI (PyQt6).

```powershell
cd integration
powershell -ExecutionPolicy Bypass -File setup.ps1

# Command-line analysis (replace the input path with your evidence image)
.\.venv312\Scripts\python.exe llm_forensic.py -i "D:\Evidence\sample.E01" -o out

# GUI
.\.venv312\Scripts\python.exe ..\gui\main.py
```

> Note: If security software such as AhnLab Safe Transaction blocks setup, open a new PowerShell window, check `uv --version`, and rerun `setup.ps1`. If uv is missing, or WinGet is not available, install uv using the [official instructions](https://docs.astral.sh/uv/getting-started/installation/) first.

Results are written to `out\<evidence_id>\`: merged `timeline.csv` · `recovered_conversations.csv` · `unified.db` (SQLite) ·
`evidence_manifest.json` (SHA-256 per segment) · `integration_report.json` (status and errors per parser) · each parser's original result folder.
Exit codes: 0 all succeeded / 1 some parsers failed or violated the contract / 2 input failure / 3 integration DB or output error. For details, see the [integration runner guide](integration/README.md) and the [GUI guide](gui/README.md).

## Autopsy Add-on

Add an evidence image to Autopsy and run the ARTINEX ingest module to inspect reconstructed user behaviors and recovered conversations in Autopsy. The tested environment is Windows 11 with Autopsy 4.23.1.

Download and fully extract the **Autopsy distribution ZIP** from [Releases](https://github.com/WHS4-Erelem/LLM_Forensic_Parser/releases). Keep `Autopsy_Addon`, `integration`, and all six parser folders together. The add-on runs the parsers from this folder as external Python processes. Do not move or delete the distribution folder after installation. If you move it, run the setup script again.

Close Autopsy and run the following from the extracted distribution root:

```powershell
# English results (default)
powershell -ExecutionPolicy Bypass -File .\Autopsy_Addon\setup.ps1

# Korean results
powershell -ExecutionPolicy Bypass -File .\Autopsy_Addon\setup.ps1 -Language ko
```

The add-on shows results in **English by default**; `-Language ko` selects Korean, and any other value stops setup with an error. With the English setting, behavior names, verdicts, the fixed parser phrases in behavior details, the labels and fixed phrases in evidence details, Timeline descriptions and add-on notices are shown in English. Conversation content, titles, prompts, file names, paths, IDs, times and other evidence values stay exactly as recovered (Korean evidence stays Korean), and the parsers' CSV and JSON files are not modified. See [Display Language](Autopsy_Addon/README.md#display-language) for the full list and the limits.

Restart Autopsy and select **ARTINEX** in the ingest module list. For detailed installation instructions, result locations, and limitations, see the [English guide](Autopsy_Addon/README.md) or [Korean guide](Autopsy_Addon/README.ko.md).

## Development Validation

Run this only when an answer key is available. It is not required for normal analysis. Run the command from `integration` and replace `<evidence_id>` with the actual result folder name.

```powershell
.\.venv312\Scripts\python.exe validation\verify_merged.py --timeline "out\<evidence_id>\timeline.csv" --key validation\scenario_keys\plain_2026-09-15.csv
```

## License

The code written for ARTINEX (the six parsers, the integration runner, the GUI and the Autopsy add-on) is licensed under **AGPL-3.0-or-later** (GNU Affero General Public License v3.0 or later).
Copyright (C) 2026 WHS4-Erelem contributors. The full license text is in [`LICENSE`](LICENSE).

External libraries installed by `setup.ps1` (pytsk3, libewf-python, dissect.*, ccl_chromium_reader, PyQt6, etc.) are not part of ARTINEX and remain under their own licenses and copyright notices.
