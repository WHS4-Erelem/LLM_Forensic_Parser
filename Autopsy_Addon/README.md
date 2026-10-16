# ARTINEX : LLM Usage Artifacts Ingest Module for Autopsy

[English](README.md) · [한국어](README.ko.md)

- __Description:__ Runs the ARTINEX forensic parsers for six LLM services (ChatGPT Desktop, ChatGPT Web, Claude Desktop, Claude Web, Gemini Web, LM Studio) on a Windows disk image inside Autopsy, and posts the reconstructed user behaviors and recovered conversations to the Blackboard, Timeline and Reports.
- __Author:__ WHS4-Erelem
- __Tested Autopsy version:__ 4.23.1 (other versions have not been tested)
- __Module Location:__ https://github.com/WHS4-Erelem/LLM_Forensic_Parser (module folder `Autopsy_Addon/ARTINEX/`; the module needs the complete distribution package, see Installation)
- __Website:__ https://github.com/WHS4-Erelem/LLM_Forensic_Parser
- __Source Code:__ https://github.com/WHS4-Erelem/LLM_Forensic_Parser
- __License:__ AGPL-3.0-or-later (see [`LICENSE`](../LICENSE))

## Overview

ARTINEX is a digital forensics project that reconstructs how a person used LLM services on a Windows PC. It consists of six independent CPython parsers, an integration runner, and this Autopsy add-on.

The add-on is a thin adapter. Autopsy opens the image and parses the file system; the add-on exports only the files each parser reads into a temporary folder that mirrors the volume root, runs each parser as a separate Python 3.12 process, checks the CSV output contract, and posts the rows to Autopsy.

```
Disk image -> Autopsy / TSK -> ARTINEX module -> per-volume export folder -> 6 ARTINEX parsers (folder input mode)
                                              -> timeline.csv / recovered_conversations.csv -> contract check -> Blackboard, Timeline, Reports
```

Autopsy's Python is Jython 2.7, so the parsers are not imported; they run as external processes from a dedicated virtual environment.

## Features

- One Data Source Ingest Module, **ARTINEX**, runs all six parsers. No other Autopsy module is required.
- Exports only the files, folders and NTFS metadata (`$MFT`, `$Extend/$UsnJrnl:$J`, `Zone.Identifier` streams) that each parser reads. Exported copies keep the original modification time.
- Runs each parser only on volumes where it has input, and separately per volume.
- Checks every CSV for the shared output contract (header, column count, timestamp format, verdict, empty cells) before posting. A parser that violates it is reported as failed and its rows are not posted.
- Links each row to the source file in the image when it can be identified unambiguously; otherwise links it to the data source and records why in `link_notes.txt`.
- Isolates failures: if one parser fails, times out or produces no output, the other parsers still run.
- Avoids duplicate rows when the module is run again on the same data source.
- Writes per-parser and per-volume status to the Ingest Inbox, including incomplete input (files that could not be exported or exceeded a limit).
- Shows results in English by default. Korean can be selected at installation (see [Display Language](#display-language)). The parsers' original output files are never modified.

## System Requirements

| Item | Requirement |
|---|---|
| Operating system | Windows (tested on Windows 11). Some parsers read Windows Prefetch and NTFS alternate data streams. |
| Autopsy | 4.23.1 (tested). Other versions have not been tested. |
| Distribution package | The complete Autopsy distribution ZIP from [Releases](https://github.com/WHS4-Erelem/LLM_Forensic_Parser/releases). Requires `Autopsy_Addon`, `integration`, and all six parser folders. |
| Python | A dedicated Python 3.12 virtual environment at `integration\.venv312`, created by the setup script. Some parser dependencies (pytsk3, libewf-python) only provide Windows wheels up to Python 3.12. |
| uv | Used by the setup script to create the environment. If uv is missing, the script installs it with WinGet (`astral-sh.uv`). If WinGet is not available or the install fails, setup stops; install uv yourself ([official instructions](https://docs.astral.sh/uv/getting-started/installation/)) and run setup again. |
| Network | Required during setup to download uv, Python 3.12 and packages. Not required during analysis. |
| Disk space | The add-on exports the files the parsers read into a work folder (by default inside the case folder). The folder must be on NTFS, because `Zone.Identifier` streams are passed as real alternate data streams. |

## Installation

1. Open [Releases](https://github.com/WHS4-Erelem/LLM_Forensic_Parser/releases), read the instructions for your chosen version, and download the **Autopsy distribution ZIP**. Extract the entire archive to a permanent location. The folder containing `Autopsy_Addon`, `integration`, and all six parser folders is the distribution root. Do not extract only the `ARTINEX` module folder.

2. Close Autopsy, then run the setup script from PowerShell:

   ```powershell
   # Run from the extracted distribution root.
   # English results (default)
   powershell -ExecutionPolicy Bypass -File .\Autopsy_Addon\setup.ps1

   # Korean results
   powershell -ExecutionPolicy Bypass -File .\Autopsy_Addon\setup.ps1 -Language ko
   ```

   `-Language` accepts `en` (default) or `ko`. Any other value stops the script with an error before anything is installed. To change the language later, run the script again with the other value.

   The script:
   1. Checks that the six parser entry points exist in the repository.
   2. Checks the dedicated virtual environment `integration\.venv312` (must be a virtual environment, Python 3.12, and able to import the main parser dependencies).
      - If the check passes, the environment is reused without reinstalling.
      - If it is missing, the script runs `integration\setup.ps1`, which installs uv with WinGet when needed and creates the environment.
      - If it exists but fails the check (wrong Python version, broken interpreter, missing packages), the script deletes only this repository's `integration\.venv312` and recreates it. It stops without installing if the path is unexpected, is a junction or link, or cannot be deleted.
      - After preparation it checks both the exit code and the environment again, and stops without installing if either fails.
   3. Finds the Autopsy Python plugin folder (`python_modules`) from the installed Autopsy configuration, and asks only if it finds none or several. You can pass it directly with `-PluginDir <python_modules folder>`.
   4. Prepares the fallback work location (`C:\artinex_work` by default) and tests that it can hold files and alternate data streams.
   5. Copies the module to `<python_modules>\ARTINEX` and writes `artinex_config.json` with the absolute paths of the Python interpreter and the repository and the selected display language. Other existing settings in that file (`work_dir`, `keep_export`, and so on) are kept; `language` is always set to the value of this run.

3. Start Autopsy. **ARTINEX** appears in the ingest module list.

The module runs the parsers from the extracted distribution folder in place. Do not move or delete that folder after installation. If you move it, run the setup script again.

Configuration file: `<python_modules>\ARTINEX\artinex_config.json`

| Key | Meaning |
|---|---|
| `python` | Absolute path of `integration\.venv312\Scripts\python.exe` (set by the setup script) |
| `repo_root` | Absolute path of the repository (set by the setup script) |
| `work_dir` | Optional fallback work location, used only when the case folder cannot be used |
| `keep_export` | Optional. `true` keeps the exported files after a successful run |
| `language` | Display language of the results: `en` or `ko` (set by the setup script). Missing or any other value means `en` |

The environment variables `ARTINEX_PYTHON`, `ARTINEX_REPO_ROOT` and `ARTINEX_WORK_DIR` override these values.

## Usage in Autopsy

1. Create a case and add a disk image as a data source.
2. In the ingest module selection, enable **ARTINEX**. Other modules are not needed for ARTINEX.
3. When ingest finishes, review the results:

| Location | Content |
|---|---|
| Data Artifacts → **LLM User Behavior (ARTINEX)** | One artifact per row of each parser's `timeline.csv` |
| Data Artifacts → **Messages** | Recovered conversation messages from `recovered_conversations.csv` |
| **Timeline** | Behaviors with a timestamp, described as `[<parser>] <behavior> (<verdict>): <details>` in the display language, and the messages |
| **Reports** | Each parser's `timeline.csv`, `recovered_conversations.csv` and parser JSON output (`cx_result.json`, `result.json`, `gemini_results.json`), unchanged. With the English setting, also `timeline_en.csv`, an English display copy of `timeline.csv` |
| **Ingest Inbox** | One status line per parser and volume |

Ingest Inbox status lines:

| Status | Meaning |
|---|---|
| `N behaviors, M messages (ran on …)` | The parser ran and its rows were posted. The parentheses show what input made it run. |
| `not run (no input it reads)` | No input for this parser was found on that volume. This does not mean the behavior did not happen. |
| `no artifacts` | The parser ran and found no traces. |
| `failed (exit N, see run.log)`, `output missing`, `CSV contract violation (…)` | Only this parser failed. The other parsers continue. |
| `[incomplete input: N not exported …]` | Some input for this parser could not be exported or exceeded a limit; see `export_skipped.txt`. |
| `(N linked to data source, see link_notes.txt)` | Rows whose source file could not be identified unambiguously. |
| `Cancelled …` | Ingest was cancelled. Parsers after this point were not run. |

Work location: for each run the module first tries `<case folder>\ModuleOutput\ARTINEX`. If files or alternate data streams cannot be written there (for example a case on an exFAT drive), it uses the fallback work location. If neither works, it stops and reports both reasons in the Ingest Inbox and the Autopsy log.

Each run creates `<work location>\<case>_ds_<id>\<run time>\`. Exported files are deleted after a successful run; results, `run.log` (with the exact command line) and `export_skipped.txt` are kept. Exported files are also kept when a parser failed or input was incomplete.

Running the module again on the same data source does not post rows that are already present. Rows whose values changed are added as new artifacts; earlier artifacts are not deleted.

Each parser has a time limit of one hour per volume. When it is reached, the process is terminated and the parser is reported as failed.

## Supported LLM Services and Artifacts

| Service | Parser | Main artifacts read |
|---|---|---|
| ChatGPT Desktop (OpenAI Codex app, Microsoft Store package) | ChatGPT_APP_Parser 0.3.31 | `.codex` session files and SQLite databases, app web cache, Sentry scope file, Prefetch, Recent shortcuts, package folder times, USN journal |
| ChatGPT Web (Chrome) | ChatGPT_Web_Parser 0.2.0 | Chrome History, Cache, Local Storage, Session Storage, Sessions, Preferences, shared_proto_db |
| Claude Desktop | Claude_APP_Parser 1.5.0 | Claude app cache, IndexedDB, Local/Session Storage, settings JSON, app logs, Prefetch, package manifest, `$MFT`, USN journal, deleted files visible to Autopsy |
| Claude Web (Chrome) | Claude_Web_Parser 1.0.0 | Chrome History, Cache, Cookies, Local Storage, IndexedDB, Sessions, downloaded files with `Zone.Identifier`, `$MFT` |
| Gemini Web (Chrome) | Gemini_Web_Parser 1.4.8.6 | Chrome History, Cache, Cookies, Preferences, Local/Session Storage, IndexedDB, Service Worker, downloaded files with `Zone.Identifier`, Recycle Bin |
| LM Studio | LMstudio_parser (reference app version 0.4.21 Build 2) | `.lmstudio` folder, program and updater folders, Start Menu shortcuts, Prefetch, related files in Downloads/Desktop/Documents/Recycle Bin, `$MFT`, USN journal |

Web parsers analyze Google Chrome profiles only. The add-on uses each parser's default analysis options, matching the integration runner; it does not enable Claude Web's `--extended-fs` option. Claude Web therefore receives `$MFT` and downloaded files with `Zone.Identifier`, but not the USN journal or Recycle Bin inputs used by that option. Other parsers receive those artifacts when their default analysis requires them.

## Analysis Output

**The parsers write CSV column names in English and behavior names, verdicts and detail texts in Korean.** The parser files are kept exactly as written. What Autopsy shows depends on the display language (see [Display Language](#display-language)).

`timeline.csv` (one row per user behavior):

| Column | Content |
|---|---|
| `Model` | Service (for example `chatgpt-desktop`) |
| `Timestamp` | `YYYY-MM-DD HH:MM:SS.ffffff KST`, or `-` when unknown |
| `User_behavior` | Behavior name in Korean (list below). Shown in English with the English setting |
| `Behavior_details` | `<kind of trace>_<key content>` in Korean. With the English setting the `<kind of trace>` part is shown in English |
| `Verdict` | `확정` (confirmed) or `의심` (suspected). Shown as `Confirmed` / `Suspected` with the English setting |
| `Artifact_path` | Path of the evidence file(s), as written by the parser |
| `Artifact_details` | Evidence details (record IDs, MFT numbers, and so on) |

`recovered_conversations.csv` (one row per recovered message): `Model`, `timestamp`, `conversation_uuid`, `conversation_title`, `message_uuid`, `parent_message_uuid`, `message order`, `role`, `content`, `Artifact_path`.

In Autopsy, the timeline columns become attributes of the **LLM User Behavior (ARTINEX)** artifact (Timestamp (KST), LLM Service, User Behavior, Behavior Details, Verdict, Artifact Path, Artifact Details). Messages become **Messages** artifacts: the message type is the parser name, the thread ID is the conversation UUID, the subject is the conversation title, and user messages are marked as outgoing.

Behavior names used in `User_behavior` (Korean parser value : English display value):

| Korean value | English display | Korean value | English display |
|---|---|---|---|
| 로그인 | Login | 사용자 프롬프트 입력/전송 | User prompt input/send |
| 로그아웃 | Logout | 사용자 프롬프트 삭제 | User prompt deleted |
| 계정 전환 | Account switch | 임시 채팅 사용 | Temporary chat used |
| 계정 이름 변경 | Account name change | 이미지 업로드 / 이미지 업로드 삭제 | Image upload / Image upload deleted |
| 애플리케이션 설치 | Application install | 문서 업로드 / 문서 업로드 삭제 | Document upload / Document upload deleted |
| 애플리케이션 실행 | Application launch | 문서 다운로드 | Document download |
| 애플리케이션 삭제 | Application uninstall | 이미지 생성 요청 | Image generation request |
| 정상 종료 | Normal exit | 생성 이미지 다운로드 / 생성 이미지 다운로드 삭제 | Generated image download / Generated image download deleted |
| 강제 종료 | Forced exit | 모델 변경 | Model change |
| 새로운 대화 생성 | New conversation created | 모델 다운로드 내역 | Model download history |
| 기존 대화 삭제 | Conversation deleted | 브라우저 시크릿 모드 | Browser incognito mode |
| 대화 수정 | Conversation edited | 방문기록 삭제 | Browsing history deleted |
| 대화 재시도 | Conversation retried | 캐시 삭제 | Cache deleted |
| 대화 공유 / 공유 링크 생성 | Conversation shared / Share link created | 대화 데이터 Export | Conversation data export |

## Display Language

The add-on shows results in **English by default**. Korean is selected at installation with `-Language ko`; running the setup script without the option, or with `-Language en`, selects English. The value is stored as `language` in `artinex_config.json`. If the value is missing or is not `en` or `ko`, the module uses English.

> **Note:** English is the default only for the text the add-on and parsers generate (behavior names, verdicts, labels and fixed phrases). Values recovered from the evidence are shown exactly as they were found and are **not translated**, so they may not be in English: conversation content, prompts, conversation titles, file names, paths, page titles and similar values appear in the language the user originally used (for example Korean).

```powershell
# English (default)
powershell -ExecutionPolicy Bypass -File .\Autopsy_Addon\setup.ps1
# Korean
powershell -ExecutionPolicy Bypass -File .\Autopsy_Addon\setup.ps1 -Language ko
```

Run the script with Autopsy closed, as in [Installation](#installation). The setting applies to ingest runs started afterwards.

**Korean setting:** the default values written by the parsers (in Korean) are shown as is.

**English setting:** translated with a fixed table built into the module (no network, no translation service, no extra library):

| Item | English setting |
|---|---|
| `User_behavior` | Translated (table above) |
| `Verdict` | `확정` → `Confirmed`, `의심` → `Suspected` |
| `Behavior_details` | The `<kind of trace>` part before `_` is translated when it is one of the fixed phrases the six parsers produce. In the `<key content>` part after `_`, only fixed labels generated by the parsers themselves are translated (for example `프로세스 … (로그 N줄)` → `process … (N log lines)`, `세션 N개` → `N session(s)`, `인증 상태 변경(로그인)` → `auth state change (login)`); the values inside them are kept |
| `Artifact_details` | Labels written by the parsers are translated (for example `유형=` → `Type=`, `대화 제목=` → `Conversation title=`, `위치=` → `Location=`, `동일 근거=3건` → `Same evidence=3`), as are fixed state/event values after those labels (for example `이벤트=삭제` → `Event=deleted`, `상태=완료` → `State=completed`), fixed summary phrases (for example `응답 데이터 확인` → `response data confirmed`) and the parsers' fixed sentence patterns (for example Claude Web `초안 … 저장 N회` → `draft … saved N times`, merge notes such as `Prefetch 실행 기록 … 와 일치` → `matches Prefetch run record …`). The values after the labels and inside the sentences are kept |
| Timeline description | Built from the translated behavior, verdict and details |
| Ingest Inbox | Status lines are in English in both settings. The incomplete-input and not-run reasons generated by the add-on (also written to `export_skipped.txt`) follow the language setting |
| Reports | The original parser files are registered unchanged. `timeline_en.csv` (same columns, the four columns above translated) is generated next to them and registered as an additional report |

**Never translated or changed** (in both settings): conversation content, conversation titles, prompts, file names, paths, URLs, UUIDs and other identifiers, MFT/record numbers, timestamps, counts and other values taken from the evidence (including the values inside `Artifact_details`), the `Model` and `Artifact_path` columns, and every column of `recovered_conversations.csv`. Korean evidence stays Korean. The parsers' `timeline.csv`, `recovered_conversations.csv` and JSON files are not modified.

Translation limits:

- A `Behavior_details` value whose `<kind of trace>` part is not in the table (for example a phrase added in a future parser version, or a parser's raw observation text used as a fallback) is shown unchanged in Korean. A behavior name outside the team list is also shown unchanged.
- In `Artifact_details`, a label, value or sentence that is not in the table stays Korean. Merge notes that the parser cut at 120 characters are translated up to the recognizable part and end with `…` (the cut-off text cannot be recovered). Linking a row to its source file in Autopsy uses the original Korean value (`MFT=`, `삭제 엔트리=True`), so the translation does not change which file a result is attached to.
- Parser redaction markers that replace evidence values (LM Studio's `[민감정보 비노출]` and `[바이너리 데이터 비노출]`) are shown as `[sensitive data redacted]` and `[binary data redacted]` with the English setting. The parser does not keep the redacted value, so it cannot be recovered.
- Running the module again on the same data source with a different language does not replace rows that are already posted; duplicate detection uses the original parser values, so the rows keep the language of the first run. Use a new case (or a new data source) to see the other language.

## Known Limitations

- **Tested environment only:** Windows 11 with Autopsy 4.23.1, using two raw (`.dd`) NTFS scenario images. E01 images, BitLocker volumes, other Autopsy versions and other operating systems have not been tested with the add-on.
- **Not a self-contained module:** the module needs the complete distribution package and the Python 3.12 environment created by the setup script. It cannot be installed by copying only the module folder.
- **Folder input mode:** the parsers receive exported files instead of the image. Compared with running the parsers directly on the image:
  - only deleted files that Autopsy lists (with a name in the directory index or MFT) are available, and only deleted files in the Claude Desktop scope are exported with content;
  - the drive letter is always shown as `C:`;
- **Temporary paths in results:** Gemini Web and LM Studio rows show the path of the temporary input folder on the analysis PC (`…\vol<fs>\in_<parser>\Users\…`) instead of the original path. The part after `in_<parser>\` is the path inside the volume. The folder is deleted after a successful run; use the Autopsy file the artifact is linked to.
- **Size limits:** `$MFT` and `$UsnJrnl:$J` larger than 1 GB each are not exported, and metadata collection in Downloads/Desktop/Documents stops at 20,000 entries. Both are reported as incomplete input for the affected parsers.
- **Time limit:** each parser run is limited to one hour per volume.

## Troubleshooting

| Problem | What to do |
|---|---|
| ARTINEX is not in the ingest module list | Restart Autopsy after running the setup script. Check that `<python_modules>\ARTINEX\ARTINEX.py` exists (Autopsy: Tools → Python Plugins opens the folder). |
| Setup stops with "parser environment preparation failed" | Read the message above it. If packages could not be downloaded, run setup again from a network that can reach PyPI and GitHub. |
| A security program (for example AhnLab Safe Transaction) blocks setup on a PC without uv | Open a **new** PowerShell window and check `uv --version`. If uv is installed, run the setup script again. If not, install uv first ([official instructions](https://docs.astral.sh/uv/getting-started/installation/)) and then run setup. |
| Setup stops with "unsupported -Language …" | Use `-Language en` or `-Language ko`, or omit the option for English. Nothing was installed or changed. |
| Results are shown in the other language | Run the setup script again with the language you want. Rows already posted to a data source keep their language (see [Display Language](#display-language)). |
| Setup stops with "could not delete … .venv312" | Close programs that use that Python (for example Autopsy or the integration runner) and run setup again. |
| Setup stops with "… is a junction or symbolic link" | Remove the junction or link yourself and run setup again. |
| A parser shows `failed (exit N, see run.log)` | Open `run.log` in that parser's result folder. Its first line is the exact command, working folder and environment. |
| `[incomplete input …]` | Open `export_skipped.txt` in the run folder. Each line gives the reason (`error`, `big`, `meta_limit`, and so on). |
| Rows linked to the data source instead of a file | See `link_notes.txt` in that parser's result folder. |
| The case is on an exFAT or network drive | If the case folder fails the write or alternate-data-stream check, the module uses the fallback work location (`C:\artinex_work`, or `work_dir` in the configuration). The reason is written to the Autopsy log (`work root …`). |
| You moved the distribution folder | Run the setup script again so that `artinex_config.json` points to the new location. |

## License and Credits

- **License:** the code written for ARTINEX (this module, the parsers and the integration runner) is licensed under the GNU Affero General Public License v3.0 or later (AGPL-3.0-or-later). Copyright (C) 2026 WHS4-Erelem contributors. The full text is in [`LICENSE`](../LICENSE).
- **Developed by:** WHS4-Erelem, project ARTINEX.
- **Source code:** https://github.com/WHS4-Erelem/LLM_Forensic_Parser
- **Built on:** [Autopsy](https://www.autopsy.com/) and The Sleuth Kit (Basis Technology).
- **Main third-party packages used by the parsers** (installed by the setup script, not part of ARTINEX; each remains under its own license and copyright notices): pytsk3, libewf-python, dissect.cstruct / util / ntfs / fve / evidence / volume, ccl_chromium_reader, ccl_simplesnappy, Brotli, cramjam, zstandard, zstd, pycryptodome. The setup script also installs PyQt6, which is used by the ARTINEX desktop GUI and not by this module.
