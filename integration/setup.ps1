# 파서 실행 환경을 만든다 (uv 필요: https://docs.astral.sh/uv/)
#   .venv312  ChatGPT Desktop · ChatGPT Web · Claude Desktop · Gemini · Claude Web · LM Studio
#             (pytsk3 + libewf-python 은 3.12 휠까지만 있음. Claude Web 의 zstd 도 3.14 에선 MSVC 빌드가 필요해 3.12 로)
# 사용: powershell -ExecutionPolicy Bypass -File setup.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

uv venv --managed-python --python 3.12 .venv312
uv pip install --python .venv312\Scripts\python.exe -r ..\ChatGPT_APP_Parser\requirements.txt
uv pip install --python .venv312\Scripts\python.exe -r ..\ChatGPT_Web_Parser\requirements.txt
uv pip install --python .venv312\Scripts\python.exe -r ..\Claude_APP_Parser\requirements.txt
uv pip install --python .venv312\Scripts\python.exe -r ..\Gemini_Web_Parser\requirements.txt
uv pip install --python .venv312\Scripts\python.exe -r ..\Claude_Web_Parser\requirements.lock
uv pip install --python .venv312\Scripts\python.exe dissect.evidence==3.13 dissect.ntfs==3.16 dissect.volume==3.18

.venv312\Scripts\python.exe -c "import pytsk3, pyewf, dissect.evidence, dissect.ntfs; print('venv312 ok')"
