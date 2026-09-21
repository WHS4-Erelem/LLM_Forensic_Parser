# 파서 실행 환경 2개를 만든다 (uv 필요: https://docs.astral.sh/uv/)
#   .venv312  ChatGPT Desktop · ChatGPT Web · Claude Desktop · Gemini · Claude Web
#             (pytsk3 + libewf-python 은 3.12 휠까지만 있음. Claude Web 의 zstd 도 3.14 에선 MSVC 빌드가 필요해 3.12 로)
#   .venv314  LM Studio (dissect 스택, 3.14 검증)
# 사용: powershell -ExecutionPolicy Bypass -File setup.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

uv venv --python 3.12 .venv312
uv pip install --python .venv312\Scripts\python.exe pytsk3==20260715 libewf-python==20240506 brotli==1.2.0 cramjam==2.12.1
uv pip install --python .venv312\Scripts\python.exe -r ..\Claude_Web_Parser\requirements.lock

uv venv --python 3.14 .venv314
uv pip install --python .venv314\Scripts\python.exe dissect.evidence==3.13 dissect.ntfs==3.16 dissect.volume==3.18

.venv312\Scripts\python.exe -c "import pytsk3, pyewf; print('venv312 ok')"
.venv314\Scripts\python.exe -c "import dissect.evidence, dissect.ntfs; print('venv314 ok')"
