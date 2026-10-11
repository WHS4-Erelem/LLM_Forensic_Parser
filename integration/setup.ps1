# 파서·GUI 실행 환경을 만든다 (uv 가 없으면 먼저 설치: https://docs.astral.sh/uv/)
#   .venv312  ChatGPT Desktop · ChatGPT Web · Claude Desktop · Gemini · Claude Web · LM Studio + GUI(PyQt6)
#             (pytsk3 + libewf-python 은 3.12 휠까지만 있음. Claude Web 의 zstd 도 3.14 에선 MSVC 빌드가 필요해 3.12 로)
# 사용: powershell -ExecutionPolicy Bypass -File setup.ps1
$ErrorActionPreference = "Stop"
Set-Location $PSScriptRoot

# 외부 명령 실패는 $ErrorActionPreference 로 멈추지 않으므로 종료 코드를 직접 본다
function Invoke-Step {
    & $args[0] $args[1..($args.Count - 1)]
    if ($LASTEXITCODE -ne 0) { throw "실패 (exit $LASTEXITCODE): $($args -join ' ')" }
}

if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
    Write-Host "uv 가 없어 설치합니다 (https://astral.sh/uv/install.ps1)"
    powershell -ExecutionPolicy ByPass -NoProfile -Command "irm https://astral.sh/uv/install.ps1 | iex"
    $env:Path = "$env:USERPROFILE\.local\bin;$env:Path"    # 설치 직후에는 이 창의 PATH 에 아직 없다
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        throw "uv 설치를 확인하지 못했습니다. https://docs.astral.sh/uv/ 안내대로 설치한 뒤 새 PowerShell 에서 다시 실행하세요."
    }
}

$py = ".venv312\Scripts\python.exe"
if (-not (Test-Path $py)) { Invoke-Step uv venv --managed-python --python 3.12 .venv312 }   # 다시 실행하면 패키지만 맞춘다
# 한 번에 풀어야 한다: Claude Desktop 의 ccl-chromium-reader==0.3.18 은 PyPI 에 없고 Gemini·Claude Web 의 git 주소로만 채워진다
Invoke-Step uv pip install --python $py `
    -r ..\ChatGPT_APP_Parser\requirements.txt `
    -r ..\ChatGPT_Web_Parser\requirements.txt `
    -r ..\Claude_APP_Parser\requirements.txt `
    -r ..\Gemini_Web_Parser\requirements.txt `
    -r ..\Claude_Web_Parser\requirements.lock `
    -r ..\gui\requirements.txt `
    dissect.evidence==3.13 dissect.ntfs==3.16 dissect.volume==3.18

Invoke-Step $py -c "import pytsk3, pyewf, dissect.evidence, dissect.ntfs, PyQt6.QtWidgets; print('venv312 ok')"
