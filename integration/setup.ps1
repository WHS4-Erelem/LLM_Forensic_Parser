# 파서·GUI 실행 환경을 만든다 (uv 가 없으면 WinGet 으로 먼저 설치: https://docs.astral.sh/uv/getting-started/installation/)
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
    $uvGuide = "https://docs.astral.sh/uv/getting-started/installation/ 안내대로 uv 를 설치한 뒤 새 PowerShell 에서 다시 실행하세요."
    if (-not (Get-Command winget -ErrorAction SilentlyContinue)) {
        throw "uv 가 없고 WinGet 도 없어 자동 설치할 수 없습니다. $uvGuide"
    }
    Write-Host "uv 가 없어 WinGet 으로 설치합니다 (astral-sh.uv)"
    winget install --id astral-sh.uv -e --source winget --accept-package-agreements --accept-source-agreements
    $wingetExit = $LASTEXITCODE
    # 설치 직후에는 이 창의 PATH 에 아직 없다: 레지스트리의 PATH 와 WinGet 링크 폴더를 다시 읽는다
    $env:Path = @(
        [Environment]::GetEnvironmentVariable("Path", "Machine"),
        [Environment]::GetEnvironmentVariable("Path", "User"),
        "$env:LOCALAPPDATA\Microsoft\WinGet\Links"
    ) -join ";"
    if (-not (Get-Command uv -ErrorAction SilentlyContinue)) {
        throw "WinGet 으로 uv 를 설치하지 못했습니다 (winget exit $wingetExit). $uvGuide"
    }
    if ($wingetExit -ne 0) { Write-Warning "winget exit $wingetExit 이지만 uv 를 찾았으므로 계속합니다: $((Get-Command uv).Source)" }
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
