# ARTINEX — Autopsy 애드온 설치 스크립트 (한 번 실행으로 실행 환경 준비 + 설치)
#   1. 저장소 루트·파서 진입점 확인   2. 통합파서 전용 가상환경(integration\.venv312) 검사 → 없거나 검사 실패면 기존 환경을 지우고
#      integration\setup.ps1 로 환경 생성(uv 설치 포함) → 재검사   3. Autopsy python_modules 폴더 찾기   4. 대체 작업 위치(C:\artinex_work) 준비
#   5. 모듈 복사 + artinex_config.json 갱신(기존 설정 보존, 언어는 이번 값으로)
# 사용: powershell -ExecutionPolicy Bypass -File setup.ps1 [-PluginDir <Autopsy python_modules 폴더>] [-Language en|ko]
#   -Language: Autopsy 결과 표시 언어. 생략하면 en (영어), 한국어는 ko.
#   자동으로 정할 수 없는 경로(플러그인 폴더 후보 0개·여러 개)만 묻는다.
param([string]$PluginDir, [string]$Language = "en")
$ErrorActionPreference = "Stop"
$Language = $Language.Trim().ToLowerInvariant()
if ($Language -notin @("en", "ko")) { throw "unsupported -Language '$Language' (use en or ko). Plugin not installed." }   # 아무것도 바꾸기 전에 멈춘다
$addon = $PSScriptRoot
$repo = Split-Path $addon -Parent
$module = Join-Path $addon "ARTINEX"

# 1. 파서 진입점 (ARTINEX.py 의 PARSERS 와 같은 목록)
$entries = @("ChatGPT_APP_Parser\run_parser.py", "ChatGPT_Web_Parser\chatgpt_parser\cli.py", "Claude_APP_Parser\run_parser.py",
             "Claude_Web_Parser\src\claude_web_forensics\cli.py", "Gemini_Web_Parser\gemini_parser.py", "LMstudio_parser\lmstudio_parser.py")
$missing = $entries | Where-Object { -not (Test-Path (Join-Path $repo $_)) }
if ($missing) { throw "parser entry not found under ${repo}: $($missing -join ', ')" }
Write-Host "[1/5] repo root: $repo (6 parsers found)"

# 2. Python: 통합파서와 같은 전용 가상환경 integration\.venv312 만 쓴다. 가상환경이고 3.12 이며 파서 의존성의 주요 모듈을 import 할 수 있어야 한다
#    (integration\setup.ps1 이 설치하는 패키지의 대표 모듈. requirements 의 버전까지 대조하지는 않는다). 정상이면 다시 설치하지 않는다.
$py = Join-Path $repo "integration\.venv312\Scripts\python.exe"
$check = "import sys; assert sys.prefix != sys.base_prefix, 'not a virtual environment'; " +
         "assert sys.version_info[:2] == (3, 12), 'Python %d.%d (need 3.12)' % sys.version_info[:2]; " +
         "import pytsk3, pyewf, brotli, cramjam, zstandard, Crypto, ccl_simplesnappy, dissect.ntfs, dissect.fve, dissect.evidence, dissect.volume, " +
         "ccl_chromium_reader.ccl_chromium_indexeddb"
function Test-Venv {   # 전용 가상환경을 쓸 수 있으면 $true (사유는 $script:why)
    if (-not (Test-Path $py)) { $script:why = "not found"; return $false }
    $ErrorActionPreference = "Continue"      # ImportError 등 stderr 가 스크립트를 멈추지 않게
    $out = & $py -I -X utf8 -c $check 2>&1
    if ($LASTEXITCODE -eq 0) { return $true }
    $script:why = "$($out | Select-Object -Last 1)"
    return $false
}
if (-not (Test-Venv)) {
    Write-Host "  $py : $script:why - preparing it with integration\setup.ps1"
    # integration\setup.ps1 은 .venv312 가 있으면 다시 만들지 않고 패키지만 맞춘다. Python 버전이 다르거나 손상된 환경은
    # 그대로 남으므로, 검사에 실패한 기존 환경은 먼저 지운다. 지우는 대상은 이 저장소의 integration\.venv312 하나뿐이다.
    $venv = Join-Path $repo "integration\.venv312"
    if (Test-Path -LiteralPath $venv) {
        $item = Get-Item -LiteralPath $venv -Force
        $expected = [IO.Path]::Combine([IO.Path]::GetFullPath((Join-Path $repo "integration")), ".venv312")
        if (-not $item.PSIsContainer -or $item.FullName.TrimEnd("\") -ne $expected) {
            throw "refusing to delete unexpected path: $($item.FullName) (expected $expected). Plugin not installed."
        }
        if ($item.Attributes -band [IO.FileAttributes]::ReparsePoint) {   # 정션·링크면 연결된 원본 폴더 내용까지 지워질 수 있다
            throw "$venv is a junction or symbolic link - remove it yourself, then run again. Plugin not installed."
        }
        Write-Host "  removing $venv"
        try { Remove-Item -LiteralPath $venv -Recurse -Force }
        catch { throw "could not delete $venv ($_). Close programs using it, then run again. Plugin not installed." }
        if (Test-Path -LiteralPath $venv) { throw "could not delete $venv completely. Close programs using it, then run again. Plugin not installed." }
    }
    # uv 가 없으면 integration\setup.ps1 이 공식 설치 스크립트로 먼저 설치한다
    $ErrorActionPreference = "Continue"
    & powershell -NoProfile -ExecutionPolicy Bypass -File (Join-Path $repo "integration\setup.ps1")
    $code = $LASTEXITCODE
    $ErrorActionPreference = "Stop"
    if ($code -ne 0 -or -not (Test-Venv)) {  # 종료 코드만 믿지 않고 실제 가상환경·의존성을 다시 검사
        throw "parser environment preparation failed (integration\setup.ps1 exit $code; $py : $(if ($code -eq 0) { $script:why } else { 'see above' })). Plugin not installed."
    }
}
Write-Host "[2/5] python: $py"

# 3. Autopsy Python 플러그인 폴더 (Tools > Python Plugins 가 여는 폴더 = <userdir>\python_modules).
#    설치된 Autopsy 의 etc\autopsy.conf 의 default_userdir, 없으면 %APPDATA%\autopsy 아래(깊이 2). 후보가 정확히 하나가 아닐 때만 묻는다.
if (-not $PluginDir) {
    $found = @()
    $root = Join-Path $env:APPDATA "autopsy"
    foreach ($conf in (Get-ChildItem "C:\Program Files\Autopsy-*\etc\autopsy.conf" -ErrorAction SilentlyContinue | Sort-Object FullName -Descending)) {
        $line = Select-String -Path $conf.FullName -Pattern '^default_userdir="(.+)"' | Select-Object -First 1
        if ($line) {
            $dir = Join-Path ($line.Matches[0].Groups[1].Value -replace '\$\{DEFAULT_USERDIR_ROOT\}', $root) "python_modules"
            if (Test-Path $dir) { $found += (Resolve-Path $dir).Path }
        }
    }
    if (-not $found -and (Test-Path $root)) {   # 설치된 Autopsy 설정이 가리키는 폴더가 있으면 그것이 답이다 (옛 폴더가 남아 있어도 묻지 않는다)
        $found += @(Get-ChildItem $root -Directory -Recurse -Depth 1 -Filter python_modules -ErrorAction SilentlyContinue | ForEach-Object { $_.FullName })
    }
    $found = @($found | Sort-Object -Unique)  # 항상 배열 — 후보 하나일 때 문자열이 되어 [0] 이 첫 글자가 되지 않게
    if ($found.Count -eq 1) { $PluginDir = $found[0] }
    elseif ($found.Count -gt 1) {
        for ($i = 0; $i -lt $found.Count; $i++) { Write-Host "  [$($i + 1)] $($found[$i])" }
        do { $n = Read-Host "Autopsy python_modules folder (1-$($found.Count))" } until ($n -match '^\d+$' -and [int]$n -ge 1 -and [int]$n -le $found.Count)
        $PluginDir = $found[[int]$n - 1]
    }
    else { $PluginDir = Read-Host "Autopsy python_modules folder not found. Enter the folder opened by Autopsy > Tools > Python Plugins" }
}
if (-not (Test-Path $PluginDir)) { throw "plugin folder not found: $PluginDir" }
Write-Host "[3/5] plugin folder: $PluginDir"

# 4. 대체 작업 위치 준비: 작업 위치는 Ingest 때 실제 사건의 ModuleOutput\ARTINEX 를 먼저 시험해 정한다 (설치 때는 사건 경로를 모른다).
#    여기서는 사건 폴더를 못 쓸 때의 대체 위치(기존 설정 work_dir, 없으면 C:\artinex_work)를 만들고 쓰기·ADS 를 시험만 한다 — 설정에 적지 않는다.
$dest = Join-Path $PluginDir "ARTINEX"
$cfgPath = Join-Path $dest "artinex_config.json"
$oldCfg = Join-Path $PluginDir "ERELM_LLM_Parser\erelm_config.json"   # 이름 바꾸기 전(ERELM) 설치본의 설정 — 새 설정이 없으면 옮겨 온다
$cfg = [ordered]@{}
$from = if (Test-Path $cfgPath) { $cfgPath } elseif (Test-Path $oldCfg) { $oldCfg } else { $null }
if ($from) {                                 # 기존 설정 보존 — python·repo_root·language 만 갱신한다
    try { (Get-Content $from -Raw -Encoding UTF8 | ConvertFrom-Json).psobject.Properties | ForEach-Object { $cfg[$_.Name] = $_.Value } }
    catch { throw "existing config is not valid JSON, fix or remove it: $from ($_)" }
}
function Test-Ads($dir) {
    try {
        New-Item -ItemType Directory -Force $dir | Out-Null
        $probe = Join-Path $dir "artinex_ads_probe.txt"
        Set-Content -LiteralPath $probe -Value "x"
        try { Set-Content -LiteralPath $probe -Stream "Zone.Identifier" -Value "x"; return $true }
        finally { Remove-Item -LiteralPath $probe -Force -ErrorAction SilentlyContinue }
    } catch { return $false }
}
$fallback = if ($cfg.work_dir) { $cfg.work_dir } else { "C:\artinex_work" }
if (Test-Ads $fallback) { Write-Host "[4/5] fallback work location: $fallback - writable, ADS ok" }
else { Write-Host "[4/5] fallback work location: $fallback - not writable or no ADS (used only if the case folder also fails)" -ForegroundColor Yellow }

# 5. 설치: 모듈 파일만 복사 (파서는 저장소에 그대로 두고 경로만 적는다). 이름 바꾸기 전 모듈(ERELM_*)은 같은 일을 하므로 지운다.
New-Item -ItemType Directory -Force $dest | Out-Null
Copy-Item (Join-Path $module "ARTINEX.py") $dest -Force
Get-ChildItem $dest -Filter "*.class" -ErrorAction SilentlyContinue | Remove-Item -Force
foreach ($name in "ERELM_LLM_Parser", "ERELM_ChatGPT_Desktop") {
    $old = Join-Path $PluginDir $name
    if (Test-Path $old) { Remove-Item $old -Recurse -Force; Write-Host "  removed old module $old" }
}
$cfg.python = $py
$cfg.repo_root = $repo
$cfg.language = $Language
$cfg | ConvertTo-Json | Out-File $cfgPath -Encoding utf8
Write-Host "[5/5] installed $dest"
Write-Host ""
Write-Host "  language    : $Language"
Write-Host "  python      : $py"
Write-Host "  plugin      : $dest"
Write-Host "  config      : $cfgPath"
Write-Host "  work folder : <case folder>\ModuleOutput\ARTINEX (fallback $fallback if it cannot hold files or ADS)"
Write-Host "Restart Autopsy, then select 'ARTINEX' in the ingest module list."
