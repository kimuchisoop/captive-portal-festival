param([string]$Python='python',[switch]$Online)
$ErrorActionPreference='Stop'
& $Python -c "import sys,platform; raise SystemExit(0 if sys.implementation.name=='cpython' and sys.version_info[:2]==(3,12) and platform.system()=='Windows' and platform.machine().upper()=='AMD64' else 1)"
if ($LASTEXITCODE -ne 0) { throw 'This offline distribution requires CPython 3.12 / Windows x64. Python itself is not included.' }
& $Python (Join-Path $PSScriptRoot 'verify_package.py')
if ($LASTEXITCODE -ne 0) { throw 'Package verification failed.' }
$venvPath=Join-Path $PSScriptRoot '.venv'
if (-not (Test-Path -LiteralPath $venvPath)) {
    & $Python -m venv $venvPath
    if ($LASTEXITCODE -ne 0) { throw 'Virtual environment creation failed.' }
}
$runtime=Join-Path $venvPath 'Scripts/python.exe'
$pipArgs=@('-m','pip','--isolated','--disable-pip-version-check','install','--require-hashes','--only-binary=:all:','-r',(Join-Path $PSScriptRoot 'requirements.lock'))
if ($Online) { $pipArgs+=@('--index-url','https://pypi.org/simple') }
else { $pipArgs+=@('--no-index','--find-links',(Join-Path $PSScriptRoot 'wheelhouse')) }
& $runtime @pipArgs
if ($LASTEXITCODE -ne 0) { throw 'Hashed dependency installation failed. Nothing was deleted.' }
& $runtime -m pip check
if ($LASTEXITCODE -ne 0) { throw 'Installed dependencies are inconsistent.' }
'Dependencies installed with hash verification. Data and logs were not changed.'
