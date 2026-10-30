param([string]$Python='python')
# Run on an internet-connected PC. Downloads the CPython 3.12 / Windows x64 wheels listed in
# server/requirements.lock into server/wheelhouse for install-dependencies.ps1 (offline mode).
# Hashes are enforced by pip and checked again below. Existing files are not deleted.
$ErrorActionPreference='Stop'
$server=Join-Path (Split-Path $PSScriptRoot -Parent) 'server'
$lock=Join-Path $server 'requirements.lock'
$wheelhouse=Join-Path $server 'wheelhouse'
New-Item -ItemType Directory -Force -Path $wheelhouse | Out-Null
& $Python -m pip --isolated --disable-pip-version-check download --require-hashes --only-binary=:all: --no-deps --platform win_amd64 --python-version 3.12 --implementation cp --dest $wheelhouse -r $lock
if ($LASTEXITCODE -ne 0) { throw 'Wheel download failed. Nothing was deleted.' }
$expected=@{}
foreach ($line in Get-Content -LiteralPath $lock) {
    if ($line -match '^\s*([^#=\s]+)==\S+\s+--hash=sha256:([0-9a-f]{64})') { $expected[$Matches[2]]=$Matches[1] }
}
$found=@{}
foreach ($file in Get-ChildItem -LiteralPath $wheelhouse -Filter '*.whl') {
    $hash=(Get-FileHash -Algorithm SHA256 -LiteralPath $file.FullName).Hash.ToLowerInvariant()
    if ($expected.ContainsKey($hash)) { $found[$hash]=$file.Name } else { Write-Warning "Not in requirements.lock (left in place): $($file.Name)" }
}
$missing=$expected.Keys | Where-Object { -not $found.ContainsKey($_) } | ForEach-Object { $expected[$_] }
if ($missing) { throw ('Missing or mismatched wheels: ' + ($missing -join ', ')) }
"Verified $($found.Count) wheels in $wheelhouse. Copy the whole server folder to the offline PC and run install-dependencies.ps1."
