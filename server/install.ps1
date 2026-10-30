param(
    [string]$Python = 'python',
    [Parameter(Mandatory = $true)][string]$DataDirectory,
    [Parameter(Mandatory = $true)][string]$MySqlConfig,
    [Parameter(Mandatory = $true)][string]$MaintenanceMySqlConfig,
    [switch]$SamplePolicy,
    [switch]$Online
)
$ErrorActionPreference = 'Stop'
$packageRoot = $PSScriptRoot
$dataPath = [System.IO.Path]::GetFullPath($DataDirectory)
if (Test-Path -LiteralPath $dataPath) { throw 'DataDirectory already exists. Use a NEW data directory.' }
& (Join-Path $packageRoot 'install-dependencies.ps1') -Python $Python -Online:$Online
$venvPath = Join-Path $packageRoot '.venv'
$pythonPath = Join-Path $venvPath 'Scripts/python.exe'
$initArgs = @((Join-Path $packageRoot 'manage.py'), '--home', $dataPath, 'init', '--db-config', (Resolve-Path -LiteralPath $MySqlConfig).Path, '--maintenance-db-config', (Resolve-Path -LiteralPath $MaintenanceMySqlConfig).Path)
if ($SamplePolicy) { $initArgs += '--sample-policy' }
& $pythonPath @initArgs
if ($LASTEXITCODE -ne 0) { throw 'Initialization failed. Do not reuse a partially initialized directory.' }
Write-Output 'Local service installed. See README.md to create an administrator and start the service.'
