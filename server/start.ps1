param([Parameter(Mandatory = $true)][string]$DataDirectory,
      [ValidateSet('serve','worker','run-jobs','backup','preflight','status','ap-check','diagnose-mysql')][string]$Mode = 'serve')
$ErrorActionPreference = 'Stop'
$pythonPath = Join-Path $PSScriptRoot '.venv/Scripts/python.exe'
& $pythonPath (Join-Path $PSScriptRoot 'manage.py') --home ([System.IO.Path]::GetFullPath($DataDirectory)) $Mode
if ($LASTEXITCODE -ne 0) { throw 'Service command failed. See the operation guide.' }
