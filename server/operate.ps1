param([Parameter(Mandatory=$true)][string]$DataDirectory,
      [ValidateSet('start','stop','status')][string]$Action='status',
      [string]$PythonExecutable='')
$ErrorActionPreference='Stop'
$dataPath=[IO.Path]::GetFullPath($DataDirectory)
$pythonPath=if($PythonExecutable) { [IO.Path]::GetFullPath($PythonExecutable) } else { Join-Path $PSScriptRoot '.venv/Scripts/python.exe' }
$supervisorPath=Join-Path $PSScriptRoot 'supervisor.py'
$runtimePath=Join-Path $dataPath 'runtime'
$currentPath=Join-Path $runtimePath 'current.json'
function Read-OwnedState {
    if (-not (Test-Path -LiteralPath $currentPath)) { return $null }
    $state=Get-Content -LiteralPath $currentPath -Raw | ConvertFrom-Json
    if ($state.token -notmatch '^[a-f0-9]{32}$') { throw 'Invalid runtime state' }
    if ($state.state -ne 'running') { return $null }
    $process=Get-CimInstance Win32_Process -Filter "ProcessId = $($state.pid)"
    if ($null -eq $process) { return $null }
    if ([string]::IsNullOrWhiteSpace($process.CommandLine)) {
        # The supervisor can exit after the process query, while stop is polling.
        $latest=Get-Content -LiteralPath $currentPath -Raw | ConvertFrom-Json
        if ($latest.token -eq $state.token -and $latest.state -ne 'running') { return $null }
        if ($null -eq (Get-CimInstance Win32_Process -Filter "ProcessId = $($state.pid)")) { return $null }
        throw 'Cannot verify runtime identity; no process will be stopped. Check retained runtime logs.'
    }
    if (-not ($process.CommandLine.Contains($supervisorPath) -and $process.CommandLine.Contains($dataPath))) {
        throw 'Runtime identity does not match this service; no process will be stopped'
    }
    return $state
}
$owned=Read-OwnedState
if ($Action -eq 'status') {
    if ($null -eq $owned) {
        'Not running. Check retained runtime logs.'
        if(Test-Path -LiteralPath $currentPath) { Get-Content -LiteralPath $currentPath -Raw }
    }
    else { $owned | Select-Object state,pid,children,restart_counts,updated_at }
    return
}
if ($Action -eq 'stop') {
    if ($null -eq $owned) { 'No running owned supervisor found.'; return }
    $stopPath=Join-Path $runtimePath "stop-$($owned.token).request"
    if (-not (Test-Path -LiteralPath $stopPath)) { [IO.File]::WriteAllText($stopPath,'Operator requested stop') }
    for ($attempt=0;$attempt -lt 25;$attempt++) {
        Start-Sleep -Milliseconds 500
        if ($null -eq (Read-OwnedState)) { 'Owned app and worker stopped. MySQL, data, and logs retained.'; return }
    }
    throw 'Stop is still pending. Check runtime logs; do not stop unrelated processes.'
}
if ($null -ne $owned) { 'Already running.'; return }
if (-not (Test-Path -LiteralPath $pythonPath)) { throw 'Install the dependencies first; see docs/ガイド.md' }
& $pythonPath (Join-Path $PSScriptRoot 'manage.py') --home $dataPath status
if ($LASTEXITCODE -ne 0) { throw 'Service validation failed' }
if ($dataPath.Contains('"') -or $supervisorPath.Contains('"')) { throw 'Unsupported quote in path' }
[IO.Directory]::CreateDirectory($runtimePath) | Out-Null
$runId=[guid]::NewGuid().ToString('N')
$arguments='"'+$supervisorPath+'" --home "'+$dataPath+'"'
$started=Start-Process -FilePath $pythonPath -ArgumentList $arguments -WindowStyle Hidden -PassThru -RedirectStandardOutput (Join-Path $runtimePath "launcher-$runId.log") -RedirectStandardError (Join-Path $runtimePath "launcher-$runId-error.log")
for ($attempt=0;$attempt -lt 20;$attempt++) {
    Start-Sleep -Milliseconds 500
    if ($null -ne (Read-OwnedState)) { 'App and worker started together. Local-only operation; logs retained.'; return }
    if ($started.HasExited) { throw 'Startup failed. Check retained launcher logs.' }
}
throw 'Startup has not completed. Check status and retained launcher logs before retrying.'
