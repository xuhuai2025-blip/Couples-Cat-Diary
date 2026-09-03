[CmdletBinding()]
param(
    [string]$PythonExecutable = '',
    [switch]$SkipBootstrap
)

$ErrorActionPreference = 'Stop'
Set-Location -LiteralPath $PSScriptRoot

if ($PythonExecutable) {
    $basePython = $PythonExecutable
    $launcherArgs = @()
} else {
    $pythonCommand = Get-Command python -ErrorAction SilentlyContinue
    if ($pythonCommand) {
        $basePython = $pythonCommand.Source
        $launcherArgs = @()
    } else {
        $pyCommand = Get-Command py -ErrorAction SilentlyContinue
        if (-not $pyCommand) {
            throw 'Python was not found. Install Python 3.10 or newer first.'
        }
        $basePython = $pyCommand.Source
        $launcherArgs = @('-3')
    }
}

if ($SkipBootstrap) {
    $runtimePython = $basePython
} else {
    $venvPython = Join-Path $PSScriptRoot '.venv\Scripts\python.exe'
    if (-not (Test-Path -LiteralPath $venvPython)) {
        Write-Host '[1/3] Creating a Python virtual environment...'
        & $basePython @launcherArgs -m venv '.venv'
        if ($LASTEXITCODE -ne 0) { throw 'Failed to create the virtual environment.' }
    }

    $runtimePython = $venvPython
    Write-Host '[2/3] Installing or checking dependencies...'
    & $runtimePython -m pip install --disable-pip-version-check -r 'requirements.txt'
    if ($LASTEXITCODE -ne 0) { throw 'Failed to install dependencies.' }
}

if (-not (Test-Path -LiteralPath 'diary.db')) {
    Write-Host '[3/3] Initializing the local preview database...'
    & $runtimePython 'init_db.py' `
        --user1 'preview_a' --name1 'Preview A' --pass1 'PreviewCat-A!8080' `
        --user2 'preview_b' --name2 'Preview B' --pass2 'PreviewCat-B!8080'
    if ($LASTEXITCODE -ne 0) { throw 'Failed to initialize the database.' }
} else {
    Write-Host '[3/3] diary.db already exists; keeping the existing local data.'
}

$env:HOST = '127.0.0.1'
$env:PORT = '8080'

Write-Host ''
Write-Host 'Couples Cat Diary is ready to start:'
Write-Host '  URL: http://127.0.0.1:8080/'
Write-Host '  Account A: preview_a / PreviewCat-A!8080'
Write-Host '  Account B: preview_b / PreviewCat-B!8080'
Write-Host '  Press Ctrl+C to stop the server.'
Write-Host ''

& $runtimePython 'app.py'
