param(
    [switch]$Persist
)

$ErrorActionPreference = "Stop"

$repoRoot = (Resolve-Path (Join-Path $PSScriptRoot "..")).Path
$venvScripts = Join-Path $repoRoot ".venv\Scripts"

if (-not (Test-Path $venvScripts)) {
    throw "Missing virtual environment at '$venvScripts'. Create it first (python -m venv .venv)."
}

if (-not ($env:PATH -split ';' | Where-Object { $_ -eq $venvScripts })) {
    $env:PATH = "$venvScripts;$env:PATH"
}

Write-Host "CASIC commands enabled for current shell: cansic, udsic, j1939sic, cosic"
Write-Host "Try: cansic -h"

if ($Persist) {
    $userPath = [Environment]::GetEnvironmentVariable("Path", "User")
    $parts = @()
    if ($userPath) {
        $parts = $userPath -split ';'
    }

    if (-not ($parts | Where-Object { $_ -eq $venvScripts })) {
        $newPath = if ([string]::IsNullOrWhiteSpace($userPath)) { $venvScripts } else { "$venvScripts;$userPath" }
        [Environment]::SetEnvironmentVariable("Path", $newPath, "User")
        Write-Host "Persisted .venv Scripts path to User PATH. Open a new terminal to use commands globally."
    }
    else {
        Write-Host "User PATH already contains .venv Scripts path."
    }
}
