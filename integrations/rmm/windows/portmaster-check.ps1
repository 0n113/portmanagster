# Portmaster health check wrapper. Exit: 0 OK, 1 WARNING, 2 CRITICAL, 3 UNKNOWN.
param(
    [string]$CorePath = "$env:ProgramFiles\Portmaster\portmaster-core.exe",
    [string]$MaxIntelAge = "336h"
)

if (-not (Test-Path -LiteralPath $CorePath)) {
    Write-Output "UNKNOWN - portmaster-core not found at $CorePath"
    exit 3
}

& "$CorePath" status --check --max-intel-age $MaxIntelAge
exit $LASTEXITCODE
