# Validate and import a Portmaster settings file (merge). Use -Reset to replace all settings.
param(
    [Parameter(Mandatory = $true)][string]$File,
    [string]$CorePath = "$env:ProgramFiles\Portmaster\portmaster-core.exe",
    [switch]$Reset
)

if (-not (Test-Path -LiteralPath $CorePath)) {
    Write-Error "portmaster-core not found at $CorePath"
    exit 3
}
if (-not (Test-Path -LiteralPath $File)) {
    Write-Error "settings file not found: $File"
    exit 2
}

& "$CorePath" settings import "$File" --validate
if ($LASTEXITCODE -ne 0) {
    Write-Error "validation failed, nothing imported"
    exit $LASTEXITCODE
}

if ($Reset) {
    & "$CorePath" settings import "$File" --reset
} else {
    & "$CorePath" settings import "$File"
}
exit $LASTEXITCODE
