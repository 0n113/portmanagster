# Export Portmaster settings to Dir\portmaster-settings-<host>-<date>.yaml, keep the last -Keep files.
param(
    [Parameter(Mandatory = $true)][string]$Dir,
    [string]$CorePath = "$env:ProgramFiles\Portmaster\portmaster-core.exe",
    [int]$Keep = 14
)

if (-not (Test-Path -LiteralPath $CorePath)) {
    Write-Error "portmaster-core not found at $CorePath"
    exit 3
}

New-Item -ItemType Directory -Force -Path $Dir | Out-Null
$hostName = $env:COMPUTERNAME
$out = Join-Path $Dir ("portmaster-settings-{0}-{1}.yaml" -f $hostName, (Get-Date -Format "yyyyMMdd-HHmmss"))

& "$CorePath" settings export --format yaml -o "$out"
if ($LASTEXITCODE -ne 0) {
    Remove-Item -LiteralPath $out -ErrorAction SilentlyContinue
    Write-Error "export failed"
    exit $LASTEXITCODE
}
Write-Output "wrote $out"

Get-ChildItem -LiteralPath $Dir -Filter "portmaster-settings-$hostName-*.yaml" |
    Sort-Object Name -Descending |
    Select-Object -Skip $Keep |
    Remove-Item -Force
exit 0
