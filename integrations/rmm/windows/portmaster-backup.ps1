# Back up the Portmaster settings and all local app profiles to Dir\portmaster-backup-<host>-<date>\
# (portmaster-core backup create), keep the last -Keep backups.
# Restore: portmaster-core.exe backup restore <Dir>\portmaster-backup-<host>-<date>
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
$out = Join-Path $Dir ("portmaster-backup-{0}-{1}" -f $hostName, (Get-Date -Format "yyyyMMdd-HHmmss"))

# A failed profile export still writes the backup (exit 1 names the profile);
# a backup without manifest was not written at all.
& "$CorePath" backup create "$out"
$rc = $LASTEXITCODE
if (-not (Test-Path -LiteralPath (Join-Path $out 'manifest.json'))) {
    Write-Error "backup failed"
    exit 1
}

Get-ChildItem -LiteralPath $Dir -Directory -Filter "portmaster-backup-$hostName-*" |
    Sort-Object Name -Descending |
    Select-Object -Skip $Keep |
    Remove-Item -Recurse -Force
exit $rc
