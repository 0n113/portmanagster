# Integration smoke test of portmaster-core on Windows. Runs inside the test
# VM as administrator (see test-windows.sh):
#
#   .\smoke.ps1 -Core C:\vmtest\portmaster-core.exe [-Dll C:\vmtest\portmaster-core.dll]
#
# With -Dll, the given core DLL replaces the downloaded one and must load.
# Fetches the signed release binaries (including the kernel extension) with
# the update command, then starts the given portmaster-core with packet
# interception and checks that it intercepts and filters traffic, answers its
# API and shuts down cleanly. Exits non-zero if any check fails.
param(
    [Parameter(Mandatory = $true)][string]$Core,
    [string]$Dll
)

$ErrorActionPreference = 'Continue'
$ProgressPreference = 'SilentlyContinue'

$Work = 'C:\vmtest\pm-smoke'
$Bin = Join-Path $Work 'bin'
$Data = Join-Path $Work 'data'
$Log = Join-Path $Work 'core.log'
$Api = 'http://127.0.0.1:817/api/v1'
$Curl = 'C:\Windows\System32\curl.exe'
$Allowed = 'example.com'
$Blocked = 'example.org'
# A name whose CNAME points outside the blocked zone (safing/portmaster#2306).
$CnameBlocked = 'tr.archive.ubuntu.com'
$CnameZone = 'ubuntu.com'

$script:failures = 0
function Pass($msg) { Write-Output "  PASS $msg" }
function Fail($msg) { Write-Output "  FAIL $msg"; $script:failures++ }
function Check($msg, [scriptblock]$test) {
    $ok = $false
    try { $ok = [bool](& $test) } catch { $ok = $false }
    if ($ok) { Pass $msg } else { Fail $msg }
}
function Step($msg) { Write-Output ''; Write-Output "== $msg" }

function HttpsOk($domain) {
    & $Curl -sS -o NUL --max-time 15 "https://$domain/" 2>$null
    return $LASTEXITCODE -eq 0
}
function HttpOk($domain) {
    & $Curl -sS -o NUL --max-time 15 "http://$domain/" 2>$null
    return $LASTEXITCODE -eq 0
}
function Resolves($domain) {
    $r = Resolve-DnsName -Name $domain -Type A -DnsOnly -QuickTimeout -ErrorAction SilentlyContinue |
        Where-Object { $_.IPAddress -and $_.IPAddress -ne '0.0.0.0' }
    return [bool]$r
}
# UdpDatagramsReceived sends three datagrams to a local UDP listener and
# returns how many arrived (safing/portmaster#2286). With -CloseAfterEach, a
# new sender socket sends one datagram and closes right away.
function UdpDatagramsReceived($address, [switch]$CloseAfterEach) {
    $listener = New-Object System.Net.Sockets.UdpClient(0)
    $sender = $null
    try {
        $port = $listener.Client.LocalEndPoint.Port
        $data = [Text.Encoding]::ASCII.GetBytes('portmaster-udp-test')
        foreach ($i in 1..3) {
            if ($null -eq $sender) { $sender = New-Object System.Net.Sockets.UdpClient }
            [void]$sender.Send($data, $data.Length, $address, $port)
            if ($CloseAfterEach) { $sender.Close(); $sender = $null }
            Start-Sleep -Milliseconds 300
        }
        $got = 0
        $from = New-Object System.Net.IPEndPoint([Net.IPAddress]::Any, 0)
        $listener.Client.ReceiveTimeout = 1000
        try { while ($true) { [void]$listener.Receive([ref]$from); $got++ } } catch { }
        return $got
    } finally {
        if ($null -ne $sender) { $sender.Close() }
        $listener.Close()
    }
}

function ApiReady {
    & $Curl -sf --max-time 5 "$Api/ready" 2>$null | Out-Null
    return $LASTEXITCODE -eq 0
}

Remove-Item -Recurse -Force $Work -ErrorAction SilentlyContinue
New-Item -ItemType Directory -Force -Path $Bin, $Data | Out-Null

Step 'Before start'
Check "https://$Allowed reachable" { HttpsOk $Allowed }
# This also puts the name into the DNS Client cache: Portmaster must flush it
# on start, or the connection would have no domain and pass the rule below.
Check "http://$CnameBlocked reachable" { HttpOk $CnameBlocked }
Check 'UDP to a local listener on 127.0.0.1' { (UdpDatagramsReceived '127.0.0.1') -eq 3 }

Step 'Release binaries'
& $Core update --bin-dir $Bin --data-dir $Data *>> $Log
# An installed upgrade that needs a restart is a success for the command.
$updateRc = $LASTEXITCODE
Check "update command succeeds (exit code $updateRc)" { $updateRc -eq 0 }
$kext = Get-ChildItem -Path $Bin -Recurse -Filter 'portmaster-kext*.sys' -ErrorAction SilentlyContinue | Select-Object -First 1
if ($kext) {
    Pass "kernel extension downloaded ($($kext.Name), signed by $((Get-AuthenticodeSignature $kext.FullName).SignerCertificate.Subject))"
} else {
    Fail 'kernel extension downloaded'
    Get-Content $Log -Tail 30
    exit 1
}

if ($Dll) {
    $target = Get-ChildItem -Path $Bin -Recurse -Filter 'portmaster-core*.dll' -ErrorAction SilentlyContinue | Select-Object -First 1
    $targetPath = if ($target) { $target.FullName } else { Join-Path $Bin 'portmaster-core.dll' }
    Copy-Item -Force $Dll $targetPath
    Pass "core DLL replaced with $Dll"
}

# Block one domain in the global settings.
# Also allow incoming SSH, as the test is controlled over SSH.
Set-Content -Path (Join-Path $Data 'config.json') -Encoding ASCII `
    -Value ('{"filter":{"endpoints":["- ' + $Blocked + '","- .' + $CnameZone + '"],"serviceEndpoints":["+ * TCP/22"]}}')

Step 'Start'
$proc = Start-Process -FilePath $Core -PassThru -WindowStyle Hidden `
    -RedirectStandardOutput $Log -RedirectStandardError "$Log.err" `
    -ArgumentList @('--bin-dir', $Bin, '--data-dir', $Data, '--log-stdout', '--log', 'info', '--allowed-clients', $Curl, '--allowed-clients', $Core)
# Without querying the handle, ExitCode stays empty after WaitForExit.
$null = $proc.Handle
$waited = 0
while (-not (ApiReady)) {
    Start-Sleep -Seconds 2
    $waited += 2
    if ($proc.HasExited -or $waited -ge 300) {
        Fail "portmaster-core starts and reports ready (exited: $($proc.HasExited), waited ${waited}s)"
        Get-Content $Log, "$Log.err" -Tail 30 -ErrorAction SilentlyContinue
        exit 1
    }
}
Pass "portmaster-core starts and reports ready (${waited}s)"
Check 'DNS Client cache flushed' { Select-String -Path $Log -Quiet -SimpleMatch 'flushed the DNS Client cache' }
Check 'kernel extension service running' { (Get-Service -Name 'PortmasterKext' -ErrorAction SilentlyContinue).Status -eq 'Running' -or (sc.exe query type= driver | Select-String -Quiet 'PortmasterKext') }

Step 'Filtering'
Start-Sleep -Seconds 3
Check "$Allowed resolves" { Resolves $Allowed }
Check "https://$Allowed reachable" { HttpsOk $Allowed }
# Windows resolves names through the DNS Client service (svchost), so the
# per-app rule applies to the connection, not to the DNS query.
Write-Output "  info: $Blocked resolves through the DNS Client service: $(Resolves $Blocked)"
Check "https://$Blocked is blocked" { -not (HttpsOk $Blocked) }
Check "http://$CnameBlocked is blocked by the rule for .$CnameZone (CNAME outside the zone)" { -not (HttpOk $CnameBlocked) }
# How fast a connection blocked by a rule fails (safing/portmaster#1981).
$sw = [Diagnostics.Stopwatch]::StartNew()
& $Curl -sS -o NUL --max-time 40 "http://$CnameBlocked/" 2>$null
$blockRc = $LASTEXITCODE
$sw.Stop()
$blockSecs = [math]::Round($sw.Elapsed.TotalSeconds, 1)
Check "a blocked connection fails at once, not by timeout (${blockSecs}s, curl exit code $blockRc)" { $blockRc -ne 0 -and $blockSecs -lt 5 }
Check 'UDP to a local listener on 127.0.0.1' { (UdpDatagramsReceived '127.0.0.1') -eq 3 }
# Known kext limitation: the first datagram of a socket waits for the verdict
# and is re-injected through the sending socket, so it is lost when the socket
# is already closed by then.
Write-Output "  info: UDP from send-and-close sockets received: $(UdpDatagramsReceived '127.0.0.1' -CloseAfterEach) of 3"

Step 'API'
Check 'ping endpoint' { & $Curl -sf --max-time 5 "$Api/ping" 2>$null | Out-Null; $LASTEXITCODE -eq 0 }
Start-Sleep -Seconds 3
$body = '{"query":{"domain":{"$like":"%' + $Allowed + '%"}},"select":["id","verdict"],"pageSize":50}'
$bodyFile = Join-Path $Work 'query.json'
Set-Content -Path $bodyFile -Value $body -Encoding ASCII
$out = & $Curl -sf --max-time 10 -X POST "$Api/netquery/query" -H 'Content-Type: application/json' --data-binary "@$bodyFile" 2>$null
$n = 0
try { $n = @(($out | Out-String | ConvertFrom-Json).results).Count } catch {}
if ($n -gt 0) { Pass "netquery lists connections to $Allowed ($n)" } else { Fail "netquery lists connections to $Allowed (got '$out')" }
$body = '{"query":{"remote_ip":{"$in":["' + (@(Resolve-DnsName -Name $CnameBlocked -Type A -ErrorAction SilentlyContinue | Where-Object IPAddress | ForEach-Object IPAddress) -join '","') + '"]}},"select":["domain","verdict"],"groupBy":["domain","verdict"],"pageSize":20}'
Set-Content -Path $bodyFile -Value $body -Encoding ASCII
Write-Output "  info: connections to the IPs of ${CnameBlocked}: $(& $Curl -sf --max-time 10 -X POST "$Api/netquery/query" -H 'Content-Type: application/json' --data-binary "@$bodyFile" 2>$null)"
$code = 0
try {
    Invoke-WebRequest -UseBasicParsing -Method Post -Uri "$Api/netquery/query" -Body '{}' -TimeoutSec 10 | Out-Null
    $code = 200
} catch { $code = [int]$_.Exception.Response.StatusCode }
if ($code -eq 403 -or $code -eq 401) { Pass "API denies an unauthorized local client ($code)" } else { Fail "API denies an unauthorized local client (got $code)" }
# app/auth identifies the calling process and waits for the user to answer
# the prompt; without the process (safing/portmaster#2302 B1) it fails at once.
$authCode = & $Curl -s -o NUL -w '%{http_code}' --max-time 5 "$Api/app/auth?app-name=vmtest&read=user&write=user&ttl=1h" 2>$null
if ($authCode -eq '000') { Pass 'app/auth identifies the caller and waits for the prompt' } else { Fail "app/auth identifies the caller and waits for the prompt (got HTTP $authCode)" }

Step 'Status and settings commands'
# portmaster-core status, settings and the RMM check script. The test binary
# is not in the bin dir, so it is allowed by --allowed-clients.
$statusJson = & $Core status 2>$null | Out-String
$status = $null
try { $status = $statusJson | ConvertFrom-Json } catch {}
Check 'status reports ready and interception active' { $status -and $status.ready -and $status.interception -and $status.filtering }
$checkLine = & $Core status --check --max-intel-age 0 2>$null | Out-String
$checkRc = $LASTEXITCODE
Write-Output "  $($checkLine.Trim())"
Check "status --check is OK or WARNING (rc $checkRc)" { $checkRc -le 1 -and $checkLine -match '^(OK|WARNING):' }
$CheckScript = Join-Path (Split-Path $Core) 'portmaster-check.ps1'
if (Test-Path $CheckScript) {
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $CheckScript -CorePath $Core -MaxIntelAge 0 2>$null | Out-String
    $rc = $LASTEXITCODE
    Check "portmaster-check.ps1 passes the exit code (rc ${rc}: $($out.Trim()))" { $rc -le 1 -and $out -match '^(OK|WARNING):' }
    $out = & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $CheckScript -CorePath 'C:\nonexistent\portmaster-core.exe' 2>$null | Out-String
    Check "portmaster-check.ps1 reports UNKNOWN for a missing core (rc $LASTEXITCODE)" { $LASTEXITCODE -eq 3 }
} else {
    Write-Output "  info: $CheckScript not found, skipped"
}
$importFile = Join-Path $Work 'import.yaml'
Set-Content -Path $importFile -Encoding ASCII -Value "type: settings`nconfig:`n  filter:`n    askTimeout: 33`n"
& $Core settings import $importFile 2>$null | Out-Null
Check 'settings import and export' { (& $Core settings export --format json --key filter/askTimeout 2>$null | Out-String | ConvertFrom-Json).config.filter.askTimeout -eq 33 }
Check 'settings import keeps the endpoint rules (merge)' { (& $Core settings export --format json 2>$null | Out-String | ConvertFrom-Json).config.filter.endpoints.Count -ge 2 }
$ApplyScript = Join-Path (Split-Path $Core) 'portmaster-apply-settings.ps1'
$BackupScript = Join-Path (Split-Path $Core) 'portmaster-backup.ps1'
if ((Test-Path $ApplyScript) -and (Test-Path $BackupScript)) {
    Set-Content -Path $importFile -Encoding ASCII -Value "type: settings`nconfig:`n  filter:`n    askTimeout: 34`n"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ApplyScript -File $importFile -CorePath $Core 2>$null | Out-Null
    $rc = $LASTEXITCODE
    Check "portmaster-apply-settings.ps1 imports the file (rc $rc)" { $rc -eq 0 -and (& $Core settings export --format json --key filter/askTimeout 2>$null | Out-String | ConvertFrom-Json).config.filter.askTimeout -eq 34 }
    $badFile = Join-Path $Work 'bad.yaml'
    Set-Content -Path $badFile -Encoding ASCII -Value "type: settings`nconfig:`n  filter:`n    noSuchSetting: 1`n"
    & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $ApplyScript -File $badFile -CorePath $Core 2>$null | Out-Null
    $rc = $LASTEXITCODE
    Check "portmaster-apply-settings.ps1 rejects an unknown key and imports nothing (rc $rc)" { $rc -ne 0 -and (& $Core settings export --format json --key filter/askTimeout 2>$null | Out-String | ConvertFrom-Json).config.filter.askTimeout -eq 34 }
    $backupDir = Join-Path $Work 'backup'
    foreach ($i in 1..3) {
        & powershell.exe -NoProfile -ExecutionPolicy Bypass -File $BackupScript -Dir $backupDir -CorePath $Core -Keep 2 2>$null | Out-Null
        $rc = $LASTEXITCODE
        if ($rc -ne 0) { break }
        Start-Sleep -Seconds 1
    }
    $backups = @(Get-ChildItem -LiteralPath $backupDir -Directory -Filter 'portmaster-backup-*' -ErrorAction SilentlyContinue | Sort-Object Name)
    Check "portmaster-backup.ps1 writes backups and keeps 2 (rc $rc, $($backups.Count) dirs)" { $rc -eq 0 -and $backups.Count -eq 2 }
    $last = if ($backups.Count -gt 0) { $backups[-1].FullName } else { Join-Path $backupDir 'none' }
    $manifest = $null
    try { $manifest = Get-Content -Raw -LiteralPath (Join-Path $last 'manifest.json') | ConvertFrom-Json } catch {}
    Check "the backup contains the setting and the app profiles ($(@($manifest.profiles).Count) profiles)" { $manifest -and @($manifest.profiles).Count -gt 0 -and (Get-Content -Raw -LiteralPath (Join-Path $last 'settings.yaml')) -match 'askTimeout:\s*34' }
    $restore = & $Core backup restore $last 2>$null | Out-String
    $rc = $LASTEXITCODE
    $report = $null
    try { $report = $restore | ConvertFrom-Json } catch {}
    Check "backup restore imports the settings and all profiles (rc $rc)" { $rc -eq 0 -and $report -and @($report.profiles).Count -eq @($manifest.profiles).Count -and -not (@($report.profiles) | Where-Object { $_.error }) }
} else {
    Write-Output "  info: apply or backup script not found, skipped"
}

Step 'Management'
# Enrollment at a portmanagster server on this machine. The signed policy sets
# a locked setting, a policy default, an endpoint rule and a group profile.
# Checks the policy layer over the user values, the report of overridden
# defaults, the offline start with the stored policy, refused old and tampered
# policies, revocation, and leave keeping the policy values.
$Server = Join-Path (Split-Path $Core) 'portmanagster-server.exe'
$MProfile = Join-Path (Split-Path $Core) 'restic-windows.yaml'
if ((Test-Path $Server) -and (Test-Path $MProfile)) {
    $SD = Join-Path $Work 'mgmt-server'
    $MUrl = 'https://127.0.0.1:8443'
    $MState = Join-Path $Data 'managed'
    $script:serverProc = $null
    $script:coreRun = 0
    # AskTimeout: the value in force; UserAskTimeout: the value the user set.
    function AskTimeout { (& $Core settings export --effective --format json --key filter/askTimeout 2>$null | Out-String | ConvertFrom-Json).config.filter.askTimeout }
    function UserAskTimeout { (& $Core settings export --format json --key filter/askTimeout 2>$null | Out-String | ConvertFrom-Json).config.filter.askTimeout }
    function Notify([switch]$User) {
        $a = @('settings', 'export', '--format', 'json', '--key', 'filter/askWithSystemNotifications')
        if (-not $User) { $a += '--effective' }
        (& $Core @a 2>$null | Out-String | ConvertFrom-Json).config.filter.askWithSystemNotifications
    }
    function ImportSetting($name, $v) {
        $f = Join-Path $Work 'mgmt-set.yaml'
        Set-Content -Path $f -Encoding ASCII -Value "type: settings`nconfig:`n  filter:`n    ${name}: $v`n"
        & $Core settings import $f 2>$null | Out-Null
        return $LASTEXITCODE
    }
    function SetGroupAskTimeout($v) {
        $f = Join-Path $Work 'mgmt-group.yaml'
        Set-Content -Path $f -Encoding ASCII -Value "type: settings`nconfig:`n  filter:`n    askTimeout: $v`n    askWithSystemNotifications: false`n"
        & $Server --dir $SD group set office $f --lock filter/askTimeout 2>&1 | Out-Null
    }
    function NewToken { ((& $Server --dir $SD token create --group office --url $MUrl 2>$null) | Select-String '^token.*: (.+)$').Matches[0].Groups[1].Value }
    function ManageStatus { & $Core manage status 2>$null | Out-String | ConvertFrom-Json }
    function StartServer {
        $script:serverProc = Start-Process -FilePath $Server -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput (Join-Path $Work 'mgmt-server.out') -RedirectStandardError (Join-Path $Work "mgmt-server-$(Get-Random).log") `
            -ArgumentList @('--dir', $SD, 'serve', '--listen', '127.0.0.1:8443')
        Start-Sleep -Seconds 3
    }
    function StopServer { if ($script:serverProc) { Stop-Process -Id $script:serverProc.Id -Force -ErrorAction SilentlyContinue; Start-Sleep -Seconds 1 } }
    function RestartCore {
        & $Curl -sf --max-time 10 -X POST "$Api/core/shutdown" 2>$null | Out-Null
        if (-not $script:proc.WaitForExit(60000)) { Stop-Process -Id $script:proc.Id -Force }
        $script:coreRun++
        $runLog = Join-Path $Work "core-mgmt-$($script:coreRun).log"
        $script:proc = Start-Process -FilePath $Core -PassThru -WindowStyle Hidden `
            -RedirectStandardOutput $runLog -RedirectStandardError "$runLog.err" `
            -ArgumentList @('--bin-dir', $Bin, '--data-dir', $Data, '--log-stdout', '--log', 'info', '--allowed-clients', $Curl, '--allowed-clients', $Core)
        $null = $script:proc.Handle
        $w = 0
        while (-not (ApiReady)) {
            Start-Sleep -Seconds 2
            $w += 2
            if ($script:proc.HasExited -or $w -ge 300) { return $false }
        }
        Write-Output "  portmaster-core restarted (${w}s)"
        return $true
    }
    function StoredPolicyLines { @(Select-String -Path (Join-Path $Work 'core-mgmt-*.log') -Pattern 'stored policy' -SimpleMatch -ErrorAction SilentlyContinue) }

    & $Server --dir $SD init --host 127.0.0.1 2>&1 | Out-Null
    & $Server --dir $SD group create office 2>&1 | Out-Null
    SetGroupAskTimeout 77
    & $Server --dir $SD group profiles office $MProfile 2>&1 | Out-Null
    $rulesFile = Join-Path $Work 'mgmt-rules.yaml'
    Set-Content -Path $rulesFile -Encoding ASCII -Value "endpoints:`n  - `"- $Allowed`"`n"
    & $Server --dir $SD group rules office $rulesFile 2>&1 | Out-Null
    $settingsBefore = Join-Path $Work 'mgmt-settings-before.json'
    & $Core settings export --format json 2>$null | Set-Content -Path $settingsBefore -Encoding ASCII
    $null = ImportSetting askTimeout 33
    StartServer
    $fps = & $Server --dir $SD fingerprints 2>$null
    $sfp = ($fps | Select-String '^server certificate: (.+)$').Matches[0].Groups[1].Value
    $kfp = ($fps | Select-String '^policy key: +(.+)$').Matches[0].Groups[1].Value

    & $Core manage enroll --server $MUrl --token (NewToken) --server-fp $sfp --policy-key-fp 'sha256:00' 2>$null | Out-Null
    $rc = $LASTEXITCODE
    Check "enroll with a wrong policy key pin is refused (rc $rc)" { $rc -ne 0 -and -not (Test-Path (Join-Path $MState 'state.json')) }
    $out = & $Core manage enroll --server $MUrl --token (NewToken) --server-fp $sfp --policy-key-fp $kfp 2>&1 | Out-String
    $rc = $LASTEXITCODE
    Check "enroll succeeds (rc $rc)" { $rc -eq 0 }
    if ($rc -ne 0) { Write-Output "    $($out.Trim())" }
    $st = ManageStatus
    $cid = $st.computerId
    Check 'status shows the group' { $st.enrolled -and $st.group -eq 'office' -and $st.appliedVersion -gt 0 }
    Check 'the locked setting is in force over the user value (77, user 33)' { (AskTimeout) -eq 77 -and (UserAskTimeout) -eq 33 }
    Check 'the policy default is in force without a user value' { (Notify) -eq $false -and $null -eq (Notify -User) }
    $rc = ImportSetting askTimeout 15
    Check "the locked setting cannot be changed (rc $rc)" { $rc -ne 0 -and (AskTimeout) -eq 77 }
    Check "the policy rule blocks https://$Allowed" { -not (HttpsOk $Allowed) }
    Check 'group profile imported' { @(& $Core profile list 2>$null | Out-String | ConvertFrom-Json | Where-Object { $_.name -eq 'restic' }).Count -gt 0 }
    $c = & $Server --dir $SD computer show $cid 2>$null | Out-String | ConvertFrom-Json
    Check 'report arrived on the server, nothing overridden' { $c.report.status.ready -and $c.report.status.interception -and $c.appliedVersion -gt 0 -and -not $c.report.overridden -and -not $c.report.refused }
    Check 'the refused enrollment created no computer' { @(& $Server --dir $SD computer list 2>$null).Count -eq 2 }
    & $Server --dir $SD computer list 2>$null | ForEach-Object { "    $_" }
    Write-Output "  info: hostname reported '$($c.hostname)', COMPUTERNAME '$env:COMPUTERNAME', DNS host name '$([Net.Dns]::GetHostName())'"

    $null = ImportSetting askWithSystemNotifications true
    $p = & $Core manage pull 2>$null | Out-String | ConvertFrom-Json
    Check 'a local admin overrides the policy default, the pull reports it' { @($p.overridden) -contains 'filter/askWithSystemNotifications' -and (Notify) -eq $true }
    $c = & $Server --dir $SD computer show $cid 2>$null | Out-String | ConvertFrom-Json
    Check 'the override is reported to the server' { @($c.report.overridden) -contains 'filter/askWithSystemNotifications' }

    $policyFile = Join-Path $MState 'policy.json'
    Copy-Item -Force $policyFile (Join-Path $Work 'mgmt-old-policy.json')
    $v1 = (ManageStatus).appliedVersion
    SetGroupAskTimeout 88
    & $Core manage pull 2>$null | Out-Null
    Check 'a server change arrives with a higher version' { (ManageStatus).appliedVersion -gt $v1 -and (AskTimeout) -eq 88 }
    Copy-Item -Force $policyFile (Join-Path $Work 'mgmt-good-policy.json')

    # Offline: the server is down, the stored policy applies at start.
    StopServer
    if (RestartCore) {
        Check 'offline start applies the stored policy' { (AskTimeout) -eq 88 }
        Check 'the policy rule holds after the restart' { -not (HttpsOk $Allowed) }
        Start-Sleep -Seconds 3
        Check 'the failed pull shows in the status' { $s = ManageStatus; $s.enrolled -and $s.lastError }
    } else { Fail 'portmaster-core restarts enrolled' }

    # An older signed policy is refused at start: the user value applies.
    Copy-Item -Force (Join-Path $Work 'mgmt-old-policy.json') $policyFile
    if (RestartCore) {
        Check 'an older stored policy is refused' { (AskTimeout) -eq 33 -and ((StoredPolicyLines)[-1].Line -match 'older') }
    } else { Fail 'portmaster-core restarts with an old policy' }

    # A changed policy fails the signature check at start.
    $refusedBefore = (StoredPolicyLines).Count
    $good = Get-Content -Raw (Join-Path $Work 'mgmt-good-policy.json')
    [IO.File]::WriteAllText($policyFile, ($good -replace '88', '89'))
    if (RestartCore) {
        Check 'a tampered stored policy is refused' { (AskTimeout) -eq 33 -and (StoredPolicyLines).Count -gt $refusedBefore }
    } else { Fail 'portmaster-core restarts with a tampered policy' }

    # Back online: the pull applies the policy; then the computer is revoked.
    StartServer
    & $Core manage pull 2>$null | Out-Null
    Check 'online again, the pull applies the policy' { $LASTEXITCODE -eq 0 -and (AskTimeout) -eq 88 }
    & $Server --dir $SD computer revoke $cid 2>&1 | Out-Null
    & $Core manage pull 2>$null | Out-Null
    $rc = $LASTEXITCODE
    Check "a revoked computer is rejected (rc $rc)" { $rc -ne 0 -and (ManageStatus).lastError }
    Check 'the policy stays in force after the revocation' { (AskTimeout) -eq 88 }
    $l = & $Core manage leave 2>$null | Out-String | ConvertFrom-Json
    Check 'manage leave removes the enrollment' { $l.enrolled -eq $false -and -not (Test-Path $MState) }
    Check 'leave keeps the locked value as a user value' { (UserAskTimeout) -eq 88 -and (AskTimeout) -eq 88 }
    Check 'leave keeps the overridden default as set by the admin' { (Notify -User) -eq $true }
    $eps = (& $Core settings export --format json --key filter/endpoints 2>$null | Out-String | ConvertFrom-Json).config.filter.endpoints
    Check 'leave keeps the policy rule in the global rules' { @($eps)[0] -eq "- $Allowed" -and -not (HttpsOk $Allowed) }
    $rc = ImportSetting askTimeout 15
    Check "the settings can be changed after leave (rc $rc)" { $rc -eq 0 -and (AskTimeout) -eq 15 }
    StopServer
    Check 'no panics or errors in the server log' { -not (Select-String -Path (Join-Path $Work 'mgmt-server-*.log') -Pattern '^panic:|level=ERROR' -ErrorAction SilentlyContinue) }
    & $Core settings import --reset $settingsBefore 2>$null | Out-Null
    Check "https://$Allowed is reachable again after the reset" { HttpsOk $Allowed }
} else {
    Write-Output "  info: $Server or $MProfile not found, skipped"
}

Step 'Load'
$jobs = 1..40 | ForEach-Object { Start-Process -FilePath $Curl -PassThru -WindowStyle Hidden -ArgumentList @('-s', '-o', 'NUL', '--max-time', '10', "https://$Allowed/?n=$_") }
$jobs | ForEach-Object { $_.WaitForExit(20000) | Out-Null }
Check 'service alive after 40 parallel connections' { -not $proc.HasExited }
Check "https://$Allowed still reachable" { HttpsOk $Allowed }

Step 'Shutdown'
& $Curl -sf --max-time 10 -X POST "$Api/core/shutdown" 2>$null | Out-Null
if ($proc.WaitForExit(60000)) { Pass 'portmaster-core stops within 60s' } else { Fail 'portmaster-core stops within 60s'; Stop-Process -Id $proc.Id -Force }
Check "exit code 0 (got $($proc.ExitCode))" { $proc.ExitCode -eq 0 }
Start-Sleep -Seconds 2
Check "https://$Allowed reachable without Portmaster" { HttpsOk $Allowed }
Check "$Blocked resolves again without Portmaster" { Resolves $Blocked }

Step 'Log'
Get-Content "$Log.err" -ErrorAction SilentlyContinue | Add-Content $Log
# Runs of the core restarted by the management test.
Get-ChildItem -Path $Work -Filter 'core-mgmt-*.log*' -ErrorAction SilentlyContinue | Sort-Object Name | Get-Content | Add-Content $Log
$panics = @(Select-String -Path $Log -Pattern '^panic:|fatal error:' -ErrorAction SilentlyContinue).Count
if ($panics -eq 0) { Pass 'no panics in the log' } else { Fail "$panics panics in the log" }
# The core DLL provides the ETW DNS integration. It fails to load when it
# needs a C runtime that the system does not have.
$dllLoaded = [bool](Select-String -Path $Log -Pattern 'integration: initialize successful' -SimpleMatch -ErrorAction SilentlyContinue)
if ($dllLoaded) {
    Pass 'core DLL loaded'
} elseif ($Dll) {
    Fail 'core DLL loaded'
} else {
    Write-Output '  info: core DLL not loaded (the upstream DLL needs the VC++ runtime)'
}
$errors = @(Select-String -Path $Log -Pattern ' (ERR|CRT) ' -CaseSensitive -ErrorAction SilentlyContinue).Count
Write-Output "  log: $(@(Get-Content $Log).Count) lines, $errors error lines (see core.log)"

Write-Output ''
if ($script:failures -eq 0) { Write-Output 'SMOKE TEST PASSED'; exit 0 }
Write-Output "SMOKE TEST FAILED: $($script:failures) checks"
exit 1
