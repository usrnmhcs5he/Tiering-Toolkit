<#
===============================================================================
 Tier0-PawCheck.ps1
 Read-only readiness check to run ON a Windows PAW (cloud-managed, not
 domain-joined). Verifies that the PAW can reach the Kerberos infrastructure
 it needs to use a Protected Users account against the management machines.

 VERSION HISTORY
   v1  2026-10-21  Initial release.
   v2  2026-10-21  Parser + PSScriptAnalyzer pass; $null-left comparison.
   v3  2026-10-21  Self-contained wording (no design-option references).

 REQUIREMENTS
   - Windows 10/11, Windows PowerShell 5.1 (no RSAT, no AD module)
   - Network path as in production (forced VPN tunnel up)

 Nothing is changed on the PAW. Output is printed and saved next to the
 script as Tier0-PawCheck-<timestamp>.txt.
 Example domain used in prompts: lab.sk; example MM: mgmt01.lab.sk
===============================================================================
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Domain,                        # AD domain FQDN, e.g. lab.sk
    [string[]]$ManagementMachines           # FQDNs, e.g. mgmt01.lab.sk
)
$ErrorActionPreference = 'Continue'
$out = New-Object System.Collections.Generic.List[string]
function Say([string]$t, [string]$c = 'Gray') { Write-Host $t -ForegroundColor $c; $out.Add($t) }
function Row([string]$status, [string]$item, [string]$detail) {
    $c = switch ($status) { 'OK' {'Green'} 'FAIL' {'Red'} 'WARN' {'Yellow'} default {'Gray'} }
    Say ("  [{0,-4}] {1,-55} {2}" -f $status, $item, $detail) $c
}

if (-not $Domain) { $Domain = Read-Host 'AD domain FQDN (e.g. lab.sk)' }
if (-not $ManagementMachines) { $ManagementMachines = (Read-Host 'Management machine FQDNs, comma-separated (e.g. mgmt01.lab.sk)') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
$Domain = $Domain.Trim().ToLower()

Say ''
Say "Tier0-PawCheck v3  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  -  host $env:COMPUTERNAME" 'Cyan'
Say ("  Domain joined: {0}   Entra joined: {1}" -f (Get-CimInstance Win32_ComputerSystem).PartOfDomain, ($null -ne (dsregcmd /status 2>$null | Select-String 'AzureAdJoined\s*:\s*YES')))
Say ''

# 1. DNS: SRV records the Kerberos client needs to find a KDC
Say '1. DNS SRV records' 'White'
$dcHosts = @()
foreach ($srv in @("_kerberos._tcp.dc._msdcs.$Domain", "_ldap._tcp.dc._msdcs.$Domain", "_kerberos._udp.$Domain")) {
    try {
        $r = Resolve-DnsName -Name $srv -Type SRV -ErrorAction Stop | Where-Object Type -eq 'SRV'
        $targets = @($r | ForEach-Object { $_.NameTarget }) | Sort-Object -Unique
        $dcHosts += $targets
        Row 'OK' $srv ($targets -join ', ')
    } catch { Row 'FAIL' $srv $_.Exception.Message }
}
$dcHosts = $dcHosts | Sort-Object -Unique
if (-not $dcHosts) { Row 'FAIL' 'DC discovery' 'No DC names resolved - Kerberos cannot work from this PAW. Check VPN/DNS.' }

# 2. Forward and reverse resolution of DCs and MMs
Say ''
Say '2. Name resolution' 'White'
foreach ($h in ($dcHosts + $ManagementMachines)) {
    try { $ip = (Resolve-DnsName -Name $h -Type A -ErrorAction Stop | Where-Object Type -eq 'A' | Select-Object -First 1).IPAddress; Row 'OK' "A  $h" $ip }
    catch { Row 'FAIL' "A  $h" $_.Exception.Message }
}

# 3. Ports: Kerberos to DCs, RDP to MMs
Say ''
Say '3. TCP reachability' 'White'
foreach ($h in $dcHosts) {
    foreach ($p in 88, 389) {
        $ok = Test-NetConnection -ComputerName $h -Port $p -WarningAction SilentlyContinue -InformationLevel Quiet
        Row ($(if ($ok) {'OK'} else {'FAIL'})) "$h`:$p" $(if ($p -eq 88) {'Kerberos'} else {'LDAP'})
    }
}
foreach ($m in $ManagementMachines) {
    $ok = Test-NetConnection -ComputerName $m -Port 3389 -WarningAction SilentlyContinue -InformationLevel Quiet
    Row ($(if ($ok) {'OK'} else {'FAIL'})) "$m`:3389" 'RDP'
    foreach ($p in 88, 445) {
        $ok2 = Test-NetConnection -ComputerName $m -Port $p -WarningAction SilentlyContinue -InformationLevel Quiet
        if ($ok2) { Row 'WARN' "$m`:$p" 'open from PAW - not needed for RDP; confirm the ACL is intentional' }
    }
}

# 4. Time (Kerberos tolerates 5 minutes)
Say ''
Say '4. Time' 'White'
try {
    $dc = $dcHosts | Select-Object -First 1
    $w = w32tm /stripchart /computer:$dc /samples:1 /dataonly 2>$null | Select-String -Pattern ',\s*([+-]\d+\.\d+)s' | Select-Object -First 1
    if ($w) { $off = [double]$w.Matches[0].Groups[1].Value; Row ($(if ([math]::Abs($off) -lt 120) {'OK'} else {'FAIL'})) "Clock offset vs $dc" ("{0:+0.0;-0.0}s (must stay under 300s)" -f $off) }
    else { Row 'WARN' 'Clock offset' 'could not measure (NTP/UDP 123 to the DC may be blocked - acceptable if the PAW syncs elsewhere)' }
} catch { Row 'WARN' 'Clock offset' $_.Exception.Message }

# 5. RDP client capability for Remote Credential Guard (optional on this hop; informational)
Say ''
Say '5. Remote Desktop client' 'White'
$mstsc = Get-Item "$env:SystemRoot\System32\mstsc.exe" -ErrorAction SilentlyContinue
if ($mstsc) { Row 'OK' 'mstsc.exe present' $mstsc.VersionInfo.ProductVersion } else { Row 'FAIL' 'mstsc.exe' 'classic client missing - the Store app does not support Remote Credential Guard' }
$pol = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -ErrorAction SilentlyContinue
if ($pol -and $pol.PSObject.Properties['RestrictedRemoteAdministration']) {
    $t = $pol.RestrictedRemoteAdministrationType
    Row 'INFO' 'Restrict delegation of credentials policy' ("enabled, type={0} (1=Restricted Admin, 2=Require RCG, 3=prefer RCG then RA)" -f $t)
    if ($t -in 2,3) { Row 'WARN' 'RCG on PAW->MM' 'With Remote Credential Guard the PAW itself requests the account ticket, unarmored; an account whose policy restricts the source device will be refused. Use a plain RDP logon on this hop so the management machine requests the ticket.' }
} else { Row 'INFO' 'Restrict delegation of credentials policy' 'not configured (plain RDP logon; the MM obtains the ticket)' }
$saved = Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation' -Name DenySavedCredentials -ErrorAction SilentlyContinue
Row ($(if ($saved) {'OK'} else {'WARN'})) 'Deny delegating saved credentials' $(if ($saved) {'configured'} else {'not configured - saved RDP credentials remain possible on this PAW'})

# 6. Functional Kerberos test (optional): obtain a TGT for a Tier 0 account
Say ''
Say '6. Optional functional test' 'White'
Say '   Run manually with a Tier 0 account (password prompt, nothing stored):' 'Gray'
Say ("     runas /user:{0}\<account> ""powershell.exe -NoExit -Command Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-Command','klist tgt'""" -f $Domain.Split('.')[0].ToUpper()) 'Gray'
Say '   Expected: AES-256 TGT, 4h lifetime. On the DC: event 303 (ProtectedUserSuccesses). For a silo account a 305 with' 'Gray'
Say '   Device Name blank appears, because the PAW is not domain-joined and cannot armor the request. In normal use the account' 'Gray'
Say '   is typed into mstsc and the management machine obtains the ticket, so no 305 appears.' 'Gray'

$file = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) ("Tier0-PawCheck-{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$out | Set-Content -Path $file -Encoding UTF8
Say ''
Say "Saved: $file" 'Cyan'
# Tier0-PawCheck.ps1 v3 end
