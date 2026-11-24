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
   v4  2026-11-24  Name resolution with a single domain controller: the DC
                   list is kept as an array, so the DC name and the first
                   management machine name are no longer joined into one
                   name (reported as "DNS name does not exist") and each
                   host gets its own A-record row.
   v5  2026-11-24  Multi-domain: -Domain takes one or more domains (forest
                   root and child domains), as a list or comma-separated.
                   SRV discovery, DC name resolution, TCP 88/389 and the
                   clock offset are checked for every domain; a domain with
                   no DC found is reported as its own FAIL row. An SRV query
                   that returns no records is a FAIL instead of an empty OK.

 REQUIREMENTS
   - Windows 10/11, Windows PowerShell 5.1 (no RSAT, no AD module)
   - Network path as in production (forced VPN tunnel up)

 Nothing is changed on the PAW. Output is printed and saved next to the
 script as Tier0-PawCheck-<timestamp>.txt.
 Example domains used in prompts: lab.sk (root), rats.lab.sk (child);
 example MM: mgmt01.lab.sk
===============================================================================
#>
#Requires -Version 5.1
[CmdletBinding()]
param(
    [string[]]$Domain,                      # AD domain FQDN(s), forest root first, e.g. lab.sk,rats.lab.sk
    [string[]]$ManagementMachines           # FQDNs, e.g. mgmt01.lab.sk
)
$ErrorActionPreference = 'Continue'
$out = New-Object System.Collections.Generic.List[string]
function Say([string]$t, [string]$c = 'Gray') { Write-Host $t -ForegroundColor $c; $out.Add($t) }
function Row([string]$status, [string]$item, [string]$detail) {
    $c = switch ($status) { 'OK' {'Green'} 'FAIL' {'Red'} 'WARN' {'Yellow'} default {'Gray'} }
    Say ("  [{0,-4}] {1,-55} {2}" -f $status, $item, $detail) $c
}

if (-not $Domain) { $Domain = Read-Host 'AD domain FQDNs, comma-separated, forest root first (e.g. lab.sk,rats.lab.sk)' }
if (-not $ManagementMachines) { $ManagementMachines = (Read-Host 'Management machine FQDNs, comma-separated (e.g. mgmt01.lab.sk)') -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ } }
# Accept a list or one comma-separated string for both parameters (powershell.exe -File passes a,b as one string).
$Domain = @($Domain | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim().ToLower() } | Where-Object { $_ } | Select-Object -Unique)
$ManagementMachines = @($ManagementMachines | ForEach-Object { $_ -split ',' } | ForEach-Object { $_.Trim() } | Where-Object { $_ })

Say ''
Say "Tier0-PawCheck v5  -  $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')  -  host $env:COMPUTERNAME" 'Cyan'
Say ("  Domain joined: {0}   Entra joined: {1}" -f (Get-CimInstance Win32_ComputerSystem).PartOfDomain, ($null -ne (dsregcmd /status 2>$null | Select-String 'AzureAdJoined\s*:\s*YES')))
Say ("  Domains: {0}" -f ($Domain -join ', '))
Say ''

# 1. DNS: SRV records the Kerberos client needs to find a KDC, per domain
Say '1. DNS SRV records' 'White'
$dcHosts = @()
$dcByDomain = @{}
foreach ($d in $Domain) {
    $found = @()
    foreach ($srv in @("_kerberos._tcp.dc._msdcs.$d", "_ldap._tcp.dc._msdcs.$d", "_kerberos._udp.$d")) {
        try {
            $r = Resolve-DnsName -Name $srv -Type SRV -ErrorAction Stop | Where-Object Type -eq 'SRV'
            $targets = @($r | ForEach-Object { $_.NameTarget } | Where-Object { $_ } | Sort-Object -Unique)
            if ($targets.Count -gt 0) { $found += $targets; Row 'OK' $srv ($targets -join ', ') }
            else { Row 'FAIL' $srv 'query answered without SRV records' }
        } catch { Row 'FAIL' $srv $_.Exception.Message }
    }
    $found = @($found | Sort-Object -Unique)
    $dcByDomain[$d] = $found
    $dcHosts += $found
    if ($found.Count -eq 0) { Row 'FAIL' "DC discovery $d" 'No DC names resolved for this domain - Kerberos cannot work for its accounts from this PAW. Check VPN/DNS.' }
}
$dcHosts = @($dcHosts | Sort-Object -Unique)

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
foreach ($d in $Domain) {
    $dc = @($dcByDomain[$d]) | Select-Object -First 1
    if (-not $dc) { Row 'WARN' "Clock offset $d" 'not measured: no DC found for this domain'; continue }
    try {
        $w = w32tm /stripchart /computer:$dc /samples:1 /dataonly 2>$null | Select-String -Pattern ',\s*([+-]\d+\.\d+)s' | Select-Object -First 1
        if ($w) { $off = [double]$w.Matches[0].Groups[1].Value; Row ($(if ([math]::Abs($off) -lt 120) {'OK'} else {'FAIL'})) "Clock offset vs $dc" ("{0:+0.0;-0.0}s (must stay under 300s)" -f $off) }
        else { Row 'WARN' "Clock offset vs $dc" 'could not measure (NTP/UDP 123 to the DC may be blocked - acceptable if the PAW syncs elsewhere)' }
    } catch { Row 'WARN' "Clock offset vs $dc" $_.Exception.Message }
}

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
Say '   Run manually with a Tier 0 account of the domain to test (password prompt, nothing stored):' 'Gray'
foreach ($d in $Domain) {
    Say ("     runas /user:<account>@{0} ""powershell.exe -NoExit -Command Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-Command','klist tgt'""" -f $d) 'Gray'
}
Say '   Expected: AES-256 TGT, 4h lifetime. On the DC: event 303 (ProtectedUserSuccesses). For a silo account a 305 with' 'Gray'
Say '   Device Name blank appears, because the PAW is not domain-joined and cannot armor the request. In normal use the account' 'Gray'
Say '   is typed into mstsc and the management machine obtains the ticket, so no 305 appears.' 'Gray'

$file = Join-Path (Split-Path -Parent $MyInvocation.MyCommand.Path) ("Tier0-PawCheck-{0}.txt" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
$out | Set-Content -Path $file -Encoding UTF8
Say ''
Say "Saved: $file" 'Cyan'
# Tier0-PawCheck.ps1 v5 end
