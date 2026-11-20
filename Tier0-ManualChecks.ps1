<#
===============================================================================
 Tier0-ManualChecks.ps1
 Manual, read-only verification of the Tier 0 authentication policy silo
 across the domains of one forest. Nothing is changed in the directory or on
 any host.

 VERSION HISTORY
   v1  2026-11-20  Initial version: seven independent blocks (domains, silo and
                   policy as seen by every DC, members, reverse checks, DC host
                   state, channel events, claims check on a management machine).
   v2  2026-11-20  Blocks 5 and 6 no longer wait on unreachable hosts: a
                   3-second port test precedes every remote call, WinRM calls
                   carry open and operation timeouts, the local machine is
                   probed without remoting, and each DC is announced before it
                   is contacted. Block 6 now reads events over WinRM (same
                   path as block 5) instead of remote event log RPC.
   v3  2026-11-20  Block 6 queries each channel on its own and reports a
                   channel error as a row instead of hiding it; the "no events"
                   row now states the look-back window and the total number of
                   records the channels hold, so an empty window is not read
                   as an empty log.

 HOW TO USE
   Run in Windows PowerShell 5.1 on a management machine or DC with the RSAT
   ActiveDirectory module, as an account that can read all domains.
   Run BLOCK 0 first (it sets the variables), then any other block on its own
   by selecting it and pressing F8 in ISE, or by pasting it into the console.
   Blocks 5 and 6 contact every DC over WinRM (TCP 5985). Each DC is named on
   screen before it is contacted; a DC that does not answer the port test
   within 3 seconds is reported as UNREACHABLE and the block moves on.
   Run the console elevated: reading the machine ticket needs it.

 Example values use the fictional forest lab.sk / rats.lab.sk. Replace the
 values in BLOCK 0 only.
===============================================================================
#>

# =============================== BLOCK 0 =====================================
# Variables used by every other block. Edit these three lines only.
$Domains  = @('lab.sk', 'rats.lab.sk')        # root first, then every child domain
$SiloName = 'AuthSilo-Tier0'
$Hours    = 24                                 # look-back window for event counts

$Channels = @(
    'Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController',
    'Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController',
    'Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController')
Import-Module ActiveDirectory
$Me = try { [System.Net.Dns]::GetHostEntry('').HostName } catch { $env:COMPUTERNAME }
$SessOpt = New-PSSessionOption -OpenTimeout 15000 -OperationTimeout 90000
function Test-TcpPort {
    param([string]$ComputerName, [int]$Port, [int]$TimeoutMs = 3000)
    $c = New-Object System.Net.Sockets.TcpClient
    try {
        $a = $c.BeginConnect($ComputerName, $Port, $null, $null)
        if ($a.AsyncWaitHandle.WaitOne($TimeoutMs)) { $c.EndConnect($a); return $true }
        return $false
    } catch { return $false } finally { $c.Close() }
}
function Invoke-DcProbe {
    # Runs a script block on a DC: locally when the DC is this machine,
    # otherwise over WinRM after a short port test. Never waits long.
    param([string]$ComputerName, [scriptblock]$ScriptBlock, [object[]]$Arguments)
    Write-Host ("  contacting {0} ..." -f $ComputerName) -ForegroundColor DarkGray
    if ($ComputerName -ieq $Me -or $ComputerName -ieq $env:COMPUTERNAME) {
        return (& $ScriptBlock @Arguments)
    }
    if (-not (Test-TcpPort -ComputerName $ComputerName -Port 5985)) {
        throw "UNREACHABLE: TCP 5985 (WinRM) did not answer within 3 seconds"
    }
    Invoke-Command -ComputerName $ComputerName -ScriptBlock $ScriptBlock -ArgumentList $Arguments -SessionOption $SessOpt -ErrorAction Stop
}
$AllDCs = foreach ($d in $Domains) {
    Get-ADDomainController -Filter * -Server $d |
        ForEach-Object { [pscustomobject]@{ Domain = $d; DC = $_.HostName; ReadOnly = $_.IsReadOnly; DN = $_.ComputerObjectDN } }
}
$Silo = Get-ADAuthenticationPolicySilo -Identity $SiloName -Server $Domains[0] -Properties *
"Domains: $($Domains -join ', ')   DCs found: $(@($AllDCs).Count)   Silo: $($Silo.DistinguishedName)"

# =============================== BLOCK 1 =====================================
# Domain functional level and DC inventory per domain.
# EXPECTED: DomainMode Windows2012R2Domain or higher in EVERY domain. Below
#           that the KDC applies no authentication policy and issues no silo
#           claim, and the Authentication channels of that domain stay empty.
$r = foreach ($d in $Domains) {
    $dom = Get-ADDomain -Server $d
    [pscustomobject]@{
        Domain     = $dom.DNSRoot
        DomainMode = $dom.DomainMode
        PDC        = $dom.PDCEmulator
        WritableDCs = @($dom.ReplicaDirectoryServers).Count
        RODCs      = @($dom.ReadOnlyReplicaDirectoryServers).Count
    }
}
$r | Format-Table -AutoSize

# =============================== BLOCK 2 =====================================
# The silo and the user policy as seen by EVERY DC of every domain.
# EXPECTED: every row identical. SiloEnforce True, PolicyEnforce True,
#           UserPolicy named, ComputerSlot and ServiceSlot False (empty),
#           UserTGT 240, FromHasSilo True, same Members count everywhere.
#           EnforceChanged is the time the silo's Enforce flag last changed;
#           it is the reference time for block 5.
#           A row that differs or shows ERROR means the Configuration
#           partition has not replicated to that DC (repadmin /showrepl <dc>).
$Block2 = foreach ($x in $AllDCs) {
    try {
        $s = Get-ADAuthenticationPolicySilo -Identity $SiloName -Server $x.DC -Properties * -ErrorAction Stop
        $p = $null
        if ($s.UserAuthenticationPolicy) {
            $p = Get-ADAuthenticationPolicy -Identity $s.UserAuthenticationPolicy -Server $x.DC -Properties * -ErrorAction Stop
        }
        $m = Get-ADReplicationAttributeMetadata -Object $s.DistinguishedName -Server $x.DC -Properties 'msDS-AuthNPolicySiloEnforced' -ErrorAction SilentlyContinue
        [pscustomobject]@{
            Domain         = $x.Domain
            DC             = $x.DC
            SiloEnforce    = $s.Enforce
            EnforceChanged = if ($m) { $m.LastOriginatingChangeTime } else { $null }
            Members        = @($s.Members).Count
            UserPolicy     = if ($p) { $p.Name } else { '(none)' }
            ComputerSlot   = [bool]$s.ComputerAuthenticationPolicy
            ServiceSlot    = [bool]$s.ServiceAuthenticationPolicy
            PolicyEnforce  = if ($p) { $p.Enforce } else { $null }
            UserTGT        = if ($p) { $p.UserTGTLifetimeMins } else { $null }
            FromHasSilo    = if ($p) { [bool]($p.UserAllowedToAuthenticateFrom -match [regex]::Escape($SiloName)) } else { $null }
        }
    } catch {
        [pscustomobject]@{ Domain = $x.Domain; DC = $x.DC; SiloEnforce = 'ERROR'; EnforceChanged = $null; Members = $null
            UserPolicy = $_.Exception.Message; ComputerSlot = $null; ServiceSlot = $null; PolicyEnforce = $null; UserTGT = $null; FromHasSilo = $null }
    }
}
$Block2 | Format-Table -AutoSize -Wrap

# =============================== BLOCK 3 =====================================
# Every member of the silo, read from its OWN domain.
# EXPECTED: Verdict "OK permitted + assigned" on every row; DirectPolicy empty;
#           ProtectedUsers True for every user, n/a for computers; Enabled True.
#           "permitted but NOT assigned" = the KDC does not apply the silo to
#           that object (the most common half-finished configuration).
$Block3 = foreach ($dn in $Silo.Members) {
    $dom = (($dn -split ',DC=') | Select-Object -Skip 1) -join '.'
    try {
        $o = Get-ADObject -Identity $dn -Server $dom -ErrorAction Stop -Properties objectClass, sAMAccountName,
             'msDS-AssignedAuthNPolicySilo', 'msDS-AssignedAuthNPolicy', memberOf, userAccountControl
        $a = $o.'msDS-AssignedAuthNPolicySilo'
        $verdict = if ($a -eq $Silo.DistinguishedName) { 'OK permitted + assigned' }
                   elseif (-not $a) { 'FAIL permitted but NOT assigned' }
                   else { 'FAIL assigned to a different silo' }
        [pscustomobject]@{
            Domain         = $dom
            Type           = $o.objectClass
            Name           = $o.sAMAccountName
            Verdict        = $verdict
            DirectPolicy   = ($o.'msDS-AssignedAuthNPolicy' -replace ',CN=AuthN.*')
            ProtectedUsers = if ($o.objectClass -eq 'user') { [bool]($o.memberOf -match '^CN=Protected Users,') } else { 'n/a' }
            Enabled        = -not [bool]($o.userAccountControl -band 2)
        }
    } catch {
        [pscustomobject]@{ Domain = $dom; Type = '?'; Name = $dn; Verdict = "FAIL not readable: $($_.Exception.Message)"; DirectPolicy = ''; ProtectedUsers = ''; Enabled = '' }
    }
}
$Block3 | Sort-Object Domain, Type, Name | Format-Table -AutoSize -Wrap
"Members per domain and type:"
$Block3 | Group-Object Domain, Type | Select-Object Count, Name | Format-Table -AutoSize

# =============================== BLOCK 4 =====================================
# Reverse checks per domain: what SHOULD be in the silo or must NOT be set.
# EXPECTED: no "assigned but NOT permitted" rows; no "direct policy" rows;
#           no "DC not in silo" rows for writable DCs; the built-in
#           Administrator (RID 500) NOT listed in Protected Users; no computer
#           or service account in Protected Users.
#           A domain with ZERO silo users and ZERO Protected Users members
#           produces no events in the Authentication channels of its DCs:
#           events are written by the KDC of the ACCOUNT's domain.
$Block4 = foreach ($d in $Domains) {
    $sid = (Get-ADDomain -Server $d).DomainSID.Value
    Get-ADObject -LDAPFilter '(msDS-AssignedAuthNPolicySilo=*)' -Server $d -Properties sAMAccountName |
        Where-Object { $Silo.Members -notcontains $_.DistinguishedName } |
        ForEach-Object { [pscustomobject]@{ Domain = $d; Finding = 'FAIL assigned but NOT permitted on the silo'; Object = $_.sAMAccountName } }
    Get-ADObject -LDAPFilter '(msDS-AssignedAuthNPolicy=*)' -Server $d -Properties sAMAccountName, 'msDS-AssignedAuthNPolicy' |
        ForEach-Object { [pscustomobject]@{ Domain = $d; Finding = "FAIL direct policy assignment ($($_.'msDS-AssignedAuthNPolicy' -replace ',CN=AuthN.*'))"; Object = $_.sAMAccountName } }
    $AllDCs | Where-Object { $_.Domain -eq $d -and $Silo.Members -notcontains $_.DN } |
        ForEach-Object { [pscustomobject]@{ Domain = $d; Finding = if ($_.ReadOnly) { 'INFO read-only DC not in silo' } else { 'FAIL DC not in silo' }; Object = $_.DC } }
    $pu = @(Get-ADGroupMember -Identity "$sid-525" -Server $d)
    foreach ($m in $pu) {
        if ($m.SID.Value -eq "$sid-500") { [pscustomobject]@{ Domain = $d; Finding = 'FAIL built-in Administrator (RID 500) is in Protected Users'; Object = $m.SamAccountName } }
        elseif ($m.objectClass -ne 'user') { [pscustomobject]@{ Domain = $d; Finding = "FAIL $($m.objectClass) in Protected Users"; Object = $m.SamAccountName } }
    }
    [pscustomobject]@{ Domain = $d; Finding = 'SUMMARY'; Object = ("silo users: {0}; silo computers: {1}; Protected Users members: {2}" -f
        @($Block3 | Where-Object { $_.Domain -eq $d -and $_.Type -eq 'user' }).Count,
        @($Block3 | Where-Object { $_.Domain -eq $d -and $_.Type -eq 'computer' }).Count, $pu.Count) }
}
$Block4 | Format-Table -AutoSize -Wrap

# =============================== BLOCK 5 =====================================
# Host state of every DC (WinRM). Run block 2 first: it supplies the enforce time.
# EXPECTED per DC:
#   KdcArmor 1 and KdcLevel 1 or 2 (1 = Supported, 2 = Always provide claims);
#   ClientArmor 1;
#   every channel "on" (the number after it is the record count);
#   KerbAudit shows Success and Failure;
#   TgtAfterEnforce True: the DC's own computer ticket was issued after the
#     silo was enforced, so it carries the silo claim. False = run
#     "klist -li 0x3e7 purge" on that DC (or reboot it);
#   LastBoot is informational: compare it with the time the channels were
#     enabled on that DC. Channels enabled after the last boot may not log
#     until the DC is restarted.
$EnforceUtc = ($Block2 | Where-Object { $_.EnforceChanged } | Sort-Object EnforceChanged | Select-Object -Last 1).EnforceChanged
if ($EnforceUtc) { $EnforceUtc = $EnforceUtc.ToUniversalTime() }
$probe = {
    param($Channels)
    $kdc = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters' -ErrorAction SilentlyContinue
    $krb = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters' -ErrorAction SilentlyContinue
    $txt = (klist -li 0x3e7 | Out-String)
    $tgtRaw = if ($txt -match 'Server:\s+krbtgt/[\s\S]*?Start Time:\s+(.+?)\s+\(local\)') { $Matches[1] } else { '' }
    $tgtUtc = $null
    try { if ($tgtRaw) { $tgtUtc = ([datetime]::Parse($tgtRaw)).ToUniversalTime() } } catch { }
    $ch = foreach ($c in $Channels) {
        $l = Get-WinEvent -ListLog $c -ErrorAction SilentlyContinue
        $short = ($c -split '/')[-1] -replace '-DomainController', ''
        if ($l) { "{0}={1}/{2}" -f $short, $(if ($l.IsEnabled) { 'on' } else { 'OFF' }), $l.RecordCount } else { "$short=MISSING" }
    }
    $aud = (auditpol /get /subcategory:'{0CCE9242-69AE-11D9-BED3-505054503030}' 2>$null | Where-Object { $_.Trim() } | Select-Object -Last 1)
    [pscustomobject]@{
        LastBoot    = (Get-CimInstance Win32_OperatingSystem).LastBootUpTime
        KdcArmor    = $kdc.EnableCbacAndArmor
        KdcLevel    = $kdc.CbacAndArmorLevel
        ClientArmor = $krb.EnableCbacAndArmor
        MachineTgt  = $tgtRaw
        TgtUtc      = $tgtUtc
        Channels    = ($ch -join '; ')
        KerbAudit   = if ($aud) { ($aud -replace '\s{2,}', ' : ').Trim() } else { 'not read' }
    }
}
$Block5 = foreach ($x in $AllDCs) {
    try {
        $h = Invoke-DcProbe -ComputerName $x.DC -ScriptBlock $probe -Arguments (, $Channels)
        [pscustomobject]@{
            Domain = $x.Domain; DC = $x.DC; LastBoot = $h.LastBoot
            KdcArmor = $h.KdcArmor; KdcLevel = $h.KdcLevel; ClientArmor = $h.ClientArmor
            MachineTgt = $h.MachineTgt
            TgtAfterEnforce = if ($EnforceUtc -and $h.TgtUtc) { $h.TgtUtc -gt $EnforceUtc } else { 'compare by hand' }
            Channels = $h.Channels; KerbAudit = $h.KerbAudit
        }
    } catch {
        [pscustomobject]@{ Domain = $x.Domain; DC = $x.DC; LastBoot = 'UNREACHABLE'; KdcArmor = ''; KdcLevel = ''; ClientArmor = ''
            MachineTgt = ''; TgtAfterEnforce = ''; Channels = $_.Exception.Message; KerbAudit = '' }
    }
}
"Silo enforce flag last changed (UTC): $EnforceUtc"
$Block5 | Format-List

# =============================== BLOCK 6 =====================================
# Events in the three Authentication channels on every DC, last $Hours hours.
# EXPECTED with the silo ENFORCED:
#   303 (ProtectedUserSuccesses) on the DCs of every domain that has Protected
#       Users members who logged on in the window;
#   105 / 106 (AuthenticationPolicyFailures) only for real denials;
#   305 / 306 must NOT appear any more (they are the audit-mode events);
#   100 / 104 (ProtectedUserFailures) only for NTLM or RC4 attempts.
#   A DC with no rows served no such request in the window. A whole DOMAIN with
#   no rows: check block 4 SUMMARY (no eligible accounts), block 1 (functional
#   level) and block 5 (channel state, last boot) for that domain.
$evProbe = {
    param($Channels, $Hours)
    foreach ($c in $Channels) {
        $total = (Get-WinEvent -ListLog $c -ErrorAction SilentlyContinue).RecordCount
        try {
            Get-WinEvent -FilterHashtable @{ LogName = $c; StartTime = (Get-Date).AddHours(-$Hours) } -MaxEvents 5000 -ErrorAction Stop |
                Select-Object LogName, Id, Message
        } catch {
            $none = $_.Exception.Message -match 'No events were found'
            [pscustomobject]@{ LogName = $c; Id = if ($none) { 0 } else { -1 }
                Message = if ($none) { "none in the window; $total record(s) in the log in total" } else { $_.Exception.Message } }
        }
    }
}
$Block6 = foreach ($x in $AllDCs) {
    $failed = $false
    try {
        $ev = @(Invoke-DcProbe -ComputerName $x.DC -ScriptBlock $evProbe -Arguments @($Channels, $Hours))
    } catch {
        $ev = @(); $failed = $true
        [pscustomobject]@{ Domain = $x.Domain; DC = $x.DC; Channel = 'ERROR'; Id = ''; Count = ''; Accounts = $_.Exception.Message; Devices = '' }
    }
    foreach ($n in ($ev | Where-Object { $_.Id -le 0 })) {
        [pscustomobject]@{ Domain = $x.Domain; DC = $x.DC
            Channel = (($n.LogName -split '/')[-1] -replace '-DomainController', '')
            Id = if ($n.Id -eq 0) { '-' } else { 'ERROR' }; Count = 0
            Accounts = "last $Hours h: $($n.Message)"; Devices = '' }
    }
    $ev = @($ev | Where-Object { $_.Id -gt 0 })
    foreach ($g in ($ev | Group-Object LogName, Id)) {
        $acc = $g.Group | ForEach-Object { if ($_.Message -match 'Account Name:\s+(\S+)') { $Matches[1] } } | Sort-Object -Unique
        $dev = $g.Group | ForEach-Object { if ($_.Message -match 'Device Name:\s+(\S+)') { $Matches[1] } } | Sort-Object -Unique
        [pscustomobject]@{
            Domain = $x.Domain; DC = $x.DC
            Channel = (($g.Group[0].LogName -split '/')[-1] -replace '-DomainController', '')
            Id = $g.Group[0].Id; Count = $g.Count
            Accounts = ($acc -join ', '); Devices = ($dev -join ', ')
        }
    }
}
$Block6 | Format-Table -AutoSize -Wrap

# =============================== BLOCK 7 =====================================
# Claims check. Run ON A MANAGEMENT MACHINE, not remotely. Two steps by hand:
#
#   runas /user:<DOMAIN>\<tier0-admin> cmd
#
# then, in the window that opens, paste the three lines below.
# EXPECTED: whoami lists  ad://ext/AuthenticationSilo  with the silo name
#           (present only while the silo is enforced and the account is
#           permitted + assigned); klist shows krbtgt with Cache Flags
#           0x41 -> PRIMARY FAST, lifetime 4:00, and the KDC that answered.
#           No AuthenticationSilo line = the account's KDC did not issue the
#           claim: check block 3 for that account and block 2 for that domain.
#
#   whoami /claims
#   klist
#   klist query_bind
#
# The machine's own ticket (device claim) cannot be displayed; its evidence is
# block 5 (TgtAfterEnforce True on the MM as well: klist -li 0x3e7 in an
# elevated prompt on the MM) together with the absence of event 105 naming
# that machine in block 6.

# Tier0-ManualChecks.ps1 v3 end
