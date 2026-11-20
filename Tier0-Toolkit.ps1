<#
===============================================================================
 Tier0-Toolkit.ps1
 Interactive toolkit for Active Directory Tier 0 enforcement with
 Authentication Policy Silos, Authentication Policies and Protected Users.

 VERSION HISTORY
   v1  2026-10-21  Initial release: menu core, settings file, plan/confirm/
                   execute flow, read-only mode, prerequisite checks, object
                   creation, account onboarding (cross-domain), log channels,
                   status/verification, event decoder, enforce/rollback.
   v2  2026-10-21  Parser + PSScriptAnalyzer pass (5.1 compatibility rules):
                   approved verbs (Wait-Menu, Import-Settings), $null-left
                   comparisons, [Console]::Clear() instead of Clear-Host.
   v3  2026-10-21  Menu reordered to execution order with step names instead
                   of phase labels; enforce step asks its own gate questions;
                   no external document references.
   v4  2026-11-02  Root/child awareness: Configuration-partition writes (create
                   silo/policy, enforce, rollback) only from the forest root;
                   child domains add their own DCs/MMs/accounts to the existing
                   silo. Always starts read-only. Existing silo/policy detected
                   on start and offered for configuration. Prerequisite report
                   adds silo/policy presence, membership (permitted + assigned)
                   for configured DCs/MMs, and deny-logon URA checks on the GPOs
                   linked to the DC and MM OUs.
   v5  2026-11-02  Silo status unified: one function produces the silo block
                   (objects, binding, enforce state, every member permitted vs
                   assigned, configured-but-missing hosts) used as the first
                   block of the prerequisite report and as the quick menu 5.
   v6  2026-11-02  Settings files from earlier versions are upgraded on load
                   (missing keys receive defaults and the file is rewritten).
                   Test guidance: RCG proof is the absence of a 4768 with client
                   address ::1 on the DC, not a 4624 field.
   v7  2026-11-02  Onboarding read pwdLastSet through Get-ADObject correctly
                   (PasswordLastSet is a Get-ADUser-only computed property and
                   failed the LDAP query). Account identities given as
                   NETBIOS\sam are resolved to the domain's DNS name. Banner
                   shows the PowerShell version and edition.
   v8  2026-11-04  Silo status always emits one row per configured DC, MM and
                   Tier 0 account (OK / FAIL with reason), instead of reporting
                   only missing ones; silo members not present in the settings
                   file are listed separately. List-type settings keys are
                   normalized to string arrays on load, so the JSON round-trip
                   cannot change how they are read.

 REQUIREMENTS
   - Windows PowerShell 5.1
   - RSAT: ActiveDirectory module (Get-ADAuthenticationPolicySilo etc.)
   - Run on a Tier 0 management machine as a Tier 0 account
   - WinRM to DCs/MMs for remote checks and channel enablement (optional;
     the toolkit reports what it cannot reach)

 DESIGN
   Every action builds a PLAN (the exact commands) and writes it to a file
   in the output folder BEFORE anything runs. In execute mode the admin must
   type YES to run the plan. In read-only mode nothing runs; the plan file is
   the deliverable and can be executed by the admin later.
   Settings live in one JSON file per domain next to the script.

 EXAMPLES in prompts use the fictional forest lab.sk (root) and rats.lab.sk
 (child). No real names, hosts or addresses are embedded in this file.
===============================================================================
#>

#Requires -Version 5.1
[CmdletBinding()]
param(
    [string]$Domain,                 # FQDN of the domain to work on; prompted if omitted
    [string]$SettingsFile            # explicit settings file; default <script dir>\Tier0-Toolkit.<domain>.json
)

Set-StrictMode -Version 2.0
$ErrorActionPreference = 'Stop'

# --------------------------------------------------------------------------
# Globals
# --------------------------------------------------------------------------
$script:ToolkitVersion = '8'
$script:ScriptDir      = Split-Path -Parent $MyInvocation.MyCommand.Path
$script:OutDir         = Join-Path $script:ScriptDir 'Tier0-Toolkit-Output'
$script:ReadOnly       = $true        # always starts read-only; menu M switches to execute mode
$script:IsForestRoot   = $false
$script:ForestRoot     = $null
$script:SiloObject     = $null        # existing silo, if found on start
$script:PolicyObject   = $null        # existing user policy, if found on start
$script:DomainMap      = $null        # NetBIOS -> DNS name cache for this forest
$script:Settings       = $null
$script:Domain         = $null
$script:DomainDC       = $null        # a writable DC of the selected domain, used for -Server

# --------------------------------------------------------------------------
# Console helpers
# --------------------------------------------------------------------------
function Write-Title   ([string]$t) { Write-Host ''; Write-Host ('=' * 78) -ForegroundColor DarkCyan; Write-Host " $t" -ForegroundColor Cyan; Write-Host ('=' * 78) -ForegroundColor DarkCyan }
function Write-Ok      ([string]$t) { Write-Host "  [OK]   $t" -ForegroundColor Green }
function Write-Warn    ([string]$t) { Write-Host "  [WARN] $t" -ForegroundColor Yellow }
function Write-Fail    ([string]$t) { Write-Host "  [FAIL] $t" -ForegroundColor Red }
function Write-Info    ([string]$t) { Write-Host "  [INFO] $t" -ForegroundColor Gray }
function Write-Mode {
    if ($script:ReadOnly) { Write-Host '  MODE: READ-ONLY  (plans are written, nothing is executed) - press M to switch' -ForegroundColor Yellow }
    else                  { Write-Host '  MODE: EXECUTE    (each plan requires a typed YES)' -ForegroundColor Magenta }
    if ($script:IsForestRoot) { Write-Host "  SCOPE: forest root ($($script:ForestRoot)) - all steps available" -ForegroundColor Gray }
    else { Write-Host "  SCOPE: child domain (root: $($script:ForestRoot)) - silo/policy creation, enforce and rollback are root-only" -ForegroundColor Gray }
    if ($script:SiloObject) { Write-Host ("  SILO : {0} exists (Enforce={1}, {2} member(s)) - write steps configure the existing object" -f $script:SiloObject.Name, $script:SiloObject.Enforce, @($script:SiloObject.Members).Count) -ForegroundColor Gray }
    else { Write-Host "  SILO : $($script:Settings.SiloName) not found in the forest" -ForegroundColor Gray }
}

function Read-Value {
    <# Prompt with default and example. Returns the string entered or the default. #>
    param([string]$Prompt, [string]$Default = '', [string]$Example = '')
    $hint = ''
    if ($Default) { $hint += " [default: $Default]" }
    if ($Example) { $hint += " (e.g. $Example)" }
    $v = Read-Host "  $Prompt$hint"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return $v.Trim()
}
function Read-YesNo {
    param([string]$Prompt, [bool]$Default = $false)
    $d = if ($Default) { 'Y/n' } else { 'y/N' }
    $v = Read-Host "  $Prompt [$d]"
    if ([string]::IsNullOrWhiteSpace($v)) { return $Default }
    return ($v.Trim().ToUpper() -in 'Y','YES')
}
function Read-List {
    <# Comma-separated list prompt; returns string[] #>
    param([string]$Prompt, [string[]]$Default = @(), [string]$Example = '')
    $v = Read-Value -Prompt $Prompt -Default ($Default -join ',') -Example $Example
    if ([string]::IsNullOrWhiteSpace($v)) { return @() }
    return @($v -split ',' | ForEach-Object { $_.Trim() } | Where-Object { $_ })
}
function Wait-Menu { [void](Read-Host '  Press Enter to return to the menu') }

# --------------------------------------------------------------------------
# Output folder and plan files
# --------------------------------------------------------------------------
function Initialize-Output {
    if (-not (Test-Path $script:OutDir)) { New-Item -ItemType Directory -Path $script:OutDir | Out-Null }
    $script:TranscriptFile = Join-Path $script:OutDir ("{0}_transcript.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))
    try { Start-Transcript -Path $script:TranscriptFile -Append | Out-Null } catch { Write-Warn "Transcript not started: $($_.Exception.Message)" }
}
function New-PlanFile {
    <# Writes the plan (commands) to a timestamped .ps1 and returns its path. #>
    param([string]$Action, [string[]]$Commands, [string]$Description)
    $stamp = Get-Date -Format 'yyyyMMdd_HHmmss'
    $safeDomain = ($script:Domain -replace '[^A-Za-z0-9.-]', '_')
    $file = Join-Path $script:OutDir ("{0}_{1}_{2}.ps1" -f $stamp, $safeDomain, $Action)
    $header = @(
        "# Tier0-Toolkit v$($script:ToolkitVersion) plan file"
        "# Action : $Action"
        "# Domain : $($script:Domain)"
        "# Created: $(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')"
        "# Mode   : $(if ($script:ReadOnly) {'READ-ONLY (not executed by the toolkit)'} else {'EXECUTE (see transcript for result)'})"
        "# $Description"
        "#"
        "# Review every line. Run with: powershell.exe -ExecutionPolicy Bypass -File `"$file`""
        "Import-Module ActiveDirectory -ErrorAction Stop"
        '$ErrorActionPreference = ''Stop'''
        ''
    )
    ($header + $Commands) | Set-Content -Path $file -Encoding UTF8
    return $file
}
function Invoke-Plan {
    <#
      Shows the plan, writes the plan file, asks for typed confirmation (execute mode)
      and runs each command in order, stopping at the first error.
    #>
    param([string]$Action, [string[]]$Commands, [string]$Description)
    Write-Host ''
    Write-Host '  ---------------------------- PLAN ----------------------------' -ForegroundColor White
    $n = 0
    foreach ($c in $Commands) { $n++; Write-Host ("  {0,3}: {1}" -f $n, $c) -ForegroundColor White }
    Write-Host '  --------------------------------------------------------------' -ForegroundColor White
    $file = New-PlanFile -Action $Action -Commands $Commands -Description $Description
    Write-Info "Plan written to $file"
    if ($script:ReadOnly) { Write-Warn 'Read-only mode: nothing executed.'; return $false }
    $answer = Read-Host '  Type YES (uppercase) to execute this plan, anything else to skip'
    if ($answer -cne 'YES') { Write-Warn 'Skipped by operator.'; return $false }
    $i = 0
    foreach ($c in $Commands) {
        $i++
        if ($c -match '^\s*#' -or [string]::IsNullOrWhiteSpace($c)) { continue }
        Write-Host ("  -> [{0}/{1}] {2}" -f $i, $Commands.Count, $c) -ForegroundColor DarkGray
        try {
            Invoke-Expression $c | Out-Host
        } catch {
            Write-Fail "Command $i failed: $($_.Exception.Message)"
            Write-Warn 'Execution stopped. Remaining commands were NOT run. Fix the cause and re-run the action.'
            return $false
        }
    }
    Write-Ok 'Plan executed.'
    return $true
}

# --------------------------------------------------------------------------
# Settings (one JSON per domain)
# --------------------------------------------------------------------------
function Get-DefaultSettings {
    param([string]$DomainFqdn)
    [ordered]@{
        _comment            = 'Tier0-Toolkit settings. One file per domain. Edit by hand or through the toolkit menu.'
        Domain              = $DomainFqdn
        SiloName            = 'AuthSilo-Tier0'
        UserPolicyName      = 'AuthPol-Tier0-User'
        UserTgtLifetimeMins = 240
        IncludeRodc         = $false
        ManagementMachines  = @()           # e.g. "MGMT01","MGMT02" (sAMAccountName without $)
        ManagementMachineOU = ''            # DN of the OU holding the MMs, e.g. OU=Tier0-MM,DC=lab,DC=sk (used for the deny-logon GPO check)
        Tier0AdminGroup     = 'Tier0-Admins' # group that must never appear in a deny list on DC/MM hosts
        Tier0Accounts       = @()           # e.g. "t0-adm1","t0-adm2" (sAMAccountName); may be in other domains: "rats.lab.sk\t0-adm3"
        ProtectedUsersAdd   = $true         # add Tier 0 accounts to Protected Users in step 4 (onboard accounts)
        _comment_channels   = 'Operational channels enabled in step 2 (logging) on DCs and MMs.'
        DcChannels          = @(
            'Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController',
            'Microsoft-Windows-Authentication/ProtectedUserFailures-DomainController',
            'Microsoft-Windows-Authentication/ProtectedUserSuccesses-DomainController')
        ClientChannels      = @('Microsoft-Windows-Authentication/ProtectedUser-Client')
        ChannelMaxSizeMB    = 64
    }
}
function Get-SettingsPath { if ($SettingsFile) { return $SettingsFile } ; return (Join-Path $script:ScriptDir ("Tier0-Toolkit.{0}.json" -f $script:Domain)) }
function Import-Settings {
    $path = Get-SettingsPath
    if (Test-Path $path) {
        $loaded = Get-Content $path -Raw | ConvertFrom-Json
        # Upgrade: add any key introduced by a newer toolkit version, keep existing values.
        $defaults = Get-DefaultSettings -DomainFqdn $script:Domain
        $added = @()
        foreach ($k in $defaults.Keys) {
            if (-not ($loaded.PSObject.Properties.Name -contains $k)) {
                $loaded | Add-Member -NotePropertyName $k -NotePropertyValue $defaults[$k]
                $added += $k
            }
        }
        # Normalize list-type keys to string arrays whatever shape the JSON held (array, scalar, comma-separated, null).
        foreach ($k in 'ManagementMachines','Tier0Accounts','DcChannels','ClientChannels') {
            $arr = @()
            foreach ($item in @($loaded.$k)) {
                if ($null -eq $item) { continue }
                foreach ($part in ([string]$item) -split ',') { if ($part.Trim()) { $arr += $part.Trim() } }
            }
            $loaded.$k = [string[]]$arr
        }
        $script:Settings = $loaded
        if ($added) { Save-Settings; Write-Warn ("Settings file upgraded; new key(s) added with defaults: {0}. Review them (menu item S)." -f ($added -join ', ')) }
        Write-Ok "Settings loaded from $path"
    } else {
        $script:Settings = [pscustomobject](Get-DefaultSettings -DomainFqdn $script:Domain)
        Save-Settings
        Write-Warn "No settings file found. Defaults written to $path - review them (menu item S)."
    }
}
function Save-Settings { $script:Settings | ConvertTo-Json -Depth 5 | Set-Content -Path (Get-SettingsPath) -Encoding UTF8 }
function Edit-Settings {
    Write-Title 'Settings'
    $s = $script:Settings
    $s.SiloName            = Read-Value 'Silo name'              $s.SiloName
    $s.UserPolicyName      = Read-Value 'User policy name'       $s.UserPolicyName
    $s.UserTgtLifetimeMins = [int](Read-Value 'User TGT lifetime (min)' $s.UserTgtLifetimeMins '240 (this design) or 120 (Microsoft Tier Model)')
    $s.IncludeRodc         = Read-YesNo 'Include read-only DCs in the silo?' ([bool]$s.IncludeRodc)
    $s.ManagementMachines  = Read-List 'Management machines (computer names)' $s.ManagementMachines 'MGMT01,MGMT02'
    $s.ManagementMachineOU = Read-Value 'OU (DN) that holds the management machines' $s.ManagementMachineOU 'OU=Tier0-MM,DC=lab,DC=sk'
    $s.Tier0AdminGroup     = Read-Value 'Tier 0 admin group (must never be denied on DC/MM)' $s.Tier0AdminGroup 'Tier0-Admins'
    $s.Tier0Accounts       = Read-List 'Tier 0 accounts (sAMAccountName, prefix other domains with domain\)' $s.Tier0Accounts 't0-adm1,rats.lab.sk\t0-adm3'
    $s.ProtectedUsersAdd   = Read-YesNo 'Add Tier 0 accounts to Protected Users when onboarding?' ([bool]$s.ProtectedUsersAdd)
    Save-Settings
    Write-Ok "Saved to $(Get-SettingsPath)"
}

# --------------------------------------------------------------------------
# AD helpers
# --------------------------------------------------------------------------
function Resolve-DomainName {
    <# Accepts a DNS name or a NetBIOS name and returns the DNS name of that domain in this forest. #>
    param([string]$Name)
    if ($Name -match '\.') { return $Name.ToLower() }
    if (-not $script:DomainMap) {
        $script:DomainMap = @{}
        foreach ($d in (Get-ADForest -Server $script:Domain).Domains) {
            try { $dd = Get-ADDomain -Identity $d; $script:DomainMap[$dd.NetBIOSName.ToUpper()] = $dd.DNSRoot.ToLower() } catch { }
        }
    }
    $key = $Name.ToUpper()
    if ($script:DomainMap.ContainsKey($key)) { return $script:DomainMap[$key] }
    throw "Domain '$Name' is not a domain of this forest (use the DNS name, e.g. rats.lab.sk)"
}
function Resolve-Account {
    <#
      Accepts "sam", "domain\sam" or a DN. Returns an object with DN, Domain (FQDN),
      Server (a DC of that domain) and the AD object.
    #>
    param([string]$Identity)
    $dom = $script:Domain; $sam = $Identity
    if ($Identity -match '^(?<d>[^\\]+)\\(?<s>.+)$') { $dom = Resolve-DomainName $Matches.d; $sam = $Matches.s }
    if ($Identity -match '^CN=') {
        $dom = (($Identity -split ',DC=' | Select-Object -Skip 1) -join '.')
        $obj = Get-ADObject -Identity $Identity -Server $dom -Properties sAMAccountName, objectClass, msDS-AssignedAuthNPolicySilo, msDS-AuthNPolicySiloMembersBL
    } else {
        $obj = Get-ADObject -Filter "sAMAccountName -eq '$sam'" -Server $dom -Properties sAMAccountName, objectClass, msDS-AssignedAuthNPolicySilo, msDS-AuthNPolicySiloMembersBL
        if (-not $obj) { throw "Account '$sam' not found in $dom" }
        if (@($obj).Count -gt 1) { throw "Account '$sam' is ambiguous in $dom" }
    }
    [pscustomobject]@{ Identity = $Identity; DN = $obj.DistinguishedName; Domain = $dom; Object = $obj; Sam = $obj.sAMAccountName; Class = $obj.objectClass }
}
function Get-DomainDCs {
    param([bool]$IncludeRodc = $false)
    $dcs = Get-ADDomainController -Filter * -Server $script:Domain
    if (-not $IncludeRodc) { $dcs = $dcs | Where-Object { -not $_.IsReadOnly } }
    return @($dcs)
}
function Get-RegistryValueRemote {
    param([string]$Computer, [string]$Path, [string]$Name)
    try {
        Invoke-Command -ComputerName $Computer -ErrorAction Stop -ScriptBlock {
            param($p, $n)
            try { (Get-ItemProperty -Path $p -Name $n -ErrorAction Stop).$n } catch { $null }
        } -ArgumentList $Path, $Name
    } catch { 'UNREACHABLE' }
}

function Update-Context {
    <# Determines forest root vs child and looks up existing silo/policy by the settings names. Called on start and after D/S. #>
    $dom = Get-ADDomain -Server $script:Domain
    $forest = Get-ADForest -Server $script:Domain
    $script:ForestRoot   = $forest.RootDomain
    $script:IsForestRoot = ($dom.DNSRoot -eq $forest.RootDomain)
    $script:DomainDC     = $dom.PDCEmulator
    $script:SiloObject   = Get-ADAuthenticationPolicySilo -Filter "Name -eq '$($script:Settings.SiloName)'" -Server $script:Domain -Properties Members, Enforce, UserAuthenticationPolicy, ComputerAuthenticationPolicy -ErrorAction SilentlyContinue
    $script:PolicyObject = Get-ADAuthenticationPolicy     -Filter "Name -eq '$($script:Settings.UserPolicyName)'" -Server $script:Domain -Properties Enforce, UserTGTLifetimeMins, UserAllowedToAuthenticateFrom -ErrorAction SilentlyContinue
}
function Assert-ForestRoot {
    param([string]$Action)
    if ($script:IsForestRoot) { return $true }
    Write-Warn "$Action writes to the Configuration partition and is available only when the toolkit is run against the forest root domain ($($script:ForestRoot))."
    return $false
}
function Get-SiloMembershipState {
    <# For a DN, returns Permitted (listed on the silo) and Assigned (attribute on the object, read from its own domain). #>
    param([string]$DN)
    $permitted = $false
    if ($script:SiloObject) { $permitted = (@($script:SiloObject.Members) -contains $DN) }
    $dom = (($DN -split ',DC=' | Select-Object -Skip 1) -join '.')
    $assigned = $false
    try { $o = Get-ADObject -Identity $DN -Server $dom -Properties msDS-AssignedAuthNPolicySilo; $assigned = [bool]$o.'msDS-AssignedAuthNPolicySilo' } catch { }
    [pscustomobject]@{ DN = $DN; Permitted = $permitted; Assigned = $assigned }
}
function Get-DenyLogonGpoState {
    <#
      Reads the GPOs linked to the given OU (gPLink only) and, for each, the five SeDeny* rights
      from its XML report. Only the linked GPOs are fetched. Returns one object per GPO.
    #>
    param([string]$OuDN)
    if (-not (Get-Module -ListAvailable GroupPolicy)) { return @([pscustomobject]@{ Gpo = '(GroupPolicy module missing)'; Linked = $false; Rights = @{}; Error = 'Install RSAT: Group Policy Management' }) }
    Import-Module GroupPolicy -ErrorAction Stop
    $rights = 'SeDenyNetworkLogonRight','SeDenyInteractiveLogonRight','SeDenyRemoteInteractiveLogonRight','SeDenyBatchLogonRight','SeDenyServiceLogonRight'
    $links = (Get-GPInheritance -Target $OuDN -Domain $script:Domain).GpoLinks
    foreach ($l in $links) {
        $found = @{}
        try {
            [xml]$x = Get-GPOReport -Guid $l.GpoId -ReportType Xml -Domain $script:Domain
            $ns = New-Object System.Xml.XmlNamespaceManager($x.NameTable)
            $ns.AddNamespace('g', 'http://www.microsoft.com/GroupPolicy/Settings')
            $ns.AddNamespace('s', 'http://www.microsoft.com/GroupPolicy/Settings/Security')
            foreach ($n in $x.SelectNodes('//s:UserRightsAssignment', $ns)) {
                $name = $n.SelectSingleNode('s:Name', $ns).InnerText
                if ($rights -contains $name) { $found[$name] = @($n.SelectNodes('s:Member/s:Name', $ns) | ForEach-Object { $_.InnerText }) }
            }
            [pscustomobject]@{ Gpo = $l.DisplayName; Linked = $l.Enabled; Enforced = $l.Enforced; Order = $l.Order; Rights = $found; Error = $null }
        } catch { [pscustomobject]@{ Gpo = $l.DisplayName; Linked = $l.Enabled; Enforced = $l.Enforced; Order = $l.Order; Rights = $found; Error = $_.Exception.Message } }
    }
}

function Get-SiloStatusRows {
    <#
      Produces the silo block used by both the prerequisite report and the quick status:
      objects and binding, enforce state, every current member (permitted vs assigned, read
      from the member's own domain), and configured DCs/MMs that are not members yet.
      Returns rows with Area/Item/Status/Detail. LDAP reads only; no WinRM.
    #>
    $s = $script:Settings
    $rows = New-Object System.Collections.Generic.List[object]
    function Add-R ($item, $status, $detail) { $rows.Add([pscustomobject]@{ Area = 'Silo'; Item = $item; Status = $status; Detail = $detail }) }
    Update-Context
    if ($script:SiloObject) {
        $bound = if ($script:SiloObject.UserAuthenticationPolicy) { ($script:SiloObject.UserAuthenticationPolicy -split ',')[0] -replace '^CN=','' } else { 'NONE' }
        Add-R "Silo $($s.SiloName)" 'OK' ("exists; Enforce={0}; members={1}; userPolicy={2}" -f $script:SiloObject.Enforce, @($script:SiloObject.Members).Count, $bound)
        if (-not $script:SiloObject.UserAuthenticationPolicy) { Add-R 'User policy binding' 'FAIL' 'silo has no user policy bound' }
    } else { Add-R "Silo $($s.SiloName)" 'FAIL' 'not created yet (menu 3 from the forest root domain)' }
    if ($script:PolicyObject) {
        Add-R "Policy $($s.UserPolicyName)" 'OK' ("exists; Enforce={0}; TGT={1} min; from-condition={2}" -f $script:PolicyObject.Enforce, $script:PolicyObject.UserTGTLifetimeMins, $(if ($script:PolicyObject.UserAllowedToAuthenticateFrom) {'set'} else {'NONE'}))
        if ($script:SiloObject -and ($script:SiloObject.Enforce -ne $script:PolicyObject.Enforce)) { Add-R 'Enforce consistency' 'WARN' ("silo Enforce={0}, policy Enforce={1} - the silo switch governs silo members; set both the same" -f $script:SiloObject.Enforce, $script:PolicyObject.Enforce) }
    } else { Add-R "Policy $($s.UserPolicyName)" 'FAIL' 'not created yet (menu 3 from the forest root domain)' }

    # Configured objects (settings inward): one row per configured DC, MM and account - always,
    # so a compliant object shows OK rather than producing no row.
    $memberDNs = @()
    if ($script:SiloObject) { $memberDNs = @($script:SiloObject.Members) }
    $configuredDNs = New-Object System.Collections.Generic.List[string]
    function Add-ConfiguredRow ([string]$label, [string]$dn, [string]$notMemberWhy) {
        $configuredDNs.Add($dn)
        $m = Get-SiloMembershipState -DN $dn
        $st  = if ($m.Permitted -and $m.Assigned) {'OK'} elseif (-not $script:SiloObject) {'INFO'} else {'FAIL'}
        $why = if ($m.Permitted -and $m.Assigned) {'permitted + assigned'}
               elseif ($m.Permitted) {'permitted on the silo but NOT assigned on the object - not protected'}
               elseif ($m.Assigned)  {'assigned on the object but NOT permitted on the silo'}
               else { $notMemberWhy }
        Add-R $label $st $why
    }
    try {
        $dcs = Get-ADDomainController -Filter * -Server $script:Domain | Where-Object { $s.IncludeRodc -or -not $_.IsReadOnly }
        foreach ($dc in $dcs) { Add-ConfiguredRow "DC $($dc.Name)" $dc.ComputerObjectDN 'not a silo member' }
        foreach ($mm in @($s.ManagementMachines)) {
            try { $c = Get-ADComputer -Identity $mm -Server $script:Domain; Add-ConfiguredRow "MM $mm" $c.DistinguishedName 'not a silo member' }
            catch { Add-R "MM $mm" 'FAIL' "computer object not found in $($script:Domain)" }
        }
        foreach ($acct in @($s.Tier0Accounts)) {
            try { $a = Resolve-Account $acct; Add-ConfiguredRow "Account $acct" $a.DN 'not onboarded yet (menu 4)' }
            catch { Add-R "Account $acct" 'FAIL' $_.Exception.Message }
        }
    } catch { Add-R 'Configured objects' 'WARN' $_.Exception.Message }

    # Silo members that are NOT in the settings file (silo outward) - strays or another domain's objects.
    foreach ($m in $memberDNs) {
        if ($configuredDNs -contains $m) { continue }
        $dom = (($m -split ',DC=' | Select-Object -Skip 1) -join '.')
        try {
            $o = Get-ADObject -Identity $m -Server $dom -Properties msDS-AssignedAuthNPolicySilo, sAMAccountName
            $assigned = [bool]$o.'msDS-AssignedAuthNPolicySilo'
            Add-R ("Member {0} ({1}, {2})" -f $o.sAMAccountName, $o.ObjectClass, $dom) $(if ($assigned) {'OK'} else {'FAIL'}) $(if ($assigned) {'permitted + assigned; not listed in the settings file'} else {'permitted on the silo but NOT assigned on the object - not protected; not listed in the settings file'})
        } catch { Add-R "Member $m" 'WARN' "cannot read from $dom : $($_.Exception.Message)" }
    }

    return $rows
}

# --------------------------------------------------------------------------
# Module: Prerequisite checks (read-only)
# --------------------------------------------------------------------------
function Test-Prerequisites {
    Write-Title "Prerequisite checks for $($script:Domain)"
    $s = $script:Settings
    $report = New-Object System.Collections.Generic.List[object]
    function Add-Row ($area, $item, $status, $detail) { $report.Add([pscustomobject]@{ Area = $area; Item = $item; Status = $status; Detail = $detail }) }

    # 1. Module and rights
    try { Import-Module ActiveDirectory -ErrorAction Stop; Add-Row 'Local' 'ActiveDirectory module' 'OK' (Get-Module ActiveDirectory).Version } catch { Add-Row 'Local' 'ActiveDirectory module' 'FAIL' $_.Exception.Message; Write-Fail 'RSAT ActiveDirectory module is required.'; return }

    # 2. Domain / forest facts
    $dom = Get-ADDomain -Server $script:Domain
    $forest = Get-ADForest -Server $script:Domain
    $dflOk = ([int]$dom.DomainMode -ge 6) -or ($dom.DomainMode -match '2012R2|2016|2019|2022|2025')
    Add-Row 'Domain' 'Domain functional level' $(if ($dflOk) {'OK'} else {'FAIL'}) "$($dom.DomainMode) (>= Windows2012R2 required)"
    Add-Row 'Domain' 'Forest root' 'INFO' $forest.RootDomain
    Add-Row 'Domain' 'Is forest root' 'INFO' ($dom.DNSRoot -eq $forest.RootDomain)
    $script:DomainDC = $dom.PDCEmulator

    # 3. DC inventory
    $dcs = Get-ADDomainController -Filter * -Server $script:Domain
    foreach ($dc in $dcs) {
        Add-Row 'DC' $dc.HostName 'INFO' ("OS={0}; RODC={1}; Site={2}" -f $dc.OperatingSystem, $dc.IsReadOnly, $dc.Site)
    }

    # 3a. Silo block (shared with menu 5)
    foreach ($r in (Get-SiloStatusRows)) { $report.Add($r) }

    # 4. DNS SRV records and ports (from this machine)
    foreach ($srv in @("_kerberos._tcp.dc._msdcs.$($script:Domain)", "_ldap._tcp.dc._msdcs.$($script:Domain)", "_kerberos._tcp.$($script:Domain)")) {
        try { $r = Resolve-DnsName -Name $srv -Type SRV -ErrorAction Stop; Add-Row 'DNS' $srv 'OK' (($r | Where-Object Type -eq 'SRV' | ForEach-Object { $_.NameTarget }) -join ', ') }
        catch { Add-Row 'DNS' $srv 'FAIL' $_.Exception.Message }
    }
    foreach ($dc in $dcs) {
        foreach ($port in 88, 389, 445, 3389, 5985) {
            $t = Test-NetConnection -ComputerName $dc.HostName -Port $port -WarningAction SilentlyContinue -InformationLevel Quiet
            Add-Row 'Port' "$($dc.HostName):$port" $(if ($t) {'OK'} else {'FAIL'}) $(switch ($port) { 88 {'Kerberos'} 389 {'LDAP'} 445 {'SMB'} 3389 {'RDP'} 5985 {'WinRM (needed for remote checks)'} })
        }
    }

    # 5. Armoring / RCG / channels on DCs and MMs (remote registry via WinRM)
    $kdcPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters'
    $krbPath = 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\Kerberos\Parameters'
    $rcgPath = 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\CredentialsDelegation'
    $hosts = @($dcs | ForEach-Object { [pscustomobject]@{ Name = $_.HostName; Role = 'DC' } })
    foreach ($mm in @($s.ManagementMachines)) { $hosts += [pscustomobject]@{ Name = "$mm.$($script:Domain)"; Role = 'MM' } }
    foreach ($h in $hosts) {
        if ($h.Role -eq 'DC') {
            $v = Get-RegistryValueRemote $h.Name $kdcPath 'EnableCbacAndArmor'
            Add-Row 'Armoring' "$($h.Name) KDC EnableCbacAndArmor" $(if ($v -eq 1) {'OK'} elseif ($v -eq 'UNREACHABLE') {'SKIP'} else {'FAIL'}) "value=$v (1 = KDC support for claims/armoring enabled)"
            $v2 = Get-RegistryValueRemote $h.Name $kdcPath 'CbacAndArmorLevel'
            Add-Row 'Armoring' "$($h.Name) KDC CbacAndArmorLevel" 'INFO' "value=$v2 (1=Supported, 2=Always provide claims, 3=Fail unarmored - must NOT be 3)"
            if ($v2 -eq 3) { Add-Row 'Armoring' "$($h.Name) Fail unarmored" 'FAIL' 'KDC rejects unarmored requests - lockout risk for non-armoring clients' }
        }
        $v = Get-RegistryValueRemote $h.Name $krbPath 'EnableCbacAndArmor'
        Add-Row 'Armoring' "$($h.Name) Kerberos client EnableCbacAndArmor" $(if ($v -eq 1) {'OK'} elseif ($v -eq 'UNREACHABLE') {'SKIP'} else {'FAIL'}) "value=$v (1 = client requests claims/armoring)"
        $v = Get-RegistryValueRemote $h.Name $rcgPath 'AllowProtectedCreds'
        Add-Row 'RCG' "$($h.Name) host AllowProtectedCreds" $(if ($v -eq 1) {'OK'} elseif ($v -eq 'UNREACHABLE') {'SKIP'} else {'WARN'}) "value=$v (1 = host accepts Remote Credential Guard / Restricted Admin)"
        $channels = if ($h.Role -eq 'DC') { $s.DcChannels } else { $s.ClientChannels }
        foreach ($ch in $channels) {
            $en = try { Invoke-Command -ComputerName $h.Name -ErrorAction Stop -ScriptBlock { param($c) (wevtutil gl $c 2>$null | Select-String '^enabled:').ToString() } -ArgumentList $ch } catch { 'UNREACHABLE' }
            Add-Row 'Channel' "$($h.Name) $($ch.Split('/')[-1])" $(if ($en -match 'true') {'OK'} elseif ($en -eq 'UNREACHABLE') {'SKIP'} else {'FAIL'}) "$en"
        }
    }

    # 6. Account readiness
    foreach ($acct in @($s.Tier0Accounts)) {
        try {
            $a = Resolve-Account $acct
            $u = Get-ADUser -Identity $a.DN -Server $a.Domain -Properties PasswordLastSet, MemberOf, msDS-AssignedAuthNPolicySilo, msDS-AuthNPolicySiloMembersBL
            $pu = $null -ne ($u.MemberOf | Where-Object { $_ -match '^CN=Protected Users,' })
            Add-Row 'Account' "$acct PasswordLastSet" $(if ($u.PasswordLastSet -and $u.PasswordLastSet -gt (Get-Date).AddYears(-10)) {'INFO'} else {'WARN'}) "$($u.PasswordLastSet) (must be after the DFL raise / modern-DC date for AES keys)"
            Add-Row 'Account' "$acct Protected Users" $(if ($pu) {'OK'} else {'INFO'}) $(if ($pu) {'member'} else {'not a member yet'})
            Add-Row 'Account' "$acct silo permitted" $(if ($u.'msDS-AuthNPolicySiloMembersBL') {'OK'} else {'INFO'}) "$($u.'msDS-AuthNPolicySiloMembersBL')"
            Add-Row 'Account' "$acct silo assigned"  $(if ($u.'msDS-AssignedAuthNPolicySilo') {'OK'} else {'INFO'}) "$($u.'msDS-AssignedAuthNPolicySilo')"
            if ($u.'msDS-AuthNPolicySiloMembersBL' -and -not $u.'msDS-AssignedAuthNPolicySilo') { Add-Row 'Account' "$acct" 'FAIL' 'Permitted but NOT assigned - the KDC does not apply the silo' }
        } catch { Add-Row 'Account' $acct 'FAIL' $_.Exception.Message }
    }

    # 7. Deny-logon User Rights on the GPOs linked to the DC OU and the MM OU (only linked GPOs are read)
    $dangerous = @($s.Tier0AdminGroup, 'Domain Admins', 'Enterprise Admins', 'Administrators', 'BUILTIN\\Administrators')
    $rightNames = @{ SeDenyNetworkLogonRight='Deny network'; SeDenyInteractiveLogonRight='Deny local'; SeDenyRemoteInteractiveLogonRight='Deny RDS'; SeDenyBatchLogonRight='Deny batch'; SeDenyServiceLogonRight='Deny service' }
    $ous = @([pscustomobject]@{ Label = 'DC OU'; DN = $dom.DomainControllersContainer })
    if ($s.ManagementMachineOU) { $ous += [pscustomobject]@{ Label = 'MM OU'; DN = $s.ManagementMachineOU } } else { Add-Row 'URA' 'MM OU' 'WARN' 'ManagementMachineOU not set in settings - deny-logon check skipped for MMs' }
    foreach ($ou in $ous) {
        $states = @(Get-DenyLogonGpoState -OuDN $ou.DN)
        $anyDeny = $false
        foreach ($g in $states) {
            if ($g.Error) { Add-Row 'URA' "$($ou.Label) GPO $($g.Gpo)" 'WARN' $g.Error; continue }
            if ($g.Rights.Count -eq 0) { continue }
            $anyDeny = $true
            foreach ($r in $g.Rights.Keys) {
                $members = $g.Rights[$r]
                $hit = @($members | Where-Object { $m = $_; $dangerous | Where-Object { $m -like "*$_" } })
                $st = if ($hit) {'FAIL'} else {'OK'}
                Add-Row 'URA' ("{0} {1} [{2}]" -f $ou.Label, $g.Gpo, $rightNames[$r]) $st ("members: {0}{1}" -f ($members -join ', '), $(if ($hit) { "  <- Tier 0 identity in a deny list on a Tier 0 host: " + ($hit -join ', ') } else { '' }))
            }
            $missing = @($rightNames.Keys | Where-Object { -not $g.Rights.ContainsKey($_) })
            if ($missing) { Add-Row 'URA' "$($ou.Label) $($g.Gpo) coverage" 'INFO' ("rights not set in this GPO: " + (($missing | ForEach-Object { $rightNames[$_] }) -join ', ')) }
            if ($g.Enforced) { Add-Row 'URA' "$($ou.Label) $($g.Gpo) link" 'WARN' 'link is Enforced - user-rights lists are not merged; an Enforced GPO replaces lower lists' }
        }
        if (-not $anyDeny) { Add-Row 'URA' "$($ou.Label) deny-logon GPO" 'FAIL' "no GPO linked to $($ou.DN) sets any SeDeny* right - Tier 0 separation not in place here" }
    }

    # Output
    $report | Format-Table -AutoSize -Wrap | Out-Host
    $csv = Join-Path $script:OutDir ("{0}_{1}_prereq-report.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $script:Domain)
    $report | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Info "Report saved to $csv"
    $fails = @($report | Where-Object Status -eq 'FAIL').Count
    if ($fails) { Write-Warn "$fails item(s) FAIL. SKIP = host unreachable over WinRM (check manually)." } else { Write-Ok 'No FAIL items.' }
}

# --------------------------------------------------------------------------
# Module: Step 3 - create silo and policy (audit mode)
# --------------------------------------------------------------------------
function Invoke-CreateObjects {
    $s = $script:Settings
    Update-Context
    $existingSilo = $script:SiloObject
    $existingPol  = $script:PolicyObject
    if ($script:IsForestRoot) {
        Write-Title 'Step 3 - Create silo and user policy (AUDIT mode, no impact); add DC + MM computer accounts'
        if ($existingSilo) { Write-Info "Silo '$($s.SiloName)' already exists (Enforce=$($existingSilo.Enforce)). Creation skipped; configuring the existing silo." }
        if ($existingPol)  { Write-Info "Policy '$($s.UserPolicyName)' already exists. Creation skipped." }
    } else {
        Write-Title "Step 3 - Add this domain's DCs and MMs to the existing silo (child domain)"
        if (-not $existingSilo) { Write-Fail "Silo '$($s.SiloName)' does not exist in the forest. Create it first from the forest root domain ($($script:ForestRoot))."; return }
        if (-not $existingSilo.UserAuthenticationPolicy) { Write-Warn 'The silo has no user policy bound yet; bind it from the forest root before onboarding accounts.' }
    }
    $createAllowed = $script:IsForestRoot

    $sddl = 'O:SYG:SYD:(XA;OICI;CR;;;WD;(@USER.ad://ext/AuthenticationSilo == "' + $s.SiloName + '"))'
    $cmds = @()
    $cmds += "# Silo and user policy for $($script:Domain). Objects are forest-wide; membership is per account."
    if ($createAllowed -and -not $existingSilo) {
        $cmds += "New-ADAuthenticationPolicySilo -Name '$($s.SiloName)' -Description 'Tier 0 boundary: DCs, management machines and their admin accounts' -Enforce:`$false -ProtectedFromAccidentalDeletion:`$true -Server '$($script:Domain)'"
    }
    if ($createAllowed -and -not $existingPol) {
        $cmds += "New-ADAuthenticationPolicy -Name '$($s.UserPolicyName)' -Description 'Tier 0 user policy: $($s.UserTgtLifetimeMins)-min TGT, TGT issuance restricted to silo devices' -Enforce:`$false -ProtectedFromAccidentalDeletion:`$true -UserTGTLifetimeMins $($s.UserTgtLifetimeMins) -RollingNTLMSecret 'Disabled' -UserAllowedToAuthenticateFrom '$sddl' -Server '$($script:Domain)'"
    }
    if ($createAllowed -and (-not $existingSilo -or -not $existingSilo.UserAuthenticationPolicy)) {
        $cmds += "Set-ADAuthenticationPolicySilo -Identity '$($s.SiloName)' -UserAuthenticationPolicy '$($s.UserPolicyName)' -Server '$($script:Domain)'"
    }
    $cmds += "# Domain controllers (IncludeRodc=$($s.IncludeRodc))"
    foreach ($dc in Get-DomainDCs -IncludeRodc ([bool]$s.IncludeRodc)) {
        $m = Get-SiloMembershipState -DN $dc.ComputerObjectDN
        if ($m.Permitted -and $m.Assigned) { $cmds += "# $($dc.Name): already permitted + assigned, skipped"; continue }
        if (-not $m.Permitted) { $cmds += "Grant-ADAuthenticationPolicySiloAccess -Identity '$($s.SiloName)' -Account '$($dc.ComputerObjectDN)' -Server '$($script:Domain)' -ErrorAction Stop" }
        if (-not $m.Assigned)  { $cmds += "Set-ADAccountAuthenticationPolicySilo -Identity '$($dc.ComputerObjectDN)' -AuthenticationPolicySilo '$($s.SiloName)' -Server '$($script:Domain)' -ErrorAction Stop" }
    }
    $cmds += '# Management machines'
    foreach ($mm in @($s.ManagementMachines)) {
        $c = Get-ADComputer -Identity $mm -Server $script:Domain
        $m = Get-SiloMembershipState -DN $c.DistinguishedName
        if ($m.Permitted -and $m.Assigned) { $cmds += "# $($mm): already permitted + assigned, skipped"; continue }
        if (-not $m.Permitted) { $cmds += "Grant-ADAuthenticationPolicySiloAccess -Identity '$($s.SiloName)' -Account '$($c.DistinguishedName)' -Server '$($script:Domain)' -ErrorAction Stop" }
        if (-not $m.Assigned)  { $cmds += "Set-ADAccountAuthenticationPolicySilo -Identity '$($c.DistinguishedName)' -AuthenticationPolicySilo '$($s.SiloName)' -Server '$($script:Domain)' -ErrorAction Stop" }
    }
    if (@($cmds | Where-Object { $_ -notmatch '^#' }).Count -eq 0) { Write-Ok 'Nothing to do - silo, policy and all configured members are already in place.'; return }
    if (-not $s.ManagementMachines) { Write-Warn 'No management machines in settings - only DCs will be silo members. Set them in menu item S.' }
    $ran = Invoke-Plan -Action $(if ($createAllowed) {'CreateObjects'} else {'AddMembers'}) -Commands $cmds -Description $(if ($createAllowed) {'Create or configure silo + user policy in audit mode; add DC and MM computer accounts (permit + assign).'} else {'Add this domain''s DC and MM computer accounts to the existing forest silo (permit + assign).'})
    if ($ran) { Update-Context; Write-Warn 'Reboot the DCs and MMs (or purge their machine ticket cache) so their TGT carries the silo claim.'; Show-Status }
}

# --------------------------------------------------------------------------
# Module: Step 4 - onboard accounts (supports other domains in the forest)
# --------------------------------------------------------------------------
function Invoke-OnboardAccounts {
    Write-Title 'Step 4 - Onboard Tier 0 accounts (silo permit + assign, Protected Users)'
    $s = $script:Settings
    $list = Read-List 'Accounts to onboard now (blank = all from settings)' @($s.Tier0Accounts) 't0-demo-adm,rats.lab.sk\t0-adm3'
    if (-not $list) { Write-Warn 'Nothing to do.'; return }
    Update-Context
    if (-not $script:SiloObject) { Write-Fail "Silo '$($s.SiloName)' does not exist in the forest. Create it first from the forest root domain ($($script:ForestRoot))."; return }
    $cmds = @("# Onboard accounts: each account in its own domain (-Server). Both silo attributes are required.")
    foreach ($acct in $list) {
        try { $a = Resolve-Account $acct } catch { Write-Fail $_.Exception.Message; continue }
        $m = Get-SiloMembershipState -DN $a.DN
        if ($m.Permitted -and $m.Assigned) { Write-Info "$acct is already permitted + assigned; only Protected Users will be checked."; }
        if ($a.Class -ne 'user') { Write-Warn "$acct is a $($a.Class) - computer/service accounts must never join Protected Users; silo steps only."; }
        $u = Get-ADObject -Identity $a.DN -Server $a.Domain -Properties pwdLastSet
        $pls = if ($u.pwdLastSet -and $u.pwdLastSet -gt 0) { [DateTime]::FromFileTime($u.pwdLastSet) } else { 'never / must change at next logon' }
        Write-Info "$acct -> $($a.DN) (password last set: $pls)"
        if (-not $m.Permitted) { $cmds += "Grant-ADAuthenticationPolicySiloAccess -Identity '$($s.SiloName)' -Account '$($a.DN)' -Server '$($a.Domain)' -ErrorAction Stop" }
        if (-not $m.Assigned)  { $cmds += "Set-ADAccountAuthenticationPolicySilo -Identity '$($a.DN)' -AuthenticationPolicySilo '$($s.SiloName)' -Server '$($a.Domain)' -ErrorAction Stop" }
        if ($s.ProtectedUsersAdd -and $a.Class -eq 'user') {
            $inPu = $false
            try { $inPu = [bool]@((Get-ADUser -Identity $a.DN -Server $a.Domain -Properties MemberOf).MemberOf | Where-Object { $_ -match '^CN=Protected Users,' }).Count } catch { }
            if ($inPu) { $cmds += "# ${acct}: already in Protected Users, skipped" }
            else { $cmds += "Add-ADGroupMember -Identity 'Protected Users' -Members '$($a.DN)' -Server '$($a.Domain)' -ErrorAction Stop" }
        }
    }
    Write-Warn 'Gate: each account must have AES keys (password set on a modern DC). A Protected User without AES keys is locked out immediately.'
    $ran = Invoke-Plan -Action 'OnboardAccounts' -Commands $cmds -Description 'Permit + assign accounts to the silo; add users to Protected Users (per account domain).'
    if ($ran) { Write-Info 'Have each user log off/on (or klist purge) so the next TGT carries the silo claim. Expect 305 only from non-silo devices.' }
}

# --------------------------------------------------------------------------
# Module: Step 2 - enable operational channels
# --------------------------------------------------------------------------
function Invoke-EnableChannels {
    Write-Title 'Step 2 - Enable Authentication operational channels on DCs and MMs'
    $s = $script:Settings
    $max = [int]$s.ChannelMaxSizeMB * 1MB
    $cmds = @('# Channels are disabled by default. Each DC logs the requests it services, so enable on every DC.')
    foreach ($dc in Get-DomainDCs -IncludeRodc $true) {
        foreach ($ch in $s.DcChannels) {
            $cmds += "Invoke-Command -ComputerName '$($dc.HostName)' -ScriptBlock { wevtutil sl '$ch' /e:true /ms:$max }"
        }
    }
    foreach ($mm in @($s.ManagementMachines)) {
        foreach ($ch in $s.ClientChannels) {
            $cmds += "Invoke-Command -ComputerName '$mm.$($script:Domain)' -ScriptBlock { wevtutil sl '$ch' /e:true }"
        }
    }
    $cmds += '# Optional Security-log subcategories (secondary signal). Uncomment to apply on DCs via auditpol:'
    $cmds += "# Invoke-Command -ComputerName <dc> -ScriptBlock { auditpol /set /subcategory:'Kerberos Authentication Service' /success:enable /failure:enable; auditpol /set /subcategory:'Kerberos Service Ticket Operations' /success:enable /failure:enable; auditpol /set /subcategory:'User / Device Claims' /success:enable }"
    Invoke-Plan -Action 'EnableChannels' -Commands $cmds -Description 'Enable AuthenticationPolicyFailures / ProtectedUser* channels on DCs and ProtectedUser-Client on MMs.' | Out-Null
}

# --------------------------------------------------------------------------
# Module: Status and verification (read-only)
# --------------------------------------------------------------------------
function Show-Status {
    Write-Title "Silo status (quick) - $($script:Domain)"
    $rows = Get-SiloStatusRows
    $rows | Format-Table Item, Status, Detail -AutoSize -Wrap | Out-Host
    $fails = @($rows | Where-Object Status -eq 'FAIL').Count
    if ($fails) { Write-Warn "$fails FAIL item(s)." } else { Write-Ok 'No FAIL items.' }
    $csv = Join-Path $script:OutDir ("{0}_{1}_silo-status.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $script:Domain)
    $rows | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Info "Saved to $csv"
}
function Show-RecentEvents {
    Write-Title 'Recent silo / Protected Users events on DCs (last 24h)'
    $hours = [int](Read-Value 'Hours to look back' '24')
    $start = (Get-Date).AddHours(-$hours)
    $ids = @{ 305='AUDIT: TGT would be denied (device fails from-condition)'; 306='AUDIT: service ticket would be denied'; 105='ENFORCED: TGT denied'; 106='ENFORCED: service ticket denied'; 101='ENFORCED: NTLM refused by policy'; 303='Protected User AES TGT issued'; 100='Protected User NTLM refused'; 104='Protected User DES/RC4 refused' }
    $all = foreach ($dc in Get-DomainDCs -IncludeRodc $true) {
        foreach ($ch in $script:Settings.DcChannels) {
            try {
                Get-WinEvent -ComputerName $dc.HostName -FilterHashtable @{ LogName = $ch; StartTime = $start } -ErrorAction Stop |
                    ForEach-Object {
                        $x = [xml]$_.ToXml()
                        $d = @{}; foreach ($n in $x.Event.EventData.Data) { if ($n.Name) { $d[$n.Name] = $n.'#text' } }
                        [pscustomobject]@{ Time = $_.TimeCreated; DC = $dc.Name; Id = $_.Id; Meaning = $ids[[int]$_.Id]; Account = ($d['AccountName'], $d['TargetUserName'] | Where-Object { $_ } | Select-Object -First 1); Device = $d['DeviceName']; Client = $d['ClientAddress']; Result = $d['Status'] }
                    }
            } catch { if ($_.Exception.Message -notmatch 'No events') { Write-Warn "$($dc.Name)/$($ch.Split('/')[-1]): $($_.Exception.Message)" } }
        }
    }
    if (-not $all) { Write-Info 'No events in the window. If channels were never enabled, run step 2 (logging) and generate a known-bad test.'; return }
    $all | Sort-Object Time -Descending | Format-Table Time, DC, Id, Account, Device, Client, Result, Meaning -AutoSize -Wrap | Out-Host
    $all | Group-Object Id | ForEach-Object { Write-Info ("{0,4} x {1}  {2}" -f $_.Count, $_.Name, $ids[[int]$_.Name]) }
    Write-Host ''
    Write-Host '  305 decoder: Device blank + 0x12 = request unarmored (fix client armoring GPO / non-domain source);' -ForegroundColor DarkGray
    Write-Host '               Device named + 0xC  = armored, device not in silo or not yet rebooted after assignment.' -ForegroundColor DarkGray
    $csv = Join-Path $script:OutDir ("{0}_{1}_events.csv" -f (Get-Date -Format 'yyyyMMdd_HHmmss'), $script:Domain)
    $all | Export-Csv -Path $csv -NoTypeInformation -Encoding UTF8
    Write-Info "Saved to $csv"
}

# --------------------------------------------------------------------------
# Module: Enforce / rollback / remove account
# --------------------------------------------------------------------------
function Invoke-Enforce {
    Write-Title 'Step 8 - ENFORCE silo and user policy'
    $s = $script:Settings
    if (-not (Assert-ForestRoot 'Enforce')) { return }
    Update-Context
    if (-not $script:SiloObject -or -not $script:PolicyObject) { Write-Fail 'Silo or policy not found; nothing to enforce.'; return }
    if ($script:SiloObject.Enforce -and $script:PolicyObject.Enforce) { Write-Ok 'Silo and policy are already enforced.'; return }
    Write-Info 'Enforcement is forest-wide: it applies to silo members in every domain, including child domains.'
    Write-Host '  Enforcement blocks logons that audit mode only reported. Answer each question; any NO stops here.' -ForegroundColor Yellow
    $gate = @(
        'Status (menu 5) shows every silo member as Assigned = True',
        'Every DC and MM was rebooted (or had its machine ticket purged) after it was added to the silo',
        'All onboarded accounts have AES keys (password set on a modern DC) and show event 303 on a DC',
        'A known-bad logon (silo account from a non-silo device) produced event 305 and it is visible in the SIEM',
        'Events (menu 6) show no 305/306 for legitimate activity over the agreed soak period',
        'Every 100/104 (Protected Users NTLM/RC4 refusals) has a traced root cause',
        'Manual mstsc /remoteGuard from an MM to a DC succeeds for an onboarded account',
        'A break-glass account logon to a DC console was tested within the last 30 days',
        'The rollback (menu 9) has been rehearsed once in this domain'
    )
    $i = 0
    foreach ($q in $gate) {
        $i++
        if (-not (Read-YesNo ("  [{0}/{1}] {2}?" -f $i, $gate.Count, $q))) { Write-Warn 'Gate not met. Nothing changed.'; return }
    }
    $cmds = @(
        "Set-ADAuthenticationPolicy     -Identity '$($s.UserPolicyName)' -Enforce:`$true -Server '$($script:Domain)'",
        "Set-ADAuthenticationPolicySilo -Identity '$($s.SiloName)'       -Enforce:`$true -Server '$($script:Domain)'"
    )
    $ran = Invoke-Plan -Action 'Enforce' -Commands $cmds -Description 'Switch policy and silo from audit to enforce. Takes effect on the next TGT request (klist purge to test now).'
    if ($ran) {
        Write-Warn 'Next: repeat the known-bad logon - expect event 105 and a failed logon. Legitimate MM->DC activity must produce no 105/106/101.'
        Write-Warn 'Then, in this order and re-testing after each: require Remote Credential Guard on the MM (client policy), apply the deny-logon GPOs to the pilot scope, apply the network ACL to the DCs.'
    }
}
function Invoke-Rollback {
    Write-Title 'Rollback - silo and policy back to AUDIT'
    $s = $script:Settings
    if (-not (Assert-ForestRoot 'Rollback')) { return }
    $cmds = @(
        "Set-ADAuthenticationPolicySilo -Identity '$($s.SiloName)'       -Enforce:`$false -Server '$($script:Domain)'",
        "Set-ADAuthenticationPolicy     -Identity '$($s.UserPolicyName)' -Enforce:`$false -Server '$($script:Domain)'"
    )
    Invoke-Plan -Action 'Rollback' -Commands $cmds -Description 'Stop blocking, keep configuration. Existing tickets are unaffected until renewed.' | Out-Null
}
function Remove-AccountFromTier0 {
    Write-Title 'Remove one account from the silo and Protected Users'
    $s = $script:Settings
    $acct = Read-Value 'Account (sam, domain\sam or DN)' '' 't0-demo-adm'
    if (-not $acct) { return }
    $a = Resolve-Account $acct
    $cmds = @(
        "Set-ADObject -Identity '$($a.DN)' -Clear msDS-AssignedAuthNPolicySilo -Server '$($a.Domain)'",
        "Revoke-ADAuthenticationPolicySiloAccess -Identity '$($s.SiloName)' -Account '$($a.DN)' -Server '$($a.Domain)' -Confirm:`$false"
    )
    if ($a.Class -eq 'user' -and (Read-YesNo 'Also remove from Protected Users?')) {
        $cmds += "Remove-ADGroupMember -Identity 'Protected Users' -Members '$($a.DN)' -Server '$($a.Domain)' -Confirm:`$false"
    }
    Invoke-Plan -Action 'RemoveAccount' -Commands $cmds -Description "Remove $acct from silo (both attributes) and optionally Protected Users." | Out-Null
}

# --------------------------------------------------------------------------
# Module: Known-bad test helper and ticket check (guidance + commands)
# --------------------------------------------------------------------------
function Show-TestGuidance {
    Write-Title 'Test commands for administrators'
    $s = $script:Settings
    Write-Host @"
  1. Ticket check for an account (run on an MM; the inner window is ELEVATED on purpose -
     runas starts a filtered token and klist would otherwise show 0 tickets):
       runas /user:$($script:Domain.Split('.')[0].ToUpper())\<account> "powershell.exe -NoExit -Command Start-Process powershell -Verb RunAs -ArgumentList '-NoExit','-Command','klist tgt'"
     Expected for a Protected User: AES-256, End Time = Start + 4:00, Renew Time = End Time.

  2. Known-bad test (audit mode): log on with a silo account from a domain-joined machine that is NOT a silo member.
     Expected on the DC: event 305 in AuthenticationPolicyFailures-DomainController with the device named and Result 0xC.
     In enforce mode: event 105 and the logon fails.

  3. Silo claim present on a rebooted host (run on that host, elevated):   whoami /claims
     Expected: ad://ext/AuthenticationSilo = $($s.SiloName) for a silo user.

  4. RCG proof on a DC: Security 4624 Logon Type 10 for the account AND no 4768 for that account with
     Client Address ::1 (or the DC's own address) during the session. A ::1 4768 means the password reached the DC.

  5. Channel sanity on a DC:   wevtutil gl "Microsoft-Windows-Authentication/AuthenticationPolicyFailures-DomainController"
"@
}

# --------------------------------------------------------------------------
# Menu
# --------------------------------------------------------------------------
function Select-Domain {
    if ($Domain) { $script:Domain = $Domain.ToLower(); return }
    $current = try { (Get-ADDomain).DNSRoot } catch { $env:USERDNSDOMAIN }
    $script:Domain = (Read-Value 'Domain to work on (FQDN)' $current 'lab.sk or rats.lab.sk').ToLower()
}
function Show-Menu {
    [Console]::Clear()
    Write-Title "Tier0-Toolkit v$($script:ToolkitVersion)   domain: $($script:Domain)"
    Write-Mode
    Write-Host "  Output : $($script:OutDir)" -ForegroundColor Gray
    Write-Host ("  Host   : PowerShell {0} ({1})" -f $PSVersionTable.PSVersion, $PSVersionTable.PSEdition) -ForegroundColor Gray
    Write-Host ''
    Write-Host '  Steps in execution order:' -ForegroundColor White
    Write-Host '   1  Check prerequisites        (full report: silo block, DFL, DCs, DNS, ports, armoring, RCG, channels, accounts, deny-logon GPOs)'
    Write-Host '   2  Enable logging             (operational event channels on DCs and MMs)'
    if ($script:IsForestRoot) { Write-Host '   3  Create silo and policy     (AUDIT mode; add DC + MM computer accounts) -> reboot DCs/MMs afterwards' }
    else                      { Write-Host '   3  Add DCs/MMs to the silo     (existing forest silo; creation is root-only) -> reboot afterwards' }
    Write-Host '   4  Onboard Tier 0 accounts    (silo permit + assign, Protected Users; cross-domain aware)'
    Write-Host '   5  Silo status (quick)        (same silo block as in 1, LDAP only: objects, members permitted vs assigned)'
    Write-Host '   6  Events                     (305/306/105/106/101/303/100/104 from all DCs, with decoder)'
    Write-Host '   7  Test commands              (ticket check, known-bad logon, claims - for administrators)'
    if ($script:IsForestRoot) { Write-Host '   8  ENFORCE                    (asks gate questions, then switches silo + policy to enforce)' }
    else                      { Write-Host '   8  ENFORCE                    (root-only)' -ForegroundColor DarkGray }
    Write-Host '  Recovery:'
    if ($script:IsForestRoot) { Write-Host '   9  Rollback to audit' }
    else                      { Write-Host '   9  Rollback to audit          (root-only)' -ForegroundColor DarkGray }
    Write-Host '  10  Remove one account from silo / Protected Users'
    Write-Host ''
    Write-Host '   S  Settings (edit and save JSON)      M  Toggle read-only / execute mode'
    Write-Host '   O  Open output folder                  D  Change domain'
    Write-Host '   Q  Quit'
    Write-Host ''
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------
try { Import-Module ActiveDirectory -ErrorAction Stop } catch { Write-Host 'RSAT ActiveDirectory module not found. Install RSAT and run again.' -ForegroundColor Red; exit 1 }
Initialize-Output
Select-Domain
Import-Settings
try { Update-Context } catch { Write-Fail "Cannot read domain/forest context: $($_.Exception.Message)"; exit 1 }

while ($true) {
    Show-Menu
    $choice = (Read-Host '  Select').Trim().ToUpper()
    try {
        switch ($choice) {
            '1'  { Test-Prerequisites; Wait-Menu }
            '2'  { Invoke-EnableChannels; Wait-Menu }
            '3'  { Invoke-CreateObjects; Wait-Menu }
            '4'  { Invoke-OnboardAccounts; Wait-Menu }
            '5'  { Show-Status; Wait-Menu }
            '6'  { Show-RecentEvents; Wait-Menu }
            '7'  { Show-TestGuidance; Wait-Menu }
            '8'  { Invoke-Enforce; Wait-Menu }
            '9'  { Invoke-Rollback; Wait-Menu }
            '10' { Remove-AccountFromTier0; Wait-Menu }
            'S'  { Edit-Settings; Update-Context; Wait-Menu }
            'M'  { $script:ReadOnly = -not $script:ReadOnly; if (-not $script:ReadOnly) { Write-Warn 'Execute mode: plans will run after a typed YES.'; Start-Sleep -Seconds 1 } }
            'O'  { Start-Process explorer.exe $script:OutDir }
            'D'  { $Domain = $null; Select-Domain; Import-Settings; Update-Context }
            'Q'  { break }
            default { }
        }
    } catch {
        Write-Fail $_.Exception.Message
        Wait-Menu
    }
    if ($choice -eq 'Q') { break }
}
try { Stop-Transcript | Out-Null } catch { }
# Tier0-Toolkit.ps1 v8 end
