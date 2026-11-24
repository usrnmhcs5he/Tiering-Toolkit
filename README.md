<div align="center">

# 🛡️ Tier0-Toolkit

**Interactive PowerShell toolkit for rolling out Active Directory Tier 0 enforcement with Authentication Policy Silos, Authentication Policies and the Protected Users group, repeatably across many domains.**

![Windows PowerShell](https://img.shields.io/badge/Windows%20PowerShell-5.1-5391FE?logo=powershell&logoColor=white)
![Active Directory](https://img.shields.io/badge/Active%20Directory-DFL%202012%20R2%2B-0078D4)
![Tier0-Toolkit](https://img.shields.io/badge/Tier0--Toolkit-v8-2EA44F)
![Tier0-PawCheck](https://img.shields.io/badge/Tier0--PawCheck-v4-2EA44F)
![Tier0-ManualChecks](https://img.shields.io/badge/Tier0--ManualChecks-v3-2EA44F)
![PSScriptAnalyzer](https://img.shields.io/badge/PSScriptAnalyzer-5.1%20compatibility%20clean-brightgreen)
[![CI](https://github.com/usrnmhcs5he/Tiering-Toolkit/actions/workflows/ci.yml/badge.svg?branch=main)](https://github.com/usrnmhcs5he/Tiering-Toolkit/actions/workflows/ci.yml)
![Starts read-only](https://img.shields.io/badge/starts-read--only-yellow)
![License](https://img.shields.io/badge/license-MIT-blue)

</div>

The toolkit automates object creation, account onboarding, log-channel enablement, status/verification and the enforce/rollback switch, in the order they must be applied, and never acts without showing the exact commands first.

---

## 📁 Files

| File | Purpose | Runs on |
|---|---|---|
| `Tier0-Toolkit.ps1` v8 | Menu-driven toolkit: prerequisite checks, object creation, account onboarding, channel enablement, status, event decoder, enforce/rollback | Tier 0 management machine (RSAT) |
| `Tier0-PawCheck.ps1` v4 | Read-only readiness check from a Windows PAW: DNS SRV, DC/MM reachability, time, RDP client policy | Non-domain-joined Windows PAW |
| `Tier0-ManualChecks.ps1` v3 | Read-only verification of the silo across all domains of one forest, run by hand block by block: functional level, silo and policy per DC, members, reverse checks, DC host state, channel events | Tier 0 management machine or DC (RSAT) |
| [`docs/ManualChecks.md`](docs/ManualChecks.md) | Documentation for `Tier0-ManualChecks.ps1`: how to run it, expected result of every block, known limitations | |
| `Tier0-Toolkit.<domain>.json` | Settings, one per domain; created with defaults on first run and upgraded in place when a newer toolkit version adds keys | next to the toolkit |
| [`SECURITY.md`](SECURITY.md) | How to report a security problem in the scripts privately | n/a |
| `Tier0-Toolkit-Output\` | Plan files, reports (CSV), transcript | next to the toolkit |

## 📦 Requirements

- Windows PowerShell 5.1 (`powershell.exe`, edition *Desktop*): minimum and the tested version. The banner shows the running version. PowerShell 7 is untested; the ActiveDirectory module is natively compatible with 7, the GroupPolicy module used by the deny-logon check is not tested by Microsoft under 7 and may report WARN there
- RSAT: Active Directory module (`Get-ADAuthenticationPolicySilo` must exist) and Group Policy Management module (for the deny-logon GPO check; the check reports a warning without it)
- Run as a Tier 0 account on a management machine that is itself a silo member
- WinRM (TCP 5985) to domain controllers and management machines for remote registry/channel checks and channel enablement; without it those rows report `SKIP` and the channel plans must be run on each host manually
- Domain functional level Windows Server 2012 R2 or later
- Domain, Enterprise and Schema rights as applicable: creating silos/policies writes to the Configuration partition (Enterprise Admins by default); assigning accounts writes to the account's own domain

## 🔒 Safety model

1. **Plan first.** Every write action builds the list of commands, prints it, and saves it as `Tier0-Toolkit-Output\<timestamp>_<domain>_<action>.ps1` *before* anything runs.
2. **Typed confirmation.** In execute mode the operator must type `YES` (uppercase). Anything else skips the plan.
3. **Always starts read-only.** Nothing is executed until the operator switches to execute mode with menu `M`; in read-only mode the plan file is the deliverable and can be reviewed, edited and run later.
4. **Stop on first error.** A failing command stops the plan; remaining commands are not run.
5. **Audit by default.** Silo and policy are created with `Enforce:$false`. Enforcement is a separate, gated menu item.
6. **Transcript** of every session in the output folder.
7. **Forest-root awareness.** Silos and policies live in the Configuration partition. Creating them, binding the policy, enforcing and rolling back are offered only when the toolkit runs against the forest root domain. From a child domain the toolkit adds that domain's DCs, MMs and accounts to the existing silo and runs all read-only steps.
8. **Existing objects are detected on start** (by the names in settings) and configured rather than recreated; members and accounts already permitted and assigned are skipped in the plans.

## 🚀 Quick start

```powershell
# On the management machine, elevated, as a Tier 0 account:
.\Tier0-Toolkit.ps1 -Domain lab.sk        # starts read-only; press M in the menu to enable execution
.\Tier0-Toolkit.ps1 -Domain rats.lab.sk   # child domain: membership and onboarding only
```

The banner shows the mode, the scope (forest root or child domain) and whether the silo already exists.

Menu items 1–8 are in execution order; run them top to bottom per domain.

| Menu | Step | What it does |
|---|---|---|
| `S` | Settings | Silo/policy names, TGT lifetime, management machines and their OU, Tier 0 admin group, Tier 0 accounts, RODC inclusion |
| `1` | Check prerequisites | Full read-only report. First block is the silo block (below), then DFL, DC inventory, DNS SRV, ports, armoring and RCG registry on DCs/MMs, channel state, account readiness, deny-logon user rights on the GPOs linked to the DC OU and the MM OU. Uses WinRM; takes minutes on larger domains |
| `2` | Enable logging | Enable the operational channels (DCs: `AuthenticationPolicyFailures`, `ProtectedUserFailures`, `ProtectedUserSuccesses`; MMs: `ProtectedUser-Client`). Done before any object exists so the first write is already audited |
| `3` | Create silo and policy (root) / Add DCs and MMs (child) | Root: create silo + user policy in **audit** mode if absent, bind the policy, add writable DCs and MMs (permit **and** assign). Child: add this domain's DCs and MMs to the existing silo. **Reboot DCs and MMs afterwards** so their machine ticket carries the silo claim |
| `4` | Onboard accounts | Permit + assign each account in its own domain; add users to Protected Users |
| `5` | Silo status (quick) | The silo block alone: LDAP reads only, seconds. Run after onboarding, after reboots, or whenever the silo picture is in question |
| `6` | Events | 305/306/105/106/101/303/100/104 from all DCs with a decoder |
| `7` | Test commands | Printed commands for administrators: ticket check, known-bad logon, claims |
| `8` | Enforce (root only) | Asks nine gate questions (assigned members, reboots, AES keys, known-bad 305 seen, no 305/306 for legitimate activity, 100/104 root-caused, RCG tested, break-glass tested, rollback rehearsed); any NO stops. Then switches policy + silo to enforce |
| `9` | Rollback (root only) | Policy + silo back to audit |
| `10` | Remove account | Clears the assigned attribute, revokes silo access, optional Protected Users removal |

After enforcement the toolkit prints the remaining manual steps in order: require Remote Credential Guard on the MM (client policy), apply the deny-logon GPOs to the pilot scope, apply the network ACL to the DCs, re-testing after each. These three are applied in GPMC and on the network, not by the toolkit.

## 🌐 Cross-domain accounts

Silos and policies are forest objects. Accounts from any domain can be members; the assignment is written to the account's own domain, which ADAC cannot do and does not display. Enter such accounts in settings as `rats.lab.sk\t0-adm3` (a NetBIOS prefix such as `RATS\t0-adm3` is accepted and resolved to the DNS name); the toolkit resolves the domain, adds `-Server` to every command and reads the verification attributes from the right domain. Protected Users is per domain; the toolkit uses the group of the account's domain.

## 🔎 Reading the results

- **Status (`5`)**: every silo member must show `Assigned = True`. *Permitted but not assigned* means the KDC does not apply the silo to that object.
- **Events (`6`)**, 305 decoder:
  - Device blank, result `0x12` - the request was **unarmored**: Kerberos client armoring GPO missing on the source, or the source is not domain-joined.
  - Device named, result `0xC` - armored and evaluated, device not in the silo **or not rebooted** since assignment.
  - After enforcement the same cases appear as **105**.
- **Prerequisite report (`1`)**: `FAIL` must be resolved; `SKIP` means the host was unreachable over WinRM and must be checked by hand; `WARN` is advisory.

## 🧱 The silo block

One function produces this block for both menu `1` and menu `5`, so the table shape and CSV columns are identical:

- silo and user policy present, enforce state of each (with a warning when they differ), policy bound to the silo, TGT lifetime, from-condition set;
- **one row per configured object, always**: every DC of the domain (enumerated), every management machine and every Tier 0 account from the settings file gets an explicit verdict - `permitted + assigned` (OK), `permitted but NOT assigned` / `assigned but NOT permitted` / `not a silo member` (FAIL once the silo exists), or `not found`;
- **members not in the settings file** are listed separately (silo outward), so strays and other domains' objects still show, with the same assigned check.

## 🚫 Deny-logon GPO check

The prerequisite report reads the GPOs **linked** to the Domain Controllers OU and to the management-machine OU from settings (`ManagementMachineOU`), fetches the XML report of only those GPOs, and extracts the five deny rights (`SeDenyNetworkLogonRight`, `SeDenyInteractiveLogonRight`, `SeDenyRemoteInteractiveLogonRight`, `SeDenyBatchLogonRight`, `SeDenyServiceLogonRight`) with their member lists. It reports:

- `FAIL` when no linked GPO sets any deny right on that OU (Tier 0 separation not in place), or when the Tier 0 admin group, `Domain Admins`, `Enterprise Admins` or `Administrators` appears in a deny list on a Tier 0 host;
- `INFO` for rights a GPO leaves unset;
- `WARN` for an Enforced link, because user-rights lists are not merged across GPOs.

This is a configuration check, not an effective-rights check; the resulting state on a host is confirmed with `gpresult /h` there. Confidence on the XML element names used to read the rights is moderate until confirmed against a real report; a parsing problem is reported as `WARN` with the message, never as a silent pass.

## ⚙️ Settings file example

```json
{
  "Domain": "lab.sk",
  "SiloName": "AuthSilo-Tier0",
  "UserPolicyName": "AuthPol-Tier0-User",
  "UserTgtLifetimeMins": 240,
  "IncludeRodc": false,
  "ManagementMachines": ["MGMT01", "MGMT02"],
  "ManagementMachineOU": "OU=Tier0-MM,DC=lab,DC=sk",
  "Tier0AdminGroup": "Tier0-Admins",
  "Tier0Accounts": ["t0-adm1", "rats.lab.sk\\t0-adm3"],
  "ProtectedUsersAdd": true,
  "ChannelMaxSizeMB": 64
}
```

## 💻 PAW checker

```powershell
.\Tier0-PawCheck.ps1 -Domain lab.sk -ManagementMachines mgmt01.lab.sk
```
Prints and saves a report: DC discovery via SRV records, A-record resolution, TCP 88/389 to DCs and 3389 to MMs, clock offset, classic `mstsc.exe` presence and the credential-delegation client policy. It changes nothing.

## 🔬 Manual checks

`Tier0-ManualChecks.ps1` verifies the silo by hand across every domain of the forest and changes nothing. Edit the three values in block 0 (`$Domains` with the root first, `$SiloName`, `$Hours`), run block 0, then run any other block on its own. It reads the silo and policy from every DC, every member from its own domain, the host state of every DC over WinRM and the events of the three Authentication channels, so domains can be compared with each other.

Blocks, expected results and known limitations are in [`docs/ManualChecks.md`](docs/ManualChecks.md).

## ⚠️ Known limitations (v1)

- No automation of GPOs (armoring, RCG host setting, URA deny-logon). The prerequisite report tells you whether they are in effect.
- No computer policy is created on domain controllers: such a policy applies to every service a DC provides and would affect all domain users; the destination boundary comes from deny-logon GPOs and the network ACL.
- `Invoke-Expression` runs the plan commands; plan files are generated by the toolkit from settings and AD lookups, never from free text, but review them as you would any script.
- Static checks only so far (parser, PSScriptAnalyzer 5.1 compatibility); no Pester suite yet. Runtime behaviour against AD is verified in the lab.

## 🧹 Hygiene

No hostnames, addresses, account names or organisation identifiers are embedded. Example values use the fictional `lab.sk` / `rats.lab.sk` forest and `MGMT01`. Generated output contains the real names of the environment it was run in and stays inside that environment.

## 🏷️ Version

Toolkit v8, PAW checker v4, manual checks v3, README v15, 2026-11-24. All three scripts pass the PowerShell parser and PSScriptAnalyzer 1.23 with the Windows PowerShell 5.1 compatibility rules (no errors). `.github/workflows/ci.yml` v2 repeats both checks on GitHub on every push, under Windows PowerShell 5.1: a parse error, a PSScriptAnalyzer error or a `PSUseCompatible*` warning fails the run. The workflow only parses and analyses the scripts; it does not run them. The CI badge at the top shows the result of the latest run on `main`. Version history is kept at the top of each script.

## 📄 License

MIT, see [`LICENSE`](LICENSE).
