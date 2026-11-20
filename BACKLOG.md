# Tier0-Toolkit backlog

Open items carried over from the design sessions, in rough priority order.
Move an item to the version history of the script when it lands.

## Lab confirmations pending (code may need adjusting)

1. **Deny-logon GPO XML parse `[M]`** — confirm the element names used by
   `Get-DenyLogonGpoState` (`UserRightsAssignment` / `Name` / `Member/Name`,
   Security namespace) against a real `Get-GPOReport -ReportType Xml` output.
   A mismatch surfaces as a WARN row with the parser message; fix the XPath
   from that message.
2. **`CbacAndArmorLevel` registry value `[M]`** — verify name and meaning on a
   DC where the KDC armoring GPO is applied
   (`HKLM\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System\KDC\Parameters`)
   and align the prerequisite-report wording (1=Supported, 2=Always provide
   claims, 3=Fail unarmored).
3. **Cross-domain enforcement `[M]`** — child-domain account in the
   root-created silo: assignment via `-Server`, claim issuance by child DCs,
   305/105 behaviour. Run the audit→enforce test matrix in the child before
   multi-domain rollout.
4. **gMSA SAM name length** — no documented gMSA failure >15 chars on 2012+;
   if long names are wanted, lab-test Install-/Test-ADServiceAccount with a
   20-char SamAccountName before changing any naming guidance.

## Features queued

5. **Local-host short-circuit** — when the target of a registry/channel check
   is the machine the toolkit runs on, read directly instead of WinRM
   loopback (removes the WinRM dependency for on-DC lab runs).
6. **Settings save-only-on-change** — the Settings page currently rewrites the
   JSON on every exit; optionally detect no-op and skip the write.
7. **PowerShell 7 notice** — startup warning when `$PSVersionTable.PSEdition`
   is Core: untested, GroupPolicy module not validated under 7; then a lab run
   under pwsh to decide support.
8. **URA GPO creation support** — menu item generating the three tier
   deny-logon GPO definitions (plan-file only; URA cannot be set via
   Set-GPRegistryValue, so emit a GPMC/LGPO import artifact or documented
   manual steps).
9. **Pester test suite** — at minimum: settings load/upgrade/normalize,
   Resolve-Account / Resolve-DomainName, plan-file generation (no execution).
10. **Event export for SIEM use-case validation** — menu 6 already exports
    CSV; add per-use-case filters once the SIEM use-case definitions exist
    (kept in the rollout document, outside this repo).

## Accepted limitations (documented, not planned)

- No automation of armoring/RCG GPOs or network ACLs; prerequisite report
  verifies them only.
- No DC computer policy (destination boundary is URA + network by design).
- `Invoke-Expression` for plan execution stays (plans are self-generated;
  the plan file + typed YES is the control).
