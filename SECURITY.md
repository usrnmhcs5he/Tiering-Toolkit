# Security policy

The toolkit changes Active Directory authentication settings for Tier 0 accounts, so reports about its security are welcome.

## Supported versions

Only the latest version of each script on the `main` branch is supported. A fix is released as a new version of the affected script; older versions are not patched.

## Reporting a vulnerability

Do not open a public issue for a security problem, because a public issue discloses the problem before a fix exists.

Use GitHub's private reporting instead: open the **Security** tab of this repository and choose **Report a vulnerability**. The report is visible only to the maintainer.

Details that help:

- the script and its version (shown in the banner and in the last line of the file),
- the Windows and Windows PowerShell version,
- the menu item or script block involved,
- the steps to reproduce the problem and the expected result.

Do not include real environment data in a report: no host, domain, account or OU names, no IP addresses, SIDs or GUIDs, no settings JSON and no files from the output folder. Replace them with the fictional names used in the README (`lab.sk`, `DC01`, `MGMT01`, `t0-demo-adm`).

## What to expect

The project is maintained in spare time. Reports are handled on a best-effort basis, with no guaranteed response time.

## Scope

In scope: flaws in the scripts of this repository, for example a write action that runs without the saved plan and the typed `YES`, an action that runs outside its domain scope, a plan built from unvalidated input, or sensitive data written where it does not belong.

Out of scope: vulnerabilities in Windows, Active Directory, Kerberos or the RSAT modules. Report those to Microsoft.

## Version

Document v1, 2026-11-22.
