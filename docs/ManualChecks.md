# Tier0-ManualChecks

`Tier0-ManualChecks.ps1` is a read-only companion to `Tier0-Toolkit.ps1`. It verifies the Tier 0 authentication policy silo across all domains of one forest and changes nothing in the directory or on any host.

It is meant for administrators who want to check the configuration by hand, block by block, and to compare domains with each other, for example a child domain whose Authentication event channels stay empty.

## Requirements

- Windows PowerShell 5.1, run elevated. Reading the machine ticket in block 5 needs elevation.
- RSAT ActiveDirectory module.
- A management machine or a domain controller, and an account that can read all domains of the forest.
- WinRM (TCP 5985) to every domain controller for blocks 5 and 6. A domain controller that does not answer is reported as a row and the block continues.

## How to run it

1. Open the script in the PowerShell ISE or keep it open next to an elevated console.
2. Edit the three values in block 0. These are the only values to change:

   ```powershell
   $Domains  = @('lab.sk', 'rats.lab.sk')   # root first, then every child domain
   $SiloName = 'AuthSilo-Tier0'
   $Hours    = 24                            # look-back window for event counts
   ```

3. Run block 0. It loads the module, lists the domain controllers of every domain and defines the helper functions.
4. Run any other block by selecting it and pressing F8 in the ISE, or by pasting it into the console.

Blocks 1, 2, 3, 6 and 7 need only block 0. Two blocks use the results of an earlier block in the same session:

- Block 4 counts silo users and silo computers from the result of block 3. Without block 3 those two counts read 0.
- Block 5 takes the enforce time from the result of block 2. Without block 2 the `TgtAfterEnforce` column reads "compare by hand".

Running the whole file in one go runs the blocks in the right order.

## Blocks and expected results

| Block | What it reads | Expected |
|---|---|---|
| 0 | Variables, domain controller inventory, helper functions | One line with the domains, the number of domain controllers found and the silo DN |
| 1 | Domain functional level per domain | `Windows2012R2Domain` or higher in every domain |
| 2 | Silo and user policy as seen by every domain controller of every domain | Identical rows. `SiloEnforce` and `PolicyEnforce` True, `ComputerSlot` and `ServiceSlot` False, `UserTGT` 240, `FromHasSilo` True. `EnforceChanged` is the time the silo Enforce flag last changed |
| 3 | Every silo member, read from its own domain | `OK permitted + assigned` on every row, no direct policy, users in Protected Users |
| 4 | Reverse checks per domain | No rows for: assigned but not permitted, direct policy assignment, writable domain controller outside the silo, built-in Administrator (RID 500) in Protected Users, non-user object in Protected Users. One `SUMMARY` row per domain with the counts of silo users, silo computers and Protected Users members |
| 5 | Host state of every domain controller over WinRM | KDC armoring value 1 with level 1 or 2, client armoring value 1, all three Authentication channels on (with record count), Kerberos audit Success and Failure, `TgtAfterEnforce` True |
| 6 | Events in the three Authentication channels per domain controller for the last `$Hours` hours | Grouped by channel and event ID with account and device names. With the silo enforced: 303 for Protected Users logons, 105 and 106 only for real denials, no 305 or 306, 100 and 104 only for NTLM or RC4 attempts. An empty window states the total record count of the log |
| 7 | Claims check by hand on a management machine (comment block only) | `whoami /claims` lists `ad://ext/AuthenticationSilo` with the silo name |

A row in block 2 that differs from the others, or shows `ERROR`, means the Configuration partition has not replicated to that domain controller.

`TgtAfterEnforce` False in block 5 means the computer ticket of that domain controller is older than the enforcement and carries no silo claim. Run `klist -li 0x3e7 purge` on that host, or restart it.

## Reading an empty domain

Events are written by the KDC of the account's own domain. A domain with no silo users and no Protected Users members shows no events, and that is a correct configuration. Check the `SUMMARY` row of block 4 first, then block 1 (functional level) and block 5 (channel state) for that domain.

In an enforced silo an empty `AuthenticationPolicyFailures` channel is the healthy state. Event 303 is the routine evidence that the configuration is in use, and it requires Protected Users membership.

## Design rules

- Read-only. The script contains no `Set-`, `New-AD*`, `Remove-` or `Add-` directory cmdlets, no `wevtutil sl` and no `auditpol /set`. `auditpol` is called with `/get` only.
- Every remote call starts with a 3-second test of TCP 5985, then uses `Invoke-Command` with open and operation timeouts. An unreachable domain controller becomes a row and the block continues.
- The machine the script runs on is probed directly, without remoting.
- Each domain controller is named on screen before it is contacted.
- No real names, addresses or identifiers. Examples use `lab.sk` and `rats.lab.sk` only.

## Known limitations

- Tested interactively in a two-domain lab only. There are no Pester tests.
- Block 5 parses the `klist` start time with the date format of the domain controller. If parsing fails the column reads "compare by hand".
- Block 6 extracts account and device names from the English event text. On other display languages those two columns stay empty.
- Block 6 recognises an empty look-back window by the English error text of `Get-WinEvent`. On other display languages an empty window is shown as an `ERROR` row carrying the localised message.
- Block 6 reads at most 5000 events per channel per domain controller.
- Block 4 reports every object that is assigned to any silo and is not a member of the silo named in block 0. In a forest with more than one silo, members of the other silos appear as "assigned but NOT permitted".
- Block 2 expects a user TGT lifetime of 240 minutes. A design with another lifetime shows a different, still consistent, value.

## Version

Document v1, 2026-11-20, for `Tier0-ManualChecks.ps1` v3. Version history of the script is kept at the top of the script.
