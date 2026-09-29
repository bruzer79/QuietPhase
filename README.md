# QuietPhase

**Detect Active Directory reconnaissance before it becomes a breach.**

QuietPhase is a PowerShell tool that checks whether your domain is configured to detect **group enumeration**, the quiet reconnaissance phase where an attacker maps out who holds privileged access. It verifies domain controller audit policy, reports which privileged and custom groups are audited for membership reads, and proposes (or, if you choose, applies) the fixes.

Most organizations alert when someone *changes* a privileged group. Very few notice when someone *reads* one. QuietPhase helps close that gap, and makes it easy to set up honeypot groups that turn enumeration into a high-confidence alert.

**Background reading:** [The Quiet Phase: Why Active Directory Group Enumeration Deserves Your Attention](BLOG-URL-TBD)

---

## Features

- **Audit policy check** on one or all domain controllers:
  - *Audit Directory Service Access* (required; produces Event 4662)
  - *Audit Security Group Management* (recommended; produces Event 4799 for Builtin groups)
  - *Force audit policy subcategory settings*
- **Privileged group check** covering Domain Admins, Enterprise Admins, Schema Admins, Key Admins, Enterprise Key Admins, Group Policy Creator Owners, Administrators, the Builtin operator groups, and DnsAdmins. Groups are located by SID, so it works on non-English domains.
- **AdminSDHolder awareness.** Protected groups (`adminCount=1`) are reset by SDProp, so AdminSDHolder is checked and remediated too.
- **Custom group selection** by partial name, with an interactive picker (`Out-ConsoleGridView`). Use it for honeypot groups or anything else you want to watch.
- **Color-coded results.** Green means the group is configured to audit enumeration; yellow means changes are needed.
- **Safe by default.** It reports only and changes nothing. Changes are made only with `-Apply`, and each one is confirmed. `-WhatIf` is supported.
- **Exportable remediation.** `-FixScriptPath` writes all proposed changes to a reviewable `.ps1` file, suitable for change control.
- **Minimal writes.** Only the SACL portion of an object's security descriptor is modified. DACLs are never touched.

## How it works

A domain controller logs a group enumeration event only when **both** of these are in place:

1. The *Audit Directory Service Access* (Success) policy is enabled on the DC.
2. The group has a SACL entry auditing **Success** reads of the **`member`** attribute by **Everyone** or **Authenticated Users**.

When both are true, each membership read produces **Event 4662** on the DC that answered the query. Key fields:

| Field | Value | Meaning |
| --- | --- | --- |
| `ObjectName` | `%{<objectGUID of the group>}` | Which group was read |
| `Properties` | `{bf9679c0-0de6-11d0-a285-00aa003049e2}` | The `member` attribute |
| `Properties` | `{bc0ac240-79a9-11d0-9020-00c04fc2d4cf}` | Membership property set (often alongside) |
| `AccessMask` | `0x10` | Read Property |
| `SubjectUserName` / `SubjectUserSid` | Account | Who performed the read |
| `SubjectLogonId` | e.g. `0x3A7F21` | Join to Event 4624 (`TargetLogonId`) for source IP and workstation |

> **Note:** SAMR-based tools such as `net group /domain` do not trigger this 4662 signal. Cover that path with process creation logging (Event 4688 / Sysmon / EDR) or network detections such as Microsoft Defender for Identity.

## Requirements

- **PowerShell 7.2 or later** (required by **Microsoft.PowerShell.ConsoleGuiTools**.)
  - **QuietPhase relies on `Out-ConsoleGridView`, which is a part of the **Microsoft.PowerShell.ConsoleHost** module, which is a dependency of **Microsoft.PowerShell.ConsoleGuiTools**.
- **ActiveDirectory module** (RSAT)
- **Elevated session** as a member of **Domain Admins** (**Enterprise Admins** for forest-root groups). Reading and writing SACLs requires *Manage auditing and security log* (SeSecurityPrivilege) on the DCs.
- **WinRM** access to remote DCs when checking audit policy on more than the local machine

## Usage

```powershell
# Report only (default): check the discovered DC, privileged groups, then pick custom groups
.\QuietPhase.ps1

# Check audit policy on every DC in the domain
.\QuietPhase.ps1 -AllDomainControllers

# Export proposed fixes for review or change approval
.\QuietPhase.ps1 -AllDomainControllers -FixScriptPath .\QuietPhase-Fix.ps1

# Preview changes, then apply them (each change is confirmed)
.\QuietPhase.ps1 -Apply -WhatIf
.\QuietPhase.ps1 -Apply

# Propose rules for Authenticated Users instead of Everyone
.\QuietPhase.ps1 -Apply -AuditPrincipal AuthenticatedUsers
```

### Parameters

| Parameter | Default | Description |
| --- | --- | --- |
| `-Server` | Discovered DC | DC or domain to target |
| `-AllDomainControllers` | Off | Check audit policy on every DC, not just the target |
| `-AuditPrincipal` | `Everyone` | Principal used for proposed rules: `Everyone` or `AuthenticatedUsers`. Either counts as configured when checking. |
| `-Apply` | Off | Apply proposed changes, with a confirmation prompt for each |
| `-SkipCustomGroups` | Off | Skip Phase 3 (custom group selection) |
| `-FixScriptPath` | None | Export all proposed remediation to a `.ps1` file |
| `-WhatIf` / `-Confirm` | Standard | Preview changes or control prompts when used with `-Apply` |

### The three phases

1. **Audit policy.** If *Audit Directory Service Access* is not enabled on every checked DC, QuietPhase prints the GPO path and `auditpol` commands to fix it, then stops. Group SACLs are useless until this is in place.
2. **Well-known privileged groups.** Each group's SACL is checked and shown green (configured) or yellow (needs changes).
3. **Custom groups.** Enter a partial name (wildcards allowed), select matches in the grid view, and repeat as needed. Press Enter on an empty line to finish.

When anything needs changes, the run ends with a **NEXT STEPS** block of ready-to-paste commands for `-Apply`, `-WhatIf`, `-FixScriptPath`, or manual ADUC steps.

## Sample output

```text
==============================================================================
 PHASE 1 - Domain controller audit policy
==============================================================================
  Domain: contoso.com   Target DC: DC01.contoso.com   DCs checked: 1

  DC01.contoso.com
    Audit Directory Service Access:      Success
    Audit Security Group Management:     Success
    Force audit policy subcategory settings: enabled (or default)

  PHASE 1 PASSED: Directory Service Access auditing is enabled.

==============================================================================
 PHASE 2 - Well-known privileged groups
==============================================================================

  Group                                    Status       Protected  Detail
  -----                                    ------       ---------  ------
  Domain Admins                            NeedsChange  Yes        No audit rule for reads of 'member' (2 other audit rule(s))
  Enterprise Admins                        NeedsChange  Yes        No audit rule for reads of 'member' (2 other audit rule(s))
  Schema Admins                            Configured   Yes        Everyone: Success ReadProperty on member (direct)
  Administrators (Builtin)                 NeedsChange  Yes        No audit rule for reads of 'member' (1 other audit rule(s))
  DnsAdmins                                NeedsChange  No         No audit rule for reads of 'member' (0 other audit rule(s))
  AdminSDHolder (DC=contoso,DC=com)        NeedsChange  (template) No audit rule for reads of 'member' (2 other audit rule(s))

  REMEDIATION - well-known privileged groups
  5 object(s) need an audit rule: Everyone | Success | Read member
    - Domain Admins
    - Enterprise Admins
    - Administrators (Builtin)
    - DnsAdmins
    - AdminSDHolder (DC=contoso,DC=com)
    (AdminSDHolder is included because SDProp resets protected groups from it about every 60 minutes.)
  Options for resolving these are listed under NEXT STEPS at the end of the run.

==============================================================================
 SUMMARY
==============================================================================
  Configured   1
  NeedsChange  5
  Unknown      0

  NEXT STEPS
  5 object(s) still need an enumeration audit rule. Choose one of these options:

  1. Apply the changes with this script (you confirm each change):
       .\QuietPhase.ps1 -Apply -WhatIf    # preview only, no changes
       .\QuietPhase.ps1 -Apply

  2. Export a fix script to review, edit, or attach to a change request, then run it elevated:
       .\QuietPhase.ps1 -FixScriptPath '.\QuietPhase-Fix.ps1'

  3. Fix manually in ADUC (View > Advanced Features) or ADSI Edit:
       Group > Properties > Security > Advanced > Auditing > Add: Everyone, Success, This object only, 'Read member'
```

*(Output abbreviated. In the console, configured groups appear in green and groups needing changes in yellow.)*

## Troubleshooting

**"Cannot read SACL: A required privilege is not held by the client"** (or a similar access error)
Reading a SACL requires *Manage auditing and security log* (SeSecurityPrivilege) on the DC. Run from an elevated session as a Domain Admin. Forest-root groups (Enterprise Admins, Schema Admins, Enterprise Key Admins) require Enterprise Admin.

**"auditpol.exe failed ... (elevation required)"**
Local `auditpol` queries need an elevated session. For remote DCs, confirm you are an administrator on the DC and that WinRM is reachable (`Test-WSMan <dc>`).

**Audit policy shows as "not a recognized (English) auditpol value"**
QuietPhase parses `auditpol` output in English. On localized DCs, verify the setting manually with `auditpol /get /category:*`.

**ConsoleGuiTools fails to install or `Out-ConsoleGridView` won't open**
Confirm you are on PowerShell 7.2 or later (`$PSVersionTable.PSVersion`) and can reach the PowerShell Gallery. If PSGallery is untrusted, accept the prompt or run `Install-Module Microsoft.PowerShell.ConsoleGuiTools -Scope CurrentUser` manually. Run QuietPhase in a real terminal (Windows Terminal, pwsh console), not the VS Code integrated console or ISE.

**A group shows "NotFound"**
The group may not exist in this domain (for example, Enterprise Admins lives in the forest root), or the root domain's DCs may be unreachable. Check DNS and trust connectivity to the forest root.

**The audit rule disappears from a protected group**
Groups with `adminCount=1` are reset from AdminSDHolder by SDProp. Make sure AdminSDHolder also carries the audit rule. QuietPhase checks and proposes this automatically.

**SACLs are configured but no 4662 events appear**
- Query the DC that actually served the request; events are logged only there.
- Confirm *Audit Directory Service Access* is enabled via GPO on **every** DC, and that no GPO is overriding a locally set `auditpol` value.
- Confirm *Force audit policy subcategory settings* is enabled.
- SAMR-based tools (`net group /domain`) do not generate 4662. Test with LDAP-based tools such as `Get-ADGroupMember`.

## Disclaimer

QuietPhase can modify security descriptors on Active Directory objects when run with `-Apply`. **Test in a lab first**, review exported fix scripts before running them, and follow your organization's change management process.

Enabling enumeration auditing **increases Security log volume** on every domain controller. Size your logs and SIEM ingestion accordingly, and filter known legitimate readers in the SIEM rather than removing audit rules.

This software is provided "as is", without warranty of any kind. **Use at your own risk.** See the [LICENSE](LICENSE) for details.

## License

Released under the [MIT License](LICENSE).