#Requires -Version 7.2
#Requires -Modules ActiveDirectory

<#
.SYNOPSIS
    QuietPhase - AD group enumeration auditing readiness check.
    Checks (and optionally fixes) auditing of Active Directory group enumeration.

.DESCRIPTION
    PHASE 1 - Domain controller audit policy
        * Audit Directory Service Access  = Success  (REQUIRED)    -> Event 4662 when a SACL'd attribute is read
        * Audit Security Group Management = Success  (RECOMMENDED) -> Event 4799 for Builtin groups (e.g. Administrators)
        If Directory Service Access is not enabled on every checked DC, remediation steps are shown
        and the script stops (unless -Apply fixes it).

    PHASE 2 - Well-known privileged groups
        Reads each group's SACL and looks for an audit rule that captures reads of the 'member'
        attribute: principal Everyone OR Authenticated Users, Success, ReadProperty on 'member'
        (or on all properties). Green = configured, Yellow = changes needed.
        Protected groups (adminCount=1) have inheritance disabled and are reset from AdminSDHolder
        by SDProp, so AdminSDHolder is checked and remediated as well.

    PHASE 3 - Custom groups
        Search by partial name, pick groups in Out-ConsoleGridView, then check/propose the same SACL.

    Remediation is always printed as copy/paste-ready PowerShell. With -Apply, each change is made
    after a confirmation prompt (standard ShouldProcess; -WhatIf is supported).

.PARAMETER Server
    Domain controller (or domain name) to target. Defaults to a discovered DC in the current domain.

.PARAMETER AllDomainControllers
    Check the audit policy on every DC in the domain instead of just the target DC.

.PARAMETER AuditPrincipal
    Principal used for PROPOSED audit rules: Everyone (default) or AuthenticatedUsers.
    Either principal counts as "configured" when checking.

.PARAMETER Apply
    Apply the proposed changes (each one confirmed).

.PARAMETER SkipCustomGroups
    Skip Phase 3.

.PARAMETER FixScriptPath
    Also write all proposed remediation to this .ps1 file for review.

.EXAMPLE
    .\QuietPhase.ps1

.EXAMPLE
    .\QuietPhase.ps1 -AllDomainControllers -FixScriptPath .\EnumAuditFix.ps1

.EXAMPLE
    .\QuietPhase.ps1 -Apply -AuditPrincipal AuthenticatedUsers

.NOTES
    Run elevated as a Domain Admin (Enterprise Admin for forest-root groups). Reading/writing SACLs
    requires "Manage auditing and security log" (SeSecurityPrivilege) on the DCs.
    auditpol output is parsed in English; on localized DCs the results may be reported as unrecognized.
#>
[CmdletBinding(SupportsShouldProcess, ConfirmImpact = 'High')]
param(
    [string]$Server,
    [switch]$AllDomainControllers,
    [ValidateSet('Everyone', 'AuthenticatedUsers')]
    [string]$AuditPrincipal = 'Everyone',
    [switch]$Apply,
    [switch]$SkipCustomGroups,
    [string]$FixScriptPath
)

$ErrorActionPreference = 'Stop'

#region ---------- Constants / state ----------
$script:Cmdlet          = $PSCmdlet
$script:SidEveryone     = 'S-1-1-0'
$script:SidAuthUsers    = 'S-1-5-11'
$script:MemberAttrGuid  = [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'   # schemaIDGUID of 'member'
$script:ProposedSid     = if ($AuditPrincipal -eq 'Everyone') { $script:SidEveryone } else { $script:SidAuthUsers }
$script:GuidDSAccess    = '{0CCE923B-69AE-11D9-BED3-505054503030}'       # Audit Directory Service Access
$script:GuidSecGroupMgmt = '{0CCE9237-69AE-11D9-BED3-505054503030}'      # Audit Security Group Management
$script:FixLines        = [System.Collections.Generic.List[string]]::new()
$script:HelperEmitted   = $false
$script:ScriptName      = Split-Path -Leaf $PSCommandPath
$script:BoundParams     = @{} + $PSBoundParameters
#endregion

#region ---------- Output helpers ----------
function Write-Section {
    param([string]$Title)
    Write-Host ''
    Write-Host ('=' * 78) -ForegroundColor Cyan
    Write-Host " $Title" -ForegroundColor Cyan
    Write-Host ('=' * 78) -ForegroundColor Cyan
}

function Write-Fix {
    # Prints a remediation line and records it for -FixScriptPath. -Comment lines are prose.
    param([string[]]$Line, [switch]$Comment)
    foreach ($l in $Line) {
        $text = if ($Comment) { "# $l" } else { $l }
        Write-Host "    $text" -ForegroundColor $(if ($Comment) { 'Gray' } else { 'White' })
        $script:FixLines.Add($text)
    }
}

function Add-FixLine {
    # Records a line for -FixScriptPath without printing it to the console.
    param([string[]]$Line, [switch]$Comment)
    foreach ($l in $Line) { $script:FixLines.Add($(if ($Comment) { "# $l" } else { $l })) }
}

function Format-RerunCommand {
    # Rebuilds the current invocation (minus remediation switches) and appends the given arguments.
    param([string[]]$Add)
    $parts = [System.Collections.Generic.List[string]]::new()
    $parts.Add(".\$script:ScriptName")
    foreach ($k in $script:BoundParams.Keys) {
        if ($k -in 'Apply', 'FixScriptPath', 'WhatIf', 'Confirm') { continue }
        $v = $script:BoundParams[$k]
        if ($v -is [switch] -or $v -is [bool]) { if ($v) { $parts.Add("-$k") } }
        else { $parts.Add("-$k '$v'") }
    }
    foreach ($a in $Add) { $parts.Add($a) }
    $parts -join ' '
}

function Test-IsElevated {
    $id = [System.Security.Principal.WindowsIdentity]::GetCurrent()
    ([System.Security.Principal.WindowsPrincipal]$id).IsInRole([System.Security.Principal.WindowsBuiltInRole]::Administrator)
}
#endregion

#region ---------- Module setup ----------
function Initialize-ConsoleGuiTools {
    $name = 'Microsoft.PowerShell.ConsoleGuiTools'
    if (-not (Get-Module -ListAvailable -Name $name)) {
        Write-Host "$name is required (Out-ConsoleGridView). Installing from PSGallery (CurrentUser)..." -ForegroundColor Yellow
        Install-Module -Name $name -Scope CurrentUser -Repository PSGallery
    }
    Import-Module -Name $name
}
#endregion

#region ---------- Phase 1: audit policy ----------
$script:AuditPolGetScript = {
    param([string]$DsGuid, [string]$SgmGuid)
    $out = [ordered]@{}
    foreach ($pair in @(@('DSAccess', $DsGuid), @('SecGroupMgmt', $SgmGuid))) {
        $raw = & auditpol.exe /get "/subcategory:$($pair[1])" /r 2>&1
        if ($LASTEXITCODE -ne 0) { throw "auditpol.exe failed on $env:COMPUTERNAME (elevation required): $($raw -join ' ')" }
        $row = $raw | Where-Object { $_ -match '\S' } | ConvertFrom-Csv | Select-Object -First 1
        $out[$pair[0]] = $row.'Inclusion Setting'
    }
    $lsa = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -ErrorAction SilentlyContinue
    $out['ForceSubcategory'] = $lsa.SCENoApplyLegacyAuditPolicy
    [pscustomobject]$out
}

$script:AuditPolSetScript = {
    param([string[]]$Guids)
    foreach ($g in $Guids) {
        $raw = & auditpol.exe /set "/subcategory:$g" /success:enable 2>&1
        if ($LASTEXITCODE -ne 0) { throw "auditpol.exe /set failed on $env:COMPUTERNAME : $($raw -join ' ')" }
    }
}

function Test-IsLocalComputer {
    param([string]$ComputerName)
    ($ComputerName -split '\.')[0] -eq $env:COMPUTERNAME
}

function Get-DCAuditPolicy {
    param([string]$ComputerName)
    $argList = @($script:GuidDSAccess, $script:GuidSecGroupMgmt)
    if (Test-IsLocalComputer $ComputerName) { & $script:AuditPolGetScript @argList }
    else { Invoke-Command -ComputerName $ComputerName -ScriptBlock $script:AuditPolGetScript -ArgumentList $argList }
}

function Test-SuccessEnabled {
    param([string]$Setting)
    [bool]($Setting -match 'Success')
}

function Get-PolicyResults {
    param([string[]]$DomainControllers)
    foreach ($dc in $DomainControllers) {
        try {
            $p = Get-DCAuditPolicy -ComputerName $dc
            [pscustomobject]@{ DC = $dc; DSAccess = $p.DSAccess; SecGroupMgmt = $p.SecGroupMgmt; Force = $p.ForceSubcategory; Error = $null }
        }
        catch {
            [pscustomobject]@{ DC = $dc; DSAccess = $null; SecGroupMgmt = $null; Force = $null; Error = $_.Exception.Message }
        }
    }
}

function Show-PolicyResults {
    param($Results)
    $known = '^(No Auditing|Success|Failure|Success and Failure)$'
    foreach ($r in $Results) {
        Write-Host ''
        Write-Host "  $($r.DC)" -ForegroundColor Cyan
        if ($r.Error) {
            Write-Host "    ERROR: $($r.Error)" -ForegroundColor Red
            continue
        }
        $ds = Test-SuccessEnabled $r.DSAccess
        Write-Host ('    {0,-36} {1}' -f 'Audit Directory Service Access:', $r.DSAccess) -ForegroundColor $(if ($ds) { 'Green' } else { 'Yellow' })
        $sg = Test-SuccessEnabled $r.SecGroupMgmt
        Write-Host ('    {0,-36} {1}' -f 'Audit Security Group Management:', $r.SecGroupMgmt) -ForegroundColor $(if ($sg) { 'Green' } else { 'Yellow' })

        foreach ($s in @($r.DSAccess, $r.SecGroupMgmt)) {
            if ($s -and $s -notmatch $known) {
                Write-Host "    NOTE: '$s' is not a recognized (English) auditpol value; verify manually." -ForegroundColor Magenta
            }
        }
        if ($r.Force -eq 0) {
            Write-Host '    WARNING: "Audit: Force audit policy subcategory settings" is DISABLED; legacy category policy may override these settings.' -ForegroundColor Yellow
        }
        else {
            Write-Host '    Force audit policy subcategory settings: enabled (or default)' -ForegroundColor Green
        }
    }
}

function Show-AuditPolicyFix {
    param($Results)
    Write-Host ''
    Write-Host '  REMEDIATION - Domain controller audit policy' -ForegroundColor Yellow
    Write-Fix -Comment -Line @(
        '=== Audit policy (persistent, recommended): Group Policy linked to the Domain Controllers OU ===',
        'GPMC > Default Domain Controllers Policy (or a dedicated DC audit GPO) > Edit >',
        '  Computer Configuration > Policies > Windows Settings > Security Settings >',
        '  Advanced Audit Policy Configuration > Audit Policies >',
        '    DS Access          > Audit Directory Service Access  = Success',
        '    Account Management > Audit Security Group Management = Success',
        '  Security Options > "Audit: Force audit policy subcategory settings (Windows Vista or later)..." = Enabled',
        'Then: gpupdate /force on each DC. Verify with: auditpol /get /category:*',
        '',
        '=== Immediate (per DC). A GPO that defines these subcategories will override this. ==='
    )
    foreach ($r in $Results) {
        if ($r.Error) {
            Write-Fix -Comment -Line "$($r.DC): could not be queried ($($r.Error)). Check WinRM/permissions and rerun."
            continue
        }
        $guids = @()
        if (-not (Test-SuccessEnabled $r.DSAccess))     { $guids += $script:GuidDSAccess }
        if (-not (Test-SuccessEnabled $r.SecGroupMgmt)) { $guids += $script:GuidSecGroupMgmt }
        foreach ($g in $guids) {
            Write-Fix -Line "Invoke-Command -ComputerName '$($r.DC)' -ScriptBlock { auditpol.exe /set /subcategory:'$g' /success:enable }"
        }
        if ($r.Force -eq 0) {
            Write-Fix -Line "Invoke-Command -ComputerName '$($r.DC)' -ScriptBlock { Set-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Control\Lsa' -Name SCENoApplyLegacyAuditPolicy -Value 1 -Type DWord }"
        }
    }
}

function Invoke-AuditPolicyFix {
    param($Results)
    foreach ($r in $Results) {
        if ($r.Error) { continue }
        $guids = @()
        if (-not (Test-SuccessEnabled $r.DSAccess))     { $guids += $script:GuidDSAccess }
        if (-not (Test-SuccessEnabled $r.SecGroupMgmt)) { $guids += $script:GuidSecGroupMgmt }
        if (-not $guids) { continue }
        if ($script:Cmdlet.ShouldProcess($r.DC, "auditpol /set /success:enable for $($guids -join ', ')")) {
            try {
                if (Test-IsLocalComputer $r.DC) { & $script:AuditPolSetScript $guids }
                else { Invoke-Command -ComputerName $r.DC -ScriptBlock $script:AuditPolSetScript -ArgumentList (, $guids) }
                Write-Host "    Applied audit policy on $($r.DC)" -ForegroundColor Green
            }
            catch { Write-Host "    FAILED on $($r.DC): $($_.Exception.Message)" -ForegroundColor Red }
        }
    }
}
#endregion

#region ---------- SACL evaluation / remediation ----------
function Add-EnumerationAuditRule {
    # Adds: <Principal> | Success | ReadProperty on 'member' | this object only. Only the SACL is written.
    param(
        [Parameter(Mandatory)][string]$Server,
        [Parameter(Mandatory)][string]$DistinguishedName,
        [ValidateSet('S-1-1-0', 'S-1-5-11')][string]$PrincipalSid = 'S-1-1-0'
    )
    $memberAttr = [guid]'bf9679c0-0de6-11d0-a285-00aa003049e2'
    $path = 'LDAP://{0}/{1}' -f $Server, ($DistinguishedName -replace '/', '\/')
    $de = [System.DirectoryServices.DirectoryEntry]::new($path)
    try {
        $de.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
        $rule = [System.DirectoryServices.ActiveDirectoryAuditRule]::new(
            [System.Security.Principal.SecurityIdentifier]::new($PrincipalSid),
            [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty,
            [System.Security.AccessControl.AuditFlags]::Success,
            $memberAttr,
            [System.DirectoryServices.ActiveDirectorySecurityInheritance]::None)
        $de.psbase.ObjectSecurity.AddAuditRule($rule)
        $de.psbase.CommitChanges()
    }
    finally { $de.psbase.Dispose() }
}

function Test-EnumerationAuditRule {
    param($Rule)
    if ($Rule.IdentityReference.Value -notin @($script:SidEveryone, $script:SidAuthUsers)) { return $false }
    if (-not ($Rule.AuditFlags -band [System.Security.AccessControl.AuditFlags]::Success)) { return $false }
    if (-not ($Rule.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty)) { return $false }
    if ($Rule.ObjectType -ne [guid]::Empty -and $Rule.ObjectType -ne $script:MemberAttrGuid) { return $false }
    if ($Rule.PropagationFlags -band [System.Security.AccessControl.PropagationFlags]::InheritOnly) { return $false }
    $true
}

function Format-AuditRule {
    param($Rule)
    $who = switch ($Rule.IdentityReference.Value) {
        'S-1-1-0'  { 'Everyone' }
        'S-1-5-11' { 'Authenticated Users' }
        default {
            try { $Rule.IdentityReference.Translate([System.Security.Principal.NTAccount]).Value }
            catch { $Rule.IdentityReference.Value }
        }
    }
    $what = if ($Rule.ObjectType -eq [guid]::Empty) { 'all properties' }
            elseif ($Rule.ObjectType -eq $script:MemberAttrGuid) { 'member' }
            else { "attr $($Rule.ObjectType)" }
    $src = if ($Rule.IsInherited) { 'inherited' } else { 'direct' }
    '{0}: {1} {2} on {3} ({4})' -f $who, $Rule.AuditFlags, $Rule.ActiveDirectoryRights, $what, $src
}

function Get-GroupAuditResult {
    param([string]$Name, [string]$DistinguishedName, [string]$Server, [bool]$Protected, [string]$Kind = 'Group')
    $result = [pscustomobject]@{
        Name = $Name; DistinguishedName = $DistinguishedName; Server = $Server
        Protected = $Protected; Kind = $Kind; Status = 'Unknown'; Detail = ''
    }
    $path = 'LDAP://{0}/{1}' -f $Server, ($DistinguishedName -replace '/', '\/')
    $de = [System.DirectoryServices.DirectoryEntry]::new($path)
    try {
        $de.psbase.Options.SecurityMasks = [System.DirectoryServices.SecurityMasks]::Sacl
        $sd = $de.psbase.ObjectSecurity
        if ($null -eq $sd) { throw 'No security descriptor returned (SeSecurityPrivilege required).' }
        $rules = @($sd.GetAuditRules($true, $true, [System.Security.Principal.SecurityIdentifier]))
        $good  = @($rules | Where-Object { Test-EnumerationAuditRule $_ })
        if ($good) {
            $result.Status = 'Configured'
            $result.Detail = ($good | ForEach-Object { Format-AuditRule $_ }) -join '; '
        }
        else {
            $result.Status = 'NeedsChange'
            $near = @($rules | Where-Object {
                ($_.ActiveDirectoryRights -band [System.DirectoryServices.ActiveDirectoryRights]::ReadProperty) -and
                ($_.ObjectType -eq [guid]::Empty -or $_.ObjectType -eq $script:MemberAttrGuid) })
            $result.Detail = if ($near) { 'Non-qualifying: ' + (($near | ForEach-Object { Format-AuditRule $_ }) -join '; ') }
                             else { "No audit rule for reads of 'member' ($($rules.Count) other audit rule(s))" }
        }
    }
    catch {
        $result.Status = 'Unknown'
        $result.Detail = "Cannot read SACL: $($_.Exception.Message)"
    }
    finally { $de.psbase.Dispose() }
    $result
}

function Get-DomainDNFromDN {
    param([string]$DistinguishedName)
    if ($DistinguishedName -match ',(DC=[^,]+(?:,DC=[^,]+)*)$') { $Matches[1] }
}

function Get-AdminSDHolderResults {
    # One AdminSDHolder check per domain that contains a protected group in the result set.
    param($GroupResults)
    $seen = @{}
    foreach ($g in $GroupResults | Where-Object { $_.Protected -and $_.Status -ne 'NotFound' }) {
        $domDN = Get-DomainDNFromDN $g.DistinguishedName
        if (-not $domDN -or $seen.ContainsKey($domDN)) { continue }
        $seen[$domDN] = $true
        Get-GroupAuditResult -Name "AdminSDHolder ($domDN)" -DistinguishedName "CN=AdminSDHolder,CN=System,$domDN" `
            -Server $g.Server -Protected $false -Kind 'AdminSDHolder'
    }
}

function Show-GroupResults {
    param($Results)
    Write-Host ''
    Write-Host ('  {0,-40} {1,-12} {2,-10} {3}' -f 'Group', 'Status', 'Protected', 'Detail') -ForegroundColor Cyan
    Write-Host ('  {0,-40} {1,-12} {2,-10} {3}' -f ('-' * 5), ('-' * 6), ('-' * 9), ('-' * 6)) -ForegroundColor Cyan
    foreach ($r in $Results) {
        $color = switch ($r.Status) {
            'Configured'  { 'Green' }
            'NeedsChange' { 'Yellow' }
            'NotFound'    { 'DarkGray' }
            default       { 'Red' }
        }
        $prot = if ($r.Kind -eq 'AdminSDHolder') { '(template)' } elseif ($r.Protected) { 'Yes' } else { 'No' }
        Write-Host ('  {0,-40} {1,-12} {2,-10} {3}' -f $r.Name, $r.Status, $prot, $r.Detail) -ForegroundColor $color
    }
}

function Invoke-SaclRemediation {
    # Prints proposed changes, optionally applies them, then re-checks. Returns the (possibly refreshed) results.
    param($Results, [string]$Title)
    $targets = @($Results | Where-Object { $_.Status -eq 'NeedsChange' })
    $unknown = @($Results | Where-Object { $_.Status -eq 'Unknown' })

    if (-not $targets -and -not $unknown) {
        Write-Host ''
        Write-Host "  All $Title are configured to audit enumeration." -ForegroundColor Green
        return $Results
    }

    Write-Host ''
    Write-Host "  REMEDIATION - $Title" -ForegroundColor Yellow
    if ($unknown) {
        Write-Host '  These SACLs could not be read. Rerun elevated as Domain Admin (Enterprise Admin for forest-root groups):' -ForegroundColor Red
        foreach ($u in $unknown) { Write-Host "    - $($u.Name): $($u.Detail)" -ForegroundColor Red }
    }
    if ($targets) {
        Write-Host "  $($targets.Count) object(s) need an audit rule: $AuditPrincipal | Success | Read member" -ForegroundColor Yellow
        foreach ($t in $targets) { Write-Host "    - $($t.Name)" -ForegroundColor Yellow }
        if ($targets | Where-Object Kind -eq 'AdminSDHolder') {
            Write-Host '    (AdminSDHolder is included because SDProp resets protected groups from it about every 60 minutes.)' -ForegroundColor Gray
        }
        if (-not $Apply) {
            Write-Host '  Options for resolving these are listed under NEXT STEPS at the end of the run.' -ForegroundColor Gray
        }

        # Recorded (not printed) for -FixScriptPath
        Add-FixLine -Comment -Line "--- $Title ---"
        Add-FixLine -Comment -Line "Adds audit rule: $AuditPrincipal | Success | ReadProperty on 'member' -> Event 4662 on DCs."
        if (-not $script:HelperEmitted) {
            $body = (Get-Command Add-EnumerationAuditRule).Definition
            Add-FixLine -Line ("function Add-EnumerationAuditRule {`n$body`n}" -split "`n")
            $script:HelperEmitted = $true
        }
        foreach ($t in $targets) {
            $dnEsc = $t.DistinguishedName -replace "'", "''"
            Add-FixLine -Line "Add-EnumerationAuditRule -Server '$($t.Server)' -DistinguishedName '$dnEsc' -PrincipalSid '$($script:ProposedSid)'   # $($t.Name)"
        }
    }

    if ($Apply -and $targets) {
        Write-Host ''
        Write-Host '  Applying changes (-Apply)...' -ForegroundColor Cyan
        foreach ($t in $targets) {
            if ($script:Cmdlet.ShouldProcess($t.DistinguishedName, "Add SACL: $AuditPrincipal Success ReadProperty(member)")) {
                try {
                    Add-EnumerationAuditRule -Server $t.Server -DistinguishedName $t.DistinguishedName -PrincipalSid $script:ProposedSid
                    Write-Host "    Applied: $($t.Name)" -ForegroundColor Green
                }
                catch { Write-Host "    FAILED: $($t.Name): $($_.Exception.Message)" -ForegroundColor Red }
            }
        }
        Write-Host ''
        Write-Host '  Re-checking...' -ForegroundColor Cyan
        $Results = foreach ($r in $Results) {
            if ($r.Status -eq 'NotFound') { $r; continue }
            Get-GroupAuditResult -Name $r.Name -DistinguishedName $r.DistinguishedName -Server $r.Server -Protected $r.Protected -Kind $r.Kind
        }
        Show-GroupResults $Results
    }
    $Results
}

function Get-GroupResultFromAD {
    param($ADGroup, [string]$Server, [string]$Label)
    $name = if ($Label) { $Label } else { $ADGroup.Name }
    Get-GroupAuditResult -Name $name -DistinguishedName $ADGroup.DistinguishedName -Server $Server -Protected ($ADGroup.adminCount -eq 1)
}
#endregion

#region ================= MAIN =================
Initialize-ConsoleGuiTools
Import-Module ActiveDirectory

if (-not (Test-IsElevated)) {
    Write-Host 'WARNING: This session is not elevated. Local auditpol queries and SACL access may fail.' -ForegroundColor Yellow
}

# ---------- PHASE 1 ----------
Write-Section 'PHASE 1 - Domain controller audit policy'

if (-not $Server) { $Server = [string]((Get-ADDomainController -Discover).HostName | Select-Object -First 1) }
$primaryDC = [string](Get-ADDomainController -Server $Server).HostName
$domain    = Get-ADDomain -Server $primaryDC

$dcList = if ($AllDomainControllers) { @((Get-ADDomainController -Filter * -Server $primaryDC).HostName | ForEach-Object { [string]$_ }) }
          else { @($primaryDC) }

Write-Host "  Domain: $($domain.DNSRoot)   Target DC: $primaryDC   DCs checked: $($dcList.Count)"
$policy = @(Get-PolicyResults -DomainControllers $dcList)
Show-PolicyResults $policy

$needsPolicyFix = @($policy | Where-Object { $_.Error -or -not (Test-SuccessEnabled $_.DSAccess) -or -not (Test-SuccessEnabled $_.SecGroupMgmt) -or $_.Force -eq 0 })
if ($needsPolicyFix) {
    Show-AuditPolicyFix $needsPolicyFix
    if ($Apply) {
        Write-Host ''
        Write-Host '  Applying audit policy (-Apply)...' -ForegroundColor Cyan
        Invoke-AuditPolicyFix $needsPolicyFix
        $policy = @(Get-PolicyResults -DomainControllers $dcList)
        Show-PolicyResults $policy
    }
}

$dsFailed = @($policy | Where-Object { $_.Error -or -not (Test-SuccessEnabled $_.DSAccess) })
if ($dsFailed) {
    Write-Host ''
    Write-Host "  PHASE 1 FAILED: 'Audit Directory Service Access' (Success) is not confirmed on: $($dsFailed.DC -join ', ')" -ForegroundColor Red
    Write-Host '  Group SACLs will not generate events until this is fixed. Apply the steps above and rerun.' -ForegroundColor Red
    if ($FixScriptPath) { $script:FixLines | Set-Content -Path $FixScriptPath -Encoding utf8; Write-Host "  Fix script written to $FixScriptPath" }
    return
}
Write-Host ''
Write-Host '  PHASE 1 PASSED: Directory Service Access auditing is enabled.' -ForegroundColor Green

# ---------- PHASE 2 ----------
Write-Section 'PHASE 2 - Well-known privileged groups'

$forest = Get-ADForest -Server $primaryDC
if ($forest.RootDomain -eq $domain.DNSRoot) {
    $rootDomain = $domain; $rootServer = $primaryDC
}
else {
    $rootServer = [string]((Get-ADDomainController -Discover -DomainName $forest.RootDomain).HostName | Select-Object -First 1)
    $rootDomain = Get-ADDomain -Server $rootServer
}
$dSid = $domain.DomainSID.Value
$rSid = $rootDomain.DomainSID.Value

$wellKnown = @(
    @{ Label = 'Domain Admins';               Identity = "$dSid-512";    Server = $primaryDC }
    @{ Label = 'Enterprise Admins';           Identity = "$rSid-519";    Server = $rootServer }
    @{ Label = 'Schema Admins';               Identity = "$rSid-518";    Server = $rootServer }
    @{ Label = 'Enterprise Key Admins';       Identity = "$rSid-527";    Server = $rootServer }
    @{ Label = 'Key Admins';                  Identity = "$dSid-526";    Server = $primaryDC }
    @{ Label = 'Group Policy Creator Owners'; Identity = "$dSid-520";    Server = $primaryDC }
    @{ Label = 'Administrators (Builtin)';    Identity = 'S-1-5-32-544'; Server = $primaryDC }
    @{ Label = 'Account Operators';           Identity = 'S-1-5-32-548'; Server = $primaryDC }
    @{ Label = 'Server Operators';            Identity = 'S-1-5-32-549'; Server = $primaryDC }
    @{ Label = 'Print Operators';             Identity = 'S-1-5-32-550'; Server = $primaryDC }
    @{ Label = 'Backup Operators';            Identity = 'S-1-5-32-551'; Server = $primaryDC }
    @{ Label = 'DnsAdmins';                   Identity = 'DnsAdmins';    Server = $primaryDC }
)

$wkResults = @(foreach ($g in $wellKnown) {
    try { $ad = Get-ADGroup -Identity $g.Identity -Server $g.Server -Properties adminCount }
    catch {
        [pscustomobject]@{ Name = $g.Label; DistinguishedName = $null; Server = $g.Server; Protected = $false
                           Kind = 'Group'; Status = 'NotFound'; Detail = 'Group not found or not accessible' }
        continue
    }
    Get-GroupResultFromAD -ADGroup $ad -Server $g.Server -Label $g.Label
})
$wkResults += @(Get-AdminSDHolderResults $wkResults)

Show-GroupResults $wkResults
Write-Host ''
Write-Host '  Tip: Builtin groups (e.g. Administrators) also log Event 4799 via Security Group Management when enumerated through SAM.' -ForegroundColor Gray
$wkResults = Invoke-SaclRemediation -Results $wkResults -Title 'well-known privileged groups'

# ---------- PHASE 3 ----------
$customResults = @()
if (-not $SkipCustomGroups) {
    Write-Section 'PHASE 3 - Custom groups'
    Write-Host "  Searches domain $($domain.DNSRoot). Wildcards (*) are allowed. Press Enter on an empty line when finished."
    $selected = [ordered]@{}
    while ($true) {
        $pattern = Read-Host '  Partial group name'
        if ([string]::IsNullOrWhiteSpace($pattern)) { break }
        $like  = "*$($pattern.Trim())*"
        $found = @(Get-ADGroup -Filter 'Name -like $like' -Server $primaryDC -Properties adminCount, Description)
        if (-not $found) { Write-Host "  No groups match '$like'." -ForegroundColor Yellow; continue }

        $picked = @($found | Sort-Object Name |
            Select-Object Name, SamAccountName, GroupScope, GroupCategory,
                          @{ n = 'Protected'; e = { $_.adminCount -eq 1 } }, Description, DistinguishedName |
            Out-ConsoleGridView -Title "Select group(s) to monitor - matches for '$like'" -OutputMode Multiple)

        foreach ($p in $picked) { $selected[$p.DistinguishedName] = $p }
        Write-Host "  Added $($picked.Count). Total selected: $($selected.Count)" -ForegroundColor Cyan
    }

    if ($selected.Count) {
        $customResults = @(foreach ($dn in $selected.Keys) {
            $ad = Get-ADGroup -Identity $dn -Server $primaryDC -Properties adminCount
            Get-GroupResultFromAD -ADGroup $ad -Server $primaryDC
        })
        # Only add AdminSDHolder if a selected group is protected and it wasn't already covered in Phase 2
        $sdh = @(Get-AdminSDHolderResults $customResults | Where-Object { $_.DistinguishedName -notin $wkResults.DistinguishedName })
        $customResults += $sdh
        Show-GroupResults $customResults
        $customResults = Invoke-SaclRemediation -Results $customResults -Title 'selected custom groups'
    }
    else {
        Write-Host '  No custom groups selected.' -ForegroundColor Gray
    }
}

# ---------- Summary ----------
Write-Section 'SUMMARY'
$all = @($wkResults) + @($customResults) | Where-Object { $_.Status -ne 'NotFound' }
foreach ($s in 'Configured', 'NeedsChange', 'Unknown') {
    $n = @($all | Where-Object Status -eq $s).Count
    $c = switch ($s) { 'Configured' { 'Green' } 'NeedsChange' { 'Yellow' } default { 'Red' } }
    Write-Host ('  {0,-12} {1}' -f $s, $n) -ForegroundColor $c
}
Write-Host ''
Write-Host "  Detection: Security log on DCs, Event ID 4662, Properties containing {$($script:MemberAttrGuid)} (member)." -ForegroundColor Gray

if ($FixScriptPath -and $script:FixLines.Count) {
    $header = @("# Proposed remediation generated $(Get-Date -Format s) by QuietPhase.ps1",
                '# REVIEW BEFORE RUNNING. Run elevated as Domain Admin / Enterprise Admin.', '')
    ($header + $script:FixLines) | Set-Content -Path $FixScriptPath -Encoding utf8
    Write-Host "  Proposed remediation written to $FixScriptPath" -ForegroundColor Cyan
}

$pending = @($all | Where-Object Status -eq 'NeedsChange')
if ($pending) {
    Write-Host ''
    Write-Host '  NEXT STEPS' -ForegroundColor Yellow
    Write-Host "  $($pending.Count) object(s) still need an enumeration audit rule. Choose one of these options:" -ForegroundColor Yellow
    Write-Host ''
    Write-Host '  1. Apply the changes with this script (you confirm each change):' -ForegroundColor White
    Write-Host "       $(Format-RerunCommand -Add '-Apply', '-WhatIf')    # preview only, no changes" -ForegroundColor Cyan
    Write-Host "       $(Format-RerunCommand -Add '-Apply')" -ForegroundColor Cyan
    Write-Host ''
    Write-Host '  2. Export a fix script to review, edit, or attach to a change request, then run it elevated:' -ForegroundColor White
    if ($FixScriptPath) {
        Write-Host "       Already written to $FixScriptPath" -ForegroundColor Cyan
    }
    else {
        Write-Host "       $(Format-RerunCommand -Add "-FixScriptPath '.\QuietPhase-Fix.ps1'")" -ForegroundColor Cyan
    }
    Write-Host ''
    Write-Host '  3. Fix manually in ADUC (View > Advanced Features) or ADSI Edit:' -ForegroundColor White
    Write-Host "       Group > Properties > Security > Advanced > Auditing > Add: $AuditPrincipal, Success, This object only, 'Read member'" -ForegroundColor Cyan
    Write-Host ''
    if (-not $SkipCustomGroups -and $customResults) {
        Write-Host '  Note: custom groups are chosen interactively, so select the same groups again when you rerun.' -ForegroundColor Gray
    }
}
elseif ($all | Where-Object Status -eq 'Unknown') {
    Write-Host ''
    Write-Host '  NEXT STEPS: some SACLs could not be read. Rerun elevated as Domain Admin (Enterprise Admin for forest-root groups).' -ForegroundColor Red
}
#endregion
