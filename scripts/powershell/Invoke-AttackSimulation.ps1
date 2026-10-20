#Requires -Version 5.1
#Requires -RunAsAdministrator

<#
.SYNOPSIS
    Simulates attacker activity on a lab Windows host to validate Microsoft Sentinel detections.

.DESCRIPTION
    Generates Windows Security events that trigger the lab's custom KQL analytics rules:

      FailedLogon  - Repeated failed logons (Event ID 4625)
                     -> "Windows - Multiple Failed Logons (Brute Force)"  [T1110]

      AdminGroup   - Creates a temporary local user (4720), adds it to the built-in
                     Administrators group (4732), waits, then removes it (4733, 4726)
                     -> "Windows - User Added to Administrators Group"    [T1098]

    All activity is logged with UTC timestamps so it can be matched against
    TimeGenerated in Sentinel. Test accounts are always cleaned up, even if the
    script is interrupted.

    FOR AUTHORIZED LAB USE ONLY. The script refuses to run on any host other than
    -LabHostName unless -Force is specified.

.PARAMETER Scenario
    Which simulation to run: All (default), FailedLogon, or AdminGroup.

.PARAMETER FailedAttempts
    Number of failed logon attempts to generate. Default 10 (rule threshold is 5).

.PARAMETER TargetAccount
    Account name used for failed logons. Defaults to a non-existent account so no
    real account can be locked out.

.PARAMETER TestUserName
    Name of the temporary local account created for the AdminGroup scenario.

.PARAMETER HoldSeconds
    How long the test user stays in Administrators before cleanup. Default 60.

.PARAMETER LabHostName
    Hostname this script is allowed to run on. Default win-dc01.

.PARAMETER LogDirectory
    Folder for the run log. Default: .\logs next to the script.

.PARAMETER Force
    Run even if the current hostname does not match -LabHostName.

.EXAMPLE
    .\Invoke-AttackSimulation.ps1
    Runs both scenarios with default settings.

.EXAMPLE
    .\Invoke-AttackSimulation.ps1 -Scenario FailedLogon -FailedAttempts 20

.EXAMPLE
    .\Invoke-AttackSimulation.ps1 -Scenario AdminGroup -HoldSeconds 120
#>

[CmdletBinding()]
param(
    [ValidateSet('All', 'FailedLogon', 'AdminGroup')]
    [string]$Scenario = 'All',

    [ValidateRange(1, 100)]
    [int]$FailedAttempts = 10,

    [ValidateNotNullOrEmpty()]
    [string]$TargetAccount = 'fakeuser',

    [ValidatePattern('^[A-Za-z0-9_-]{1,20}$')]
    [string]$TestUserName = 'labtest-attacker',

    [ValidateRange(0, 3600)]
    [int]$HoldSeconds = 60,

    [string]$LabHostName = 'win-dc01',

    [string]$LogDirectory = (Join-Path $PSScriptRoot 'logs'),

    [switch]$Force
)

Set-StrictMode -Version Latest
$ErrorActionPreference = 'Stop'

# Well-known SID of the built-in Administrators group (same on every Windows install)
$AdministratorsSid = 'S-1-5-32-544'

# --------------------------------------------------------------------------
# Helpers
# --------------------------------------------------------------------------

function Write-Log {
    param(
        [Parameter(Mandatory)][string]$Message,
        [ValidateSet('INFO', 'WARN', 'ERROR')][string]$Level = 'INFO'
    )
    $timestamp = (Get-Date).ToUniversalTime().ToString('yyyy-MM-dd HH:mm:ss') + 'Z'
    $line = "[$timestamp] [$Level] $Message"
    Add-Content -Path $script:LogFile -Value $line
    switch ($Level) {
        'WARN'  { Write-Host $line -ForegroundColor Yellow }
        'ERROR' { Write-Host $line -ForegroundColor Red }
        default { Write-Host $line }
    }
}

function New-RandomPassword {
    # Lab-only throwaway password: guaranteed upper, lower, digit, and symbol.
    param([ValidateRange(12, 64)][int]$Length = 24)

    $upper  = 'ABCDEFGHJKLMNPQRSTUVWXYZ'.ToCharArray()
    $lower  = 'abcdefghijkmnopqrstuvwxyz'.ToCharArray()
    $digit  = '23456789'.ToCharArray()
    $symbol = '!@#$%^&*-_=+'.ToCharArray()
    $all    = $upper + $lower + $digit + $symbol

    $chars = @(
        ($upper  | Get-Random)
        ($lower  | Get-Random)
        ($digit  | Get-Random)
        ($symbol | Get-Random)
    )
    $chars += 1..($Length - 4) | ForEach-Object { $all | Get-Random }
    -join ($chars | Sort-Object { Get-Random })
}

# --------------------------------------------------------------------------
# Scenario 1: Failed logons (Event ID 4625)
# --------------------------------------------------------------------------

function Invoke-FailedLogonSimulation {
    param(
        [Parameter(Mandatory)][string]$Account,
        [Parameter(Mandatory)][int]$Attempts
    )

    Write-Log "=== Scenario: FailedLogon | target '$Account' | $Attempts attempts ==="

    $badPassword = ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force
    $credential  = New-Object System.Management.Automation.PSCredential($Account, $badPassword)
    $failed = 0

    for ($i = 1; $i -le $Attempts; $i++) {
        try {
            Start-Process -FilePath "$env:SystemRoot\System32\cmd.exe" `
                          -ArgumentList '/c exit' `
                          -Credential $credential `
                          -ErrorAction Stop
            Write-Log "Attempt $i/$Attempts unexpectedly SUCCEEDED for '$Account'" -Level WARN
        }
        catch {
            $failed++
            Write-Log "Attempt $i/$Attempts failed as expected for '$Account'"
        }
        Start-Sleep -Milliseconds 500
    }

    Write-Log "FailedLogon complete: $failed/$Attempts failures generated (expect Event ID 4625)"
}

# --------------------------------------------------------------------------
# Scenario 2: User added to Administrators (Event IDs 4720, 4732, 4733, 4726)
# --------------------------------------------------------------------------

function Invoke-AdminGroupSimulation {
    param(
        [Parameter(Mandatory)][string]$UserName,
        [Parameter(Mandatory)][int]$Hold
    )

    Write-Log "=== Scenario: AdminGroup | test user '$UserName' | hold $Hold s ==="

    $adminGroup = Get-LocalGroup -SID $AdministratorsSid

    if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) {
        throw "Local user '$UserName' already exists. Remove it or choose a different -TestUserName."
    }

    try {
        $password = ConvertTo-SecureString (New-RandomPassword) -AsPlainText -Force
        New-LocalUser -Name $UserName `
                      -Password $password `
                      -Description 'SIEM lab test account - removed automatically' `
                      -AccountNeverExpires | Out-Null
        Write-Log "Created local user '$UserName' (expect Event ID 4720)"

        Add-LocalGroupMember -Group $adminGroup -Member $UserName
        Write-Log "Added '$UserName' to '$($adminGroup.Name)' [$AdministratorsSid] (expect Event ID 4732)"

        if ($Hold -gt 0) {
            Write-Log "Holding $Hold seconds before cleanup..."
            Start-Sleep -Seconds $Hold
        }
    }
    finally {
        # Cleanup always runs, even on error or Ctrl+C
        try {
            $isMember = Get-LocalGroupMember -Group $adminGroup -ErrorAction SilentlyContinue |
                        Where-Object { $_.Name -like "*\$UserName" }
            if ($isMember) {
                Remove-LocalGroupMember -Group $adminGroup -Member $UserName
                Write-Log "Removed '$UserName' from '$($adminGroup.Name)' (expect Event ID 4733)"
            }
            if (Get-LocalUser -Name $UserName -ErrorAction SilentlyContinue) {
                Remove-LocalUser -Name $UserName
                Write-Log "Deleted local user '$UserName' (expect Event ID 4726)"
            }
        }
        catch {
            Write-Log "Cleanup problem: $($_.Exception.Message). Remove '$UserName' manually." -Level ERROR
        }
    }

    Write-Log "AdminGroup complete"
}

# --------------------------------------------------------------------------
# Main
# --------------------------------------------------------------------------

if ($env:COMPUTERNAME -ne $LabHostName -and -not $Force) {
    throw "This host is '$env:COMPUTERNAME', not the lab host '$LabHostName'. Use -Force only if this is a lab machine."
}

if (-not (Test-Path $LogDirectory)) {
    New-Item -ItemType Directory -Path $LogDirectory | Out-Null
}
$script:LogFile = Join-Path $LogDirectory ("AttackSimulation_{0}.log" -f (Get-Date -Format 'yyyyMMdd_HHmmss'))

$startUtc = (Get-Date).ToUniversalTime()
Write-Log "Attack simulation started on $env:COMPUTERNAME by $env:USERDOMAIN\$env:USERNAME | Scenario: $Scenario"

try {
    if ($Scenario -in 'All', 'FailedLogon') {
        Invoke-FailedLogonSimulation -Account $TargetAccount -Attempts $FailedAttempts
    }
    if ($Scenario -in 'All', 'AdminGroup') {
        Invoke-AdminGroupSimulation -UserName $TestUserName -Hold $HoldSeconds
    }
}
catch {
    Write-Log "Simulation aborted: $($_.Exception.Message)" -Level ERROR
    throw
}

$endUtc = (Get-Date).ToUniversalTime()
Write-Log "Attack simulation finished. Log saved to $script:LogFile"

$verifyQuery = @"
SecurityEvent
| where Computer has "$LabHostName"
| where TimeGenerated between (datetime($($startUtc.ToString('yyyy-MM-ddTHH:mm:ssZ'))) .. datetime($($endUtc.AddMinutes(1).ToString('yyyy-MM-ddTHH:mm:ssZ'))))
| where EventID in (4625, 4720, 4732, 4733, 4726)
| summarize Count = count() by EventID, Activity
| order by EventID asc
"@

Write-Host ''
Write-Host 'Verify in Sentinel / Advanced hunting (allow 5-15 minutes for ingestion):' -ForegroundColor Cyan
Write-Host $verifyQuery
