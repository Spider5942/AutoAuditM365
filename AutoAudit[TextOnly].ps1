#Install-Module Microsoft.Graph -Scope CurrentUser
#Install-Module Microsoft.Graph.Beta -Scope CurrentUser
#Install-Module Microsoft.Graph.Security -Scope CurrentUser
#Install-Module ExchangeOnlineManagement -Scope CurrentUser

$scopes = @(
    "Policy.Read.All",
    "SecurityEvents.Read.All",
    "Directory.Read.All",
    "Organization.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "DeviceManagementManagedDevices.Read.All",
    "Group.Read.All",
    "SecurityEvents.Read.All",
    "CustomDetection.Read.All"
)

Connect-MgGraph -Scopes $scopes -NoWelcome


#####Entra ID#####
Write-Host ("`n#####Entra ID#####") -ForegroundColor Cyan

#New User & Sign-In Risk Policies
$caPolicies = Get-MgIdentityConditionalAccessPolicy -All
$nonMicrosoftCAPolicies = $caPolicies | Where-Object { $_.DisplayName -notmatch "Microsoft-managed:" }
$microsoftCAPolicies = $caPolicies | Where-Object { $_.DisplayName -match "Microsoft-managed:" }

Remove-Variable caPolicies

Write-Host ("`nThere are currently ") -NoNewline
Write-Host ($microsoftCAPoliciesCount.Count) -ForegroundColor Yellow -NoNewline
Write-Host (" microsoft-managed policies") -ForegroundColor Yellow -NoNewline
Write-Host (" in this environment.")

$signInRiskPolicy = $nonMicrosoftCAPolicies | Where-Object { $_.Conditions.SignInRiskLevels } | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime
$userRiskPolicy = $nonMicrosoftCAPolicies | Where-Object { $_.Conditions.UserRiskLevels }  | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime

$blockAuthFlowPolicy = $nonMicrosoftCAPolicies | Where-Object { $_.Conditions.AuthenticationFlows.TransferMethods } | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime
$blockLegacyAuthPolicy = $nonMicrosoftCAPolicies | Where-Object { $_.Conditions.ClientAppTypes -match "exchangeActiveSync" -and $_.Conditions.ClientAppTypes -match "other" } | Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime
$deviceTrustWorkstationPolicy = $nonMicrosoftCAPolicies |
                     Where-Object { $_.Conditions.Platforms.IncludePlatforms -contains "windows" -and
                                    $_.Conditions.Platforms.IncludePlatforms -contains "macOS" -and
                                    $_.Conditions.Platforms.IncludePlatforms -contains "linux" -and
                                    $_.DisplayName.ToLower() -match "device trust" } |
                     Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime
$deviceTrustMobileDevicePolicy = $nonMicrosoftCAPolicies |
                     Where-Object { $_.Conditions.Platforms.IncludePlatforms -contains "android" -and
                                    $_.Conditions.Platforms.IncludePlatforms -contains "iOS" -and
                                    $_.Conditions.Platforms.IncludePlatforms -contains "windowsPhone" -and
                                    $_.DisplayName -match "device trust" } |
                     Select-Object DisplayName, State, CreatedDateTime, ModifiedDateTime

if ($signInRiskPolicy) {
    ForEach ($p in $signInRiskPolicy) {
        Write-Host ("`nA potential sign-in risk policy named ") -NoNewLine
        Write-Host ($p.DisplayName) -ForegroundColor Yellow -NoNewline

        if ($p.ModifiedDateTime) {
            Write-Host (" is " + $p.State + " and was last updated on ") -NoNewline
            Write-Host ($p.ModifiedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow
        }
        else {
            Write-Host (" is " + $p.State + " and was created on ") -NoNewline
            Write-Host ($p.CreatedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
            Write-Host (" (no modifications to the policy since creation).")
        }
    }
}
else {
    Write-Host ("`nNo potential sign-in risk policy was found.")
}

if ($userRiskPolicy) {
    ForEach ($p in $userRiskPolicy) {
        Write-Host ("`nA potential user risk policy named ") -NoNewLine
        Write-Host ($p.DisplayName) -ForegroundColor Yellow -NoNewline

        if ($p.ModifiedDateTime) {
            Write-Host (" is " + $p.State + " and was last updated on ") -NoNewline
            Write-Host ($p.ModifiedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow
        }
        else {
            Write-Host (" is " + $p.State + " and was created on ") -NoNewline
            Write-Host ($p.CreatedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
            Write-Host (" (no modifications to the policy since creation).")
        }
    }
}
else {
    Write-Host ("`nNo potential user risk policy was found.")
}

if ($blockAuthFlowPolicy) {
    ForEach ($p in $blockAuthFlowPolicy) {
        Write-Host ("`nA potential block authentication flows policy named ") -NoNewLine
        Write-Host ($p.DisplayName) -ForegroundColor Yellow -NoNewline

        if ($p.ModifiedDateTime) {
            Write-Host (" is " + $p.State + " and was last updated on ") -NoNewline
            Write-Host ($p.ModifiedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow
        }
        else {
            Write-Host (" is " + $p.State + " and was created on ") -NoNewline
            Write-Host ($p.CreatedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
            Write-Host (" (no modifications to the policy since creation).")
        }
    }
}
else {
    Write-Host ("`nNo potential block authentication flows policy was found.")
}

if ($blockLegacyAuthPolicy) {
    ForEach ($p in $blockLegacyAuthPolicy) {
        Write-Host ("`nA potential block legacy authentication policy named ") -NoNewLine
        Write-Host ($p.DisplayName) -ForegroundColor Yellow -NoNewline

        if ($p.ModifiedDateTime) {
            Write-Host (" is " + $p.State + " and was last updated on ") -NoNewline
            Write-Host ($p.ModifiedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow
        }
        else {
            Write-Host (" is " + $p.State + " and was created on ") -NoNewline
            Write-Host ($p.CreatedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
            Write-Host (" (no modifications to the policy since creation).")
        }
    }
}
else {
    Write-Host ("`nNo potential block legacy authentication policy was found.")
}

if ($deviceTrustWorkstationPolicy) {
    ForEach ($p in $deviceTrustWorkstationPolicy) {
        Write-Host ("`nA potential device trust (workstation) policy named ") -NoNewLine
        Write-Host ($p.DisplayName) -ForegroundColor Yellow -NoNewline

        if ($p.ModifiedDateTime) {
            Write-Host (" is " + $p.State + " and was last updated on ") -NoNewline
            Write-Host ($p.ModifiedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow
        }
        else {
            Write-Host (" is " + $p.State + " and was created on ") -NoNewline
            Write-Host ($p.CreatedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
            Write-Host (" (no modifications to the policy since creation).")
        }
    }
}
else {
    Write-Host ("`nNo potential device trust (workstation) policy was found.")
}

if ($deviceTrustMobileDevicePolicy) {
    ForEach ($p in $deviceTrustMobileDevicePolicy) {
        Write-Host ("`nA potential device trust (mobile) policy named ") -NoNewLine
        Write-Host ($p.DisplayName) -ForegroundColor Yellow -NoNewline

        if ($p.ModifiedDateTime) {
            Write-Host (" is " + $p.State + " and was last updated on ") -NoNewline
            Write-Host ($p.ModifiedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow
        }
        else {
            Write-Host (" is " + $p.State + " and was created on ") -NoNewline
            Write-Host ($p.CreatedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
            Write-Host (" (no modifications to the policy since creation).")
        }
    }
}
else {
    Write-Host ("`nNo potential device trust (mobile) policy was found.")
}

#####Admin Center#####
Write-Host "`n#####Admin Center#####" -ForegroundColor Cyan

#Cloud or Hybrid Environment?
$org = Get-MgOrganization

if ($org.OnPremisesSyncEnabled -eq $true) {
    Write-Host ("`nThe tenant ") -NoNewline
    Write-Host ($org.DisplayName) -ForegroundColor Yellow -NoNewline
    Write-Host (" is a ") -NoNewline
    Write-Host ("hybrid") -ForegroundColor Yellow -NoNewline
    Write-Host (" environment.")
} else {
    Write-Host ("`nThe tenant ") -NoNewline
    Write-Host ($org.DisplayName) -ForegroundColor Yellow -NoNewline
    Write-Host (" is a ") -NoNewline
    Write-Host ("cloud") -ForegroundColor Yellow -NoNewline
    Write-Host (" environment.")
}


#####InTune#####
Write-Host ("`n#####InTune#####") -ForegroundColor Cyan

#Windows & MacOS Device Counts
$devices = Get-MgDeviceManagementManagedDevice -All

$totalDevCount = $devices.Count
$winDevCount = ($devices | Where-Object { $_.OperatingSystem -eq "Windows" }).Count
$macDevCount = ($devices | Where-Object { $_.OperatingSystem -eq "macOS" }).Count
$androidDevCount = ($devices | Where-Object { $_.OperatingSystem -eq "android" }).Count
$iOSDevCount = ($devices | Where-Object { $_.OperatingSystem -eq "iOS" }).Count
$nonCompliantDevCount = ($devices | Where-Object { $_.ComplianceState -ne "compliant" }).Count
$personalDevCount = ($devices | Where-Object { $_.DeviceEnrollmentType -eq "userEnrollment" }).Count

Write-Host ("`nThere is/are ") -NoNewline
Write-Host ($totalDevCount) -ForegroundColor Yellow -NoNewline
Write-Host (" total device(s)") -ForegroundColor Yellow -NoNewline
Write-Host (" in this environment.")

Write-Host ("`nThere is/are ") -NoNewline
Write-Host ($winDevCount) -ForegroundColor Yellow -NoNewline
Write-Host (" Windows device(s)") -ForegroundColor Yellow -NoNewline
Write-Host (" in this environment.")

Write-Host ("`nThere is/are ") -NoNewline
Write-Host ($macDevCount) -ForegroundColor Yellow -NoNewline
Write-Host (" macOS device(s)") -ForegroundColor Yellow -NoNewline
Write-Host (" in this environment.")

Write-Host ("`nThere is/are ") -NoNewline
Write-Host ($iOSDevCount) -ForegroundColor Yellow -NoNewline
Write-Host (" iOS device(s)") -ForegroundColor Yellow -NoNewline
Write-Host (" in this environment.")

Write-Host ("`nThere is/are ") -NoNewline
Write-Host ($androidDevCount) -ForegroundColor Yellow -NoNewline
Write-Host (" Android device(s)") -ForegroundColor Yellow -NoNewline
Write-Host (" in this environment.")

Write-Host ("`nThere is/are ") -NoNewline
Write-Host ($nonCompliantDevCount) -ForegroundColor Yellow -NoNewline
Write-Host (" non-compliant device(s)") -ForegroundColor Yellow -NoNewline
Write-Host (" in this environment.")

Write-Host ("`nThere is/are ") -NoNewline
Write-Host ($personalDevCount) -ForegroundColor Yellow -NoNewline
Write-Host (" personal device(s)") -ForegroundColor Yellow -NoNewline
Write-Host (" in this environment.")

#MacOS MDM Cert Expiration
try {
    $appleMDMCert = Get-MgDeviceManagementApplePushNotificationCertificate -ErrorAction Stop

    Write-Host ("`nThe Apple MDM certificate on record expires on ") -NoNewline
    Write-Host ($appleMDMCert.ExpirationDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
    Write-Host (".")
}
catch {
    Write-Host ("`nThere is no Apple MDM certificate on record.")
}

#Feature Update Ring Info
$featureUpdatePolicies = Get-MgBetaDeviceManagementWindowsFeatureUpdateProfile -All

$winFeatureUpdateVersions = [System.Collections.ArrayList]::new()

$featureUpdatePolicies | ForEach-Object {
    [void]$winFeatureUpdateVersions.Add($_.FeatureUpdateVersion.Substring($_.FeatureUpdateVersion.Length - 4))
}

$winFeatureUpdateVersions = $winFeatureUpdateVersions | Select-Object -unique

Write-Host ("`nWindows ") -NoNewline
Write-Host ("feature update rings") -ForegroundColor Yellow -NoNewline
Write-Host (" have been found for the following versions:")

if ($winFeatureUpdateVersions.Count -eq 0) {
    Write-Host ("`nNone") -ForegroundColor Yellow
} else {
    foreach ($v in $winFeatureUpdateVersions) {
        Write-Host ("• ") -NoNewline
        Write-Host ($v) -ForegroundColor Yellow
    }
}

#Most Recent Quality Update
$qualityUpdatePolicies = Get-MgBetaDeviceManagementWindowsQualityUpdateProfile
if ($qualityUpdatePolicies) {
    ForEach ($p in $qualityUpdatePolicies) {
        Write-Host ("`nThe quality update policy named ") -NoNewline
        Write-Host ($p.DisplayName) -ForegroundColor Yellow -NoNewline
        if ($p.ModifiedDateTime) {
            Write-Host (" was last updated on ") -NoNewline
            Write-Host ($p.ModifiedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow
        }
        else {
            Write-Host (" was created on ") -NoNewline
            Write-Host ($p.CreatedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
            Write-Host (" (no modifications to the policy since creation).")
        }
    }
} else {
    Write-Host ("No potential quality update ring was found.")
}

#Device Configuration Profiles (Checking for Office Update Policy, macOS Updates, and Antivirus for macOS & Windows)
$deviceConfigurationProfiles = Get-MgBetaDeviceManagementConfigurationPolicy -All

$officeUpdatePolicy = $deviceConfigurationProfiles | Where-Object { $_.Name -match "Office" -and $_.Name -match "Update" }
if (-not $officeUpdatePolicy) {
    Write-Host ("`nNo ") -NoNewline
    Write-Host ("Office update policy") -ForegroundColor Yellow -NoNewline
    Write-Host (" was identified.")
} else {
    $officeUpdatePolicy | ForEach-Object {
        Write-Host ("`nA potential ") -NoNewline
        Write-Host ("Office update policy") -ForegroundColor Yellow -NoNewline
        Write-Host (" was found named ") -NoNewline
        Write-Host ($_.Name) -ForegroundColor Yellow -NoNewline
        Write-Host (".")
    }
}

$macOSAntivirusPolicy = $deviceConfigurationProfiles | Where-Object { $_.TemplateReference.TemplateFamily -eq "endpointSecurityAntivirus" -and $_.Platforms -eq "macOS" }

if (-not $macOSAntivirusPolicy) {
    Write-Host ("`nNo ") -NoNewline
    Write-Host ("macOS antivirus policy") -ForegroundColor Yellow -NoNewline
    Write-Host (" was identified.")
} else {
    $macOSAntivirusPolicy | ForEach-Object {
        Write-Host ("`nA potential ") -NoNewline
        Write-Host ("macOS antivirus policy") -ForegroundColor Yellow -NoNewline
        Write-Host (" was found named ") -NoNewline
        Write-Host ($_.Name) -ForegroundColor Yellow -NoNewline
        Write-Host (".")
    }
}

$macOSUpdatePolicy = $deviceConfigurationProfiles | Where-Object { ($_.Name -match "macOS Update" -or $_.Name -match "Catalina") -and $_.Platforms -eq "macOS" }

$macOSUpdatePolicy | ForEach-Object {
    Write-Host ("`nA potential ") -NoNewline
    Write-Host ("macOS update policy") -ForegroundColor Yellow -NoNewline
    Write-Host (" was found named ") -NoNewline
    Write-Host ($_.Name) -ForegroundColor Yellow -NoNewline
    Write-Host (".")
}

$winAVPolicy = $deviceConfigurationProfiles | Where-Object { $_.TemplateReference.TemplateFamily -eq "endpointSecurityAntivirus" -and $_.Name -notmatch "experience" }

if (!$winAVPolicy) {
    Write-Host ("`nNo ") -NoNewline
    Write-Host ("Windows antivirus policies") -ForegroundColor Yellow -NoNewline
    Write-Host (" were found.")
} elseif ($winAVPolicy.Count -eq 1) {
    Write-Host ("`nA potential ") -NoNewline
    Write-Host ("Windows antivirus policy") -ForegroundColor Yellow -NoNewline
    Write-Host (" was found named ") -NoNewline
    Write-Host ($winAVPolicy.Name) -ForegroundColor Yellow -NoNewline
    Write-Host (", which was last modified on ") -NoNewline
    Write-Host ($winAVPolicy.LastModifiedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
    Write-Host (".")
} else {
    Write-Host `nThe following policies are all current Windows antivirus policies.
    $winAVPolicy | ForEach-Object {
        Write-Host ("• ") -NoNewline
        Write-Host ($_.Name + " (Modified On: " + $_.LastModifiedDateTime.ToString("MM/dd/yyyy") + ").") -ForegroundColor Yellow
    }
}

$winSecExpPolicy = $deviceConfigurationProfiles | Where-Object { $_.TemplateReference.TemplateFamily -eq "endpointSecurityAntivirus" -and $_.Name -match "experience" }

if (!$winSecExpPolicy) {
    Write-Host ("`nNo ") -NoNewline
    Write-Host ("Windows security experience") -ForegroundColor Yellow -NoNewline
    Write-Host (" policies were found.")
} elseif ($winSecExpPolicy.Count -eq 1) {
    Write-Host ("`nA potential ") -NoNewline
    Write-Host ("Windows security experience") -ForegroundColor Yellow -NoNewline
    Write-Host (" policy was found named ") -NoNewline
    Write-Host ($winSecExpPolicy.Name) -ForegroundColor Yellow -NoNewline
    Write-Host (", which was last modified on ") -NoNewline
    Write-Host ($winSecExpPolicy.LastModifiedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
    Write-Host (".")
} else {
    Write-Host ("`nThe following policies are all current ") -NoNewline
    Write-Host ("Windows security experience") -ForegroundColor Yellow -NoNewline
    Write-Host (" policies.")
    $winSecExpPolicy | ForEach-Object {
        Write-Host ("• ") -NoNewline
        Write-Host ($_.Name + " (Modified On: " + $_.LastModifiedDateTime.ToString("MM/dd/yyyy") + ")") -ForegroundColor Yellow -NoNewline
        Write-Host (".")
    }
}

$asrPolicy = $deviceConfigurationProfiles | Where-Object { $_.Name -match "ASR" }

if (!$asrPolicy) {
    Write-Host ("`nNo ") -NoNewline
    Write-Host ("ASR policy") -ForegroundColor Yellow -NoNewline
    Write-Host (" was found.")
} elseif ($asrPolicy.Count -eq 1) {
    Write-Host ("`nA potential ") -NoNewline
    Write-Host ("ASR policy") -ForegroundColor Yellow -NoNewline
    Write-Host (" was found named ") -NoNewline
    Write-Host ($asrPolicy.Name) -ForegroundColor Yellow -NoNewline
    Write-Host (", which was last modified on ") -NoNewline
    Write-Host ($asrPolicy.LastModifiedDateTime.ToString("MM/dd/yyyy")) -ForegroundColor Yellow -NoNewline
    Write-Host (".")
} else {
    Write-Host ("`nThe following policies are all current ") -NoNewline
    Write-Host ("ASR policies") -ForegroundColor Yellow -NoNewline
    Write-Host (".")
    $asrPolicy | ForEach-Object {
        Write-Host ("• ") -NoNewline
        Write-Host ($_.Name + " (Modified On: " + $_.LastModifiedDateTime.ToString("MM/dd/yyyy") + ")") -ForegroundColor Yellow -NoNewline
        Write-Host (".")
    }
}

#####Defender for Endpoint#####
Write-Host "`n#####Defender for Endpoint#####" -ForegroundColor Cyan

#SecureScore(s)
function Format-SecureScorePercent($s) {
    if ($s.MaxScore -gt 0) {
        return ("{0:P2}" -f ($s.CurrentScore / $s.MaxScore))
    }
    return $null
}

$secureScores = Get-MgSecuritySecureScore -Top 90

$secureScoreToday = Format-SecureScorePercent($secureScores | Sort-Object CreatedDateTime -Descending | Select-Object -First 1)
$secureScore30DaysAgo = Format-SecureScorePercent($secureScores | Where-Object { $_.CreatedDateTime -lt (Get-Date).AddDays(-30) } | Sort-Object CreatedDateTime -Descending | Select-Object -First 1)
$secureScore60DaysAgo = Format-SecureScorePercent($secureScores | Where-Object { $_.CreatedDateTime -lt (Get-Date).AddDays(-60) } | Sort-Object CreatedDateTime -Descending | Select-Object -First 1)
$secureScore90DaysAgo = Format-SecureScorePercent($secureScores | Sort-Object CreatedDateTime -Descending | Select-Object -Last 1)

Write-Host "`nSecureScore:" -ForegroundColor Green

if ($secureScoreToday -eq $null) {
    Write-Host ("A null value was returned for the current SecureScore.") -ForegroundColor Red
} else {
    Write-Host ("Today: ") -NoNewline
    Write-Host ($secureScoreToday) -ForegroundColor Yellow
}

if ($secureScore30DaysAgo -eq $null) {
    Write-Host ("A null value was returned for the 30-day SecureScore.") -ForegroundColor Red
} else {
    Write-Host ("30 Days Ago: ") -NoNewline
    Write-Host ($secureScore30DaysAgo) -ForegroundColor Yellow
}

if ($secureScore60DaysAgo -eq $null) {
    Write-Host ("A null value was returned for the 60-day SecureScore.") -ForegroundColor Red
} else {
    Write-Host ("60 Days Ago: ") -NoNewline
    Write-Host ($secureScore60DaysAgo) -ForegroundColor Yellow
}

if ($secureScore90DaysAgo -eq $null) {
    Write-Host ("A null value was returned for the 90-day SecureScore.") -ForegroundColor Red
} else {
    Write-Host ("90 Days Ago: ") -NoNewline
    Write-Host ($secureScore90DaysAgo) -ForegroundColor Yellow
}

#Disconnect from MgGraph and Connect to IPPSession
$null = Disconnect-MgGraph

Connect-IPPSSession -ShowBanner:$false

$dfeAtpHighSeverityAlerts = Get-ProtectionAlert | Where-Object { $_.Severity -eq "high" } | Select-Object Name, NotificationEnabled, NotifyUser

Write-Host ("`nDefender ATP Alerts and Recipients:") -ForegroundColor Green

$dfeAtpHighSeverityAlerts | ForEach-Object {
    if ($_.NotificationEnabled -eq $false) {
        Write-Host ("`n!!! The alert '") -ForegroundColor Red -NoNewline
        Write-Host ($_.Name) -ForegroundColor Yellow -NoNewline
        Write-Host ("' is not currently enabled.") -ForegroundColor Red
    }
    Write-Host ("• ") -NoNewline
    Write-Host ("'" + $_.Name + "'") -ForegroundColor Yellow -NoNewline
    Write-Host (" is currently being sent to ") -NoNewline
    Write-Host ($_.NotifyUser) -ForegroundColor Yellow -NoNewline
    Write-Host (".")
}

Get-PSSession | Remove-PSSession

$null = Read-Host -Prompt "Press Enter to continue"