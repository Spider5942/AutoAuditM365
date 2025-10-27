<####################
Author: Carson Williams
Summary:
    This script is intended to retrieve various data through MS Graph or Exchange Online
    which otherwise would necessitate accessing Entra ID, the M365 Admin Center, InTune,
    and Microsoft Defender.
Initial Creation: 2025-10-25
Last Edit: 2025-10-26
Changelog:
    2025-10-25: Added functionality to retrieve conditional access risk policies
                Added functionality to determine cloud or hybrid status
                Added functionality to determine Windows and macOS device counts
                Added functionality to retrieve Apple MDM certificate expiration date
                Added functionality to identify Windows feature update policies and corresponding versions
                Completed InTune section (for now), which checks for Windows/macOS updates, office updates, AV/ASR policies, etc.
                Completed Defender section (for now). All basic data retrieval tasks completed.
    2025-10-26: Added (work-in-progress) JSON export functionality. Determining what data needs to be passed along.
####################>

#Define scopes for reading relevant info
$scopes = @(
    "Policy.Read.All",
    "SecurityEvents.Read.All",
    "Directory.Read.All",
    "Organization.Read.All",
    "DeviceManagementConfiguration.Read.All",
    "Group.Read.All",
    "SecurityEvents.Read.All",
    "CustomDetection.Read.All"
)

#Connect to MS Graph using specified scopes
Connect-MgGraph -Scopes $scopes -NoWelcome

###Entra ID###
#Retrieve sign-in/user risk policies, sort into separate variables, and remove initial variable
$riskPolicies = Get-MgIdentityConditionalAccessPolicy -All |
                Where-Object { $_.Conditions.SignInRiskLevels -or $_.Conditions.UserRiskLevels }

$signInRiskPolicy = $riskPolicies |
                    Where-Object { $_.Conditions.SignInRiskLevels } |
                    Select-Object DisplayName, State, ModifiedDateTime

$userRiskPolicy = $riskPolicies |
                  Where-Object { $_.Conditions.UserRiskLevels } |
                  Select-Object DisplayName, State, ModifiedDateTime

Remove-Variable riskPolicies

###Admin Center###
$org = Get-MgOrganization

$orgName = $org.DisplayName
$orgID = $org.Id

if ($org.OnPremisesSyncEnabled -eq $false) {
    $orgIsHybrid = $false
}
else {
    $orgIsHybrid = $true
}

###InTune###
#Retrieve list of devices and count of Windows/macOS managed devices
$devices = Get-MgDeviceManagementManagedDevice -all

$winDevCount = ($devices | Where-Object { $_.OperatingSystem -eq "Windows" }).Count
$macDevCount = ($devices | Where-Object { $_.OperatingSystem -eq "macOS" }).Count

Remove-Variable devices

#Retrieve Apple MDM push certificate expiration date
$appleMDMCertExpiration = (Get-MgDeviceManagementApplePushNotificationCertificate).ExpirationDateTime

#Retrieve Windows feature update policy/policies
$winFeatureUpdatePolicies = Get-MgBetaDeviceManagementWindowsFeatureUpdateProfile -All |
                         Where-Object { $_.FeatureUpdateVersion -match "Windows" }

$winFeatureUpdateVersions = [System.Collections.ArrayList]::new()

$winFeatureUpdatePolicies | ForEach-Object {
    [void]$winFeatureUpdateVersions.Add($_.FeatureUpdateVersion.Substring($_.FeatureUpdateVersion.Length - 4))
}

$winFeatureUpdateVersions = $winFeatureUpdateVersions | Select-Object -unique

#Retrieve last quality update release date
$winQualityUpdatePolicyLastModified = (Get-MgBetaDeviceManagementWindowsQualityUpdateProfile).LastModifiedDateTime

#Retrieve and sort through device configuration policies (looking for office updates, macOS updates, and AV for windows & macOS)
$deviceConfigurationProfiles = Get-MgBetaDeviceManagementConfigurationPolicy -All

#Check for macOS update policy
$macOSUpdatePolicy = $deviceConfigurationProfiles | Where-Object { ($_.Name -match "macOS Update" -or $_.Name -match "Catalina") -and $_.Platforms -eq "macOS" }

#Check for Office Update policy
$officeUpdatePolicy = $deviceConfigurationProfiles | Where-Object { $_.Name -match "Office" -and $_.Name -match "Update" }

#Check for Windows & macOS AV policies
$winAVPolicy = $deviceConfigurationProfiles | Where-Object { $_.TemplateReference.TemplateFamily -eq "endpointSecurityAntivirus" -and $_.Platforms -match "windows" }
$macOSAVPolicy = $deviceConfigurationProfiles | Where-Object { $_.TemplateReference.TemplateFamily -eq "endpointSecurityAntivirus" -and $_.Platforms -eq "macOS" }

#Check for Defender Security Experience policy
$winSecExpPolicy = $deviceConfigurationProfiles | Where-Object { $_.TemplateReference.TemplateFamily -eq "microsoftDefenderSecurityExperience" }

#Check for ASR policy
$asrPolicy = $deviceConfigurationProfiles | Where-Object { $_.Name -match "ASR" }

Remove-Variable deviceConfigurationProfiles

###Defender###
#Declaring SecureScore Function to format values on 100-point scale
function Format-SecureScorePercent($score) {
    if ($score.MaxScore -gt 0) {
        return ("{0:P2}" -f ($score.CurrentScore / $score.MaxScore))
    }
    return $null
}

#Retrieve SecureScore values over past 90 days
$secureScores = Get-MgSecuritySecureScore -Top 90

#Identify historic values (i.e, current, 30-day, 60-day, and 90-day) and format using Format-SecureScorePercent() function
$secureScoreToday = Format-SecureScorePercent($secureScores | Sort-Object CreatedDateTime -Descending | Select-Object -First 1)
$secureScore30DaysAgo = Format-SecureScorePercent($secureScores | Where-Object { $_.CreatedDateTime -lt (Get-Date).AddDays(-30) } | Sort-Object CreatedDateTime -Descending | Select-Object -First 1)
$secureScore60DaysAgo = Format-SecureScorePercent($secureScores | Where-Object { $_.CreatedDateTime -lt (Get-Date).AddDays(-60) } | Sort-Object CreatedDateTime -Descending | Select-Object -First 1)
$secureScore90DaysAgo = Format-SecureScorePercent($secureScores | Sort-Object CreatedDateTime -Descending | Select-Object -Last 1)

Remove-Variable secureScores

#Disconnect from MS Graph and begin IP Session silently
$null = Disconnect-MgGraph
Connect-IPPSSession -ShowBanner:$false

#Retrieve Defender ATP high-severity alerts, status, and recipients
$dfeATPHighSeverityAlerts = Get-ProtectionAlert | Where-Object { $_.Severity -eq "high" } | Select Name, NotificationEnabled, NotifyUser

#Retrieve and remove all active PS Sessions
Get-PSSession | Remove-PSSession

###JSON Data Export Process###
#Package all data into PSCustomObject for
$envelope = [PSCustomObject]@{
    tenantName = $orgName
    tenantID = $orgId
    isHybrid = $orgIsHybrid
    signInRiskPolicy = $signInRiskPolicy
    userRiskPolicy = $userRiskPolicy
    winDevCount = $winDevCount
    macDevCount = $macDevCount
    appleMDMCertExpiration = $appleMDMCertExpiration
    winFeatureUpdateVersions = $winFeatureUpdateVersions
    winQualityUpdateDate = $winQualityUpdatePolicyLastModified
    macOSUpdate = $macOSUpdatePolicy
    officeUpdatePolicy = $officeUpdatePolicy
    winAVPolicy = $winAVPolicy
    winSecExpPolicy = $winSecExpPolicy
    macOSAVPolicy = $macOSAVPolicy
    asrPolicy = $asrPolicy
    secureScoreToday = $secureScoreToday
    secureScore30DaysAgo = $secureScore30DaysAgo
    secureScore60DaysAgo = $secureScore60DaysAgo
    secureScore90DaysAgo = $secureScore90DaysAgo
    defATPHighSeverityAlerts = $dfeATPHighSeverityAlerts
}

#Assign output path (for now just in the same folder as the script)
$outPath = Join-Path $PSScriptRoot "$orgName.json"

#May need to use -Depth parameter for ConvertTo-Json if nested data is included later on
$json = $envelope | ConvertTo-Json -Compress
$json | Out-File -FilePath $outPath -Encoding utf8