# Import Group Policy module
Import-Module GroupPolicy

# Generate GPO Report and save it as XML
Get-GPOReport -All -ReportType Xml -Domain "RTSnetworking.com" -Server "RTS-DC1" -Path xml-report\gporeport.xml

# Convert XML to XML object for easier handling
[xml]$xmlData = Get-Content 'xml-report\gporeport.xml'

# Create a namespace manager
$nsManager = New-Object System.Xml.XmlNamespaceManager($xmlData.NameTable)
$nsManager.AddNamespace("gp", "http://www.microsoft.com/GroupPolicy/Settings")
$nsManager.AddNamespace("sec", "http://www.microsoft.com/GroupPolicy/Settings/Security")


# XPath to find the PasswordHistorySize within the specific GPO
$passwordHistory = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='PasswordHistorySize']", $nsManager)
# Desired setting
$desiredPasswordHistory = 24
# Compare current setting to desired setting
if ([int]$passwordHistory.SettingNumber -ge $desiredPasswordHistory) {
    Write-Output "PASSED: 'Enforce password history' is set to $($passwordHistory.SettingNumber)"
} else {
    Write-Output "FAILED: 'Enforce password history' is set to $($passwordHistory.SettingNumber)"
}

$maxPasswordAge = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='MaximumPasswordAge']", $nsManager)
# Desired setting for maximum password age
$desiredMaxPasswordAge = 365
# Compare current setting to desired setting
if ([int]$maxPasswordAge.SettingNumber -le $desiredMaxPasswordAge -and [int]$maxPasswordAge.SettingNumber -gt 0 ) {
    Write-Output "PASSED: 'Maximum password age' is set to $($maxPasswordAge.SettingNumber)"
} else {
    Write-Output "FAILED: 'Maximum password age' is set to $($passwordHistory.SettingNumber)"
}

$minPasswordAge = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='MinimumPasswordAge']", $nsManager)
# Desired setting for minimum password age
$desiredMinPasswordAge = 1
# Compare current setting to desired setting
if ([int]$minPasswordAge.SettingNumber -le $desiredMinPasswordAge) {
    Write-Output "PASSED: 'Minimum password age' is set to $($minPasswordAge.SettingNumber)"
} else {
    Write-Output "FAILED: 'Minimum password age' is set to $($minPasswordAge.SettingNumber)"
}

$minPasswordLength = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='MinimumPasswordLength']", $nsManager)
# Desired setting for minimum password length
$desiredMinPasswordLength = 14
# Compare current setting to desired setting
if ([int]$minPasswordLength.SettingNumber -ge $desiredMinPasswordLength) {
    Write-Output "PASSED: 'Minimum password length' is set to $($minPasswordLength.SettingNumber)"
} else {
    Write-Output "FAILED: 'Minimum password length' is set to $($minPasswordLength.SettingNumber)."
}

$passwordComplexity = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='PasswordComplexity']", $nsManager)
# Desired setting for password complexity
$desiredPasswordComplexity = "true"
# Compare current setting to desired setting
if ([string]$passwordComplexity.SettingBoolean -eq $desiredPasswordComplexity) {
    Write-Output "PASSED: 'Password must meet complexity requirements' is set to enabled"
} else {
    Write-Output "FAILED: 'Password must meet complexity requirements' is set to disabled."
}

$clearTextPassword = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='ClearTextPassword']", $nsManager)
# Desired setting for password complexity
$desiredClearTextPassword = "false"
# Compare current setting to desired setting
if ([string]$clearTextPassword.SettingBoolean -eq $desiredClearTextPassword) {
    Write-Output "PASSED: 'Store passwords using reversible encryption' is set to disabled"
} else {
    Write-Output "FAILED: 'Store passwords using reversible encryption' is set to enabled."
}


# Define the registry path and the key
$registryPath = "HKLM:\System\CurrentControlSet\Control\SAM"
$propertyName = "RelaxMinimumPasswordLengthLimits"
$fullRegistryPath = "$registryPath\$propertyName"
# Check if the registry path exists
if (Test-Path $fullRegistryPath) {
    try {
        # Get the registry property value
        $registryValue = Get-ItemProperty -Path $registryPath -Name $propertyName

        # Check if the value is as expected
        if ($registryValue.$propertyName -eq 1) {
            Write-Output "PASSED: 'Relax minimum password length limits' is set to enabled."
        } else {
            Write-Output "FAILED: 'Relax minimum password length limits' is set to disabled."
        }
        Write-Output "This setting only affects local accounts on the computer."
    } catch {
        Write-Output "Failed to retrieve the property. It may not exist or some error occurred."
        Write-Output "This setting only affects local accounts on the computer."
    }
} else {
    Write-Output "NEUTRAL: 'Relax minimum password length limits' is not set."
    Write-Output "  '^^^' This setting only affects local accounts on the computer."
}

$lockoutDuration = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='LockoutDuration']", $nsManager)
# Desired setting for password complexity
$desiredLockoutDuration = 15
if ($null -ne $lockoutDuration){
    # Compare current setting to desired setting
    if ([int]$lockoutDuration.SettingNumber -ge $desiredLockoutDuration) {
        Write-Output "PASSED: 'Account lockout duration' is set to $($lockoutDuration.SettingNumber)."
    } else {
        Write-Output "FAILED: 'Account lockout duration' is set to $($lockoutDuration.SettingNumber).."
    }
} else {
    Write-Output "FAILED: 'Account lockout durations' is not set."
}

$lockoutThreshold = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='LockoutBadCount']", $nsManager)
# Desired setting for password complexity
$desiredLockoutThreshold = 5
if ($null -ne $lockoutThreshold){
    # Compare current setting to desired setting
    if ([int]$lockoutThreshold.SettingNumber -le $desiredLockoutThreshold -and [int]$lockoutThreshold.SettingNumber -ne 0) {
        Write-Output "PASSED: 'Account lockout threshold' is set to $($lockoutThreshold.SettingNumber)."
    } else {
        Write-Output "FAILED: 'Account lockout threshold' is set to $($lockoutThreshold.SettingNumber).."
    }
} else {
    Write-Output "FAILED: 'Account lockout threshold' is not set."
}

$allowAdministratorAccountLockout = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='AllowAdministratorLockout']", $nsManager)
# Desired setting for password complexity
$desiredAdministratorLockout = "true"
if ($null -ne $allowAdministratorAccountLockout){
    # Compare current setting to desired setting
    if ([string]$allowAdministratorAccountLockout.SettingBoolean -eq $desiredAdministratorLockout ) {
        Write-Output "PASSED: 'Allow Administrator account lockout' is set to enabled."
    } else {
        Write-Output "FAILED: 'Allow Administrator account lockout' is set to disabled."
    }
} else {
    Write-Output "FAILED: 'Allow Administrator account lockout' is not set."
}

$resetLockoutCount = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='ResetLockoutCount']", $nsManager)
# Desired setting for password complexity
$desiredResetLockoutCount = 15
if ($null -ne $resetLockoutCount){
    # Compare current setting to desired setting
    if ([int]$resetLockoutCount.SettingNumber -ge $desiredResetLockoutCount ) {
        Write-Output "PASSED: 'Reset account lockout counter after' is set to $($resetLockoutCount.SettingNumber)."
    } else {
        Write-Output "FAILED: 'Reset account lockout counter after' is set to $($resetLockoutCount.SettingNumber)."
    }
} else {
    Write-Output "FAILED: 'Reset account lockout counter after' is not set."
}

