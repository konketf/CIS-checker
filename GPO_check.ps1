# Import Group Policy module
Import-Module GroupPolicy

# Generate GPO Report and save it as XML
# Get-GPOReport -All -ReportType Xml -Domain "RTSnetworking.com" -Server "RTS-DC1" -Path xml-report\gporeport.xml

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
    Write-Output "PASSED: Current PasswordHistorySize is $($passwordHistory.SettingNumber)"
} else {
    Write-Output "FAILED: Current PasswordHistorySize is $($passwordHistory.SettingNumber)"
}

$maxPasswordAge = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='MaximumPasswordAge']", $nsManager)
# Desired setting for maximum password age
$desiredMaxPasswordAge = 365
# Compare current setting to desired setting
if ([int]$maxPasswordAge.SettingNumber -le $desiredMaxPasswordAge -and [int]$maxPasswordAge.SettingNumber -gt 0 ) {
    Write-Output "PASSED: Current MaximumPasswordAge is $($maxPasswordAge.SettingNumber)"
} else {
    Write-Output "FAILED: Current MaximumPasswordAge is $($passwordHistory.SettingNumber)"
}

$minPasswordAge = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='MinimumPasswordAge']", $nsManager)
# Desired setting for minimum password age
$desiredMinPasswordAge = 1
# Compare current setting to desired setting
if ([int]$minPasswordAge.SettingNumber -le $desiredMinPasswordAge) {
    Write-Output "PASSED: Current MinimumPasswordAge is $($minPasswordAge.SettingNumber)"
} else {
    Write-Output "FAILED: Current MinimumPasswordAge is $($minPasswordAge.SettingNumber)"
}

$minPasswordLength = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='MinimumPasswordLength']", $nsManager)
# Desired setting for minimum password length
$desiredMinPasswordLength = 14
# Compare current setting to desired setting
if ([int]$minPasswordLength.SettingNumber -ge $desiredMinPasswordLength) {
    Write-Output "PASSED: Current MinimumPasswordLength is $($minPasswordLength.SettingNumber)"
} else {
    Write-Output "FAILED: Current MinimumPasswordLength is $($minPasswordLength.SettingNumber)."
}

$passwordComplexity = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:Account[sec:Name='PasswordComplexity']", $nsManager)
# Desired setting for password complexity
$desiredPasswordComplexity = "true"
# Compare current setting to desired setting
if ([string]$passwordComplexity.SettingBoolean -eq $desiredPasswordComplexity) {
    Write-Output "PASSED: PasswordComplexity is enabled"
} else {
    Write-Output "FAILED: PasswordComplexity is disabled."
}