# Import Group Policy module
Import-Module GroupPolicy

# Generate GPO Report and save it as XML
$domain = "RTSnetworking.com"
$server = "RTS-DC1"
$xmlReportPath = "xml-report\gporeport2.xml"
Get-GPOReport -All -ReportType Xml -Domain $domain -Server $server -Path $xmlReportPath

# Convert XML to XML object for easier handling
[xml]$xmlData = Get-Content $xmlReportPath

# Create a namespace manager
$nsManager = New-Object System.Xml.XmlNamespaceManager($xmlData.NameTable)
$nsManager.AddNamespace("gp", "http://www.microsoft.com/GroupPolicy/Settings")
$nsManager.AddNamespace("sec", "http://www.microsoft.com/GroupPolicy/Settings/Security")
$nsManager.AddNamespace("types", "http://www.microsoft.com/GroupPolicy/Types")

# XPath to find the 'Accounts: Block Microsoft accounts' policy within the specific GPO
$microsoftAccountsPolicy = $xmlData.SelectSingleNode("//sec:Name[.='Accounts: Block Microsoft accounts']", $nsManager)

# Desired setting
$desiredSetting = "Users can't add or log on with Microsoft accounts"

# Check and compare the current setting
if ($null -ne $microsoftAccountsPolicy) {
    # Navigate to the parent node to find the setting
    $policyParentNode = $microsoftAccountsPolicy.ParentNode
    $currentSettingNode = $policyParentNode.SelectSingleNode("sec:DisplayString", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Accounts: Block Microsoft accounts' is set to 'Users can't add or log on with Microsoft accounts'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Accounts: Block Microsoft accounts' is not set correctly. Current setting: '$currentSetting'. Set it to 'Users can't add or log on with Microsoft accounts'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Accounts: Block Microsoft accounts' current setting not found. Set it to 'Users can't add or log on with Microsoft accounts'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Accounts: Block Microsoft accounts' policy not found. Set it to 'Users can't add or log on with Microsoft accounts'!" -ForegroundColor Red
}


# Check if the Guest account is disabled
$guestAccount = Get-LocalUser -Name "Guest"

if ($guestAccount.Enabled -eq $false) {
    Write-Host "PASSED: 'Accounts: Guest account status' is set to 'Disabled'." -ForegroundColor Blue
} else {
    Write-Host "FAILED: 'Accounts: Guest account status' is not set correctly. Current state: 'Enabled'. Set it to 'Disabled'!" -ForegroundColor Red
}


# XPath to find the 'Accounts: Limit local account use of blank passwords to console logon only' policy within the specific GPO
$blankPasswordPolicy = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Accounts: Limit local account use of blank passwords to console logon only']", $nsManager)

# Desired setting
$desiredSetting = "true"

# Check and compare the current setting
if ($null -ne $blankPasswordPolicy) {
    # Navigate to the setting node to find the DisplayBoolean value
    $currentSettingNode = $blankPasswordPolicy.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Accounts: Limit local account use of blank passwords to console logon only' is set to 'Enabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Accounts: Limit local account use of blank passwords to console logon only' is not set correctly. Current setting: '$currentSetting'. Set it to 'Enabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Accounts: Limit local account use of blank passwords to console logon only' current setting not found. Set it to 'Enabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Accounts: Limit local account use of blank passwords to console logon only' policy not found. Set it to 'Enabled'!" -ForegroundColor Red
}


$adminAccount = Get-LocalUser -Name "Administrator" -ErrorAction SilentlyContinue

if ($null -ne $adminAccount) {
    Write-Host "The 'Administrator' account exists. Use the 'Accounts: Rename administrator account' policy to rename it." -ForegroundColor Red
} else {
    Write-Host "The 'Administrator' account does not exist or has already been renamed." -ForegroundColor Green
}


$guestAccount = Get-LocalUser -Name "Guest" -ErrorAction SilentlyContinue

if ($null -ne $guestAccount) {
    Write-Host "The 'Guest' account exists. Use the 'Accounts: Rename guest account' policy to rename it." -ForegroundColor Red
} else {
    Write-Host "The 'Guest' account does not exist or has already been renamed." -ForegroundColor Green
}


# XPath to find the 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' policy within the specific GPO
$auditPolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings']", $nsManager)

# Desired setting
$desiredSetting = "true"

# Check and compare the current setting
if ($null -ne $auditPolicyNode) {
    # Navigate to the setting node to find the Displayboolean value
    $currentSettingNode = $auditPolicyNode.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is set to 'Enabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' is not set correctly. Current setting: '$currentSetting'. Set it to 'Enabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' current setting not found. Set it to 'Enabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Audit: Force audit policy subcategory settings (Windows Vista or later) to override audit policy category settings' policy not found. Set it to 'Enabled'!" -ForegroundColor Red
}


# XPath to find the 'Audit: Shut down system immediately if unable to log security audits' policy within the specific GPO
$auditPolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Audit: Shut down system immediately if unable to log security audits']", $nsManager)

# Desired setting
$desiredSetting = "false"

# Check and compare the current setting
if ($null -ne $auditPolicyNode) {
    # Navigate to the setting node to find the DisplayBoolean value
    $currentSettingNode = $auditPolicyNode.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Audit: Shut down system immediately if unable to log security audits' is set to 'Disabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Audit: Shut down system immediately if unable to log security audits' is not set correctly. Current setting: '$currentSetting'. Set it to 'Disabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Audit: Shut down system immediately if unable to log security audits' current setting not found. Set it to 'Disabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Audit: Shut down system immediately if unable to log security audits' policy not found. Set it to 'Disabled'!" -ForegroundColor Red
}


# XPath to find the 'Devices: Prevent users from installing printer drivers' policy within the specific GPO
$printerDriverPolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Devices: Prevent users from installing printer drivers']", $nsManager)

# Desired setting
$desiredSetting = "true"

# Check and compare the current setting
if ($null -ne $printerDriverPolicyNode) {
    # Navigate to the setting node to find the DisplayBoolean value
    $currentSettingNode = $printerDriverPolicyNode.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Devices: Prevent users from installing printer drivers' is set to 'Enabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Devices: Prevent users from installing printer drivers' is not set correctly. Current setting: '$currentSetting'. Set it to 'Enabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Devices: Prevent users from installing printer drivers' current setting not found. Set it to 'Enabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Devices: Prevent users from installing printer drivers' policy not found. Set it to 'Enabled'!" -ForegroundColor Red
}


# XPath to find the 'Domain member: Digitally encrypt or sign secure channel data (always)' policy within the specific GPO
$secureChannelPolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Domain member: Digitally encrypt or sign secure channel data (always)']", $nsManager)

# Desired setting
$desiredSetting = "true"

# Check and compare the current setting
if ($null -ne $secureChannelPolicyNode) {
    # Navigate to the setting node to find the DisplayBoolean value
    $currentSettingNode = $secureChannelPolicyNode.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Domain member: Digitally encrypt or sign secure channel data (always)' is set to 'Enabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Domain member: Digitally encrypt or sign secure channel data (always)' is not set correctly. Current setting: '$currentSetting'. Set it to 'Enabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Domain member: Digitally encrypt or sign secure channel data (always)' current setting not found. Set it to 'Enabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Domain member: Digitally encrypt or sign secure channel data (always)' policy not found. Set it to 'Enabled'!" -ForegroundColor Red
}


# XPath to find the 'Domain member: Digitally encrypt secure channel data (when possible)' policy within the specific GPO
$secureChannelWhenPossiblePolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Domain member: Digitally encrypt secure channel data (when possible)']", $nsManager)

# Desired setting
$desiredSetting = "true"

# Check and compare the current setting
if ($null -ne $secureChannelWhenPossiblePolicyNode) {
    # Navigate to the setting node to find the DisplayBoolean value
    $currentSettingNode = $secureChannelWhenPossiblePolicyNode.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Domain member: Digitally encrypt secure channel data (when possible)' is set to 'Enabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Domain member: Digitally encrypt secure channel data (when possible)' is not set correctly. Current setting: '$currentSetting'. Set it to 'Enabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Domain member: Digitally encrypt secure channel data (when possible)' current setting not found. Set it to 'Enabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Domain member: Digitally encrypt secure channel data (when possible)' policy not found. Set it to 'Enabled'!" -ForegroundColor Red
}


# XPath to find the 'Domain member: Digitally sign secure channel data (when possible)' policy within the specific GPO
$secureChannelSignWhenPossiblePolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Domain member: Digitally sign secure channel data (when possible)']", $nsManager)

# Desired setting
$desiredSetting = "true"

# Check and compare the current setting
if ($null -ne $secureChannelSignWhenPossiblePolicyNode) {
    # Navigate to the setting node to find the DisplayBoolean value
    $currentSettingNode = $secureChannelSignWhenPossiblePolicyNode.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Domain member: Digitally sign secure channel data (when possible)' is set to 'Enabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Domain member: Digitally sign secure channel data (when possible)' is not set correctly. Current setting: '$currentSetting'. Set it to 'Enabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Domain member: Digitally sign secure channel data (when possible)' current setting not found. Set it to 'Enabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Domain member: Digitally sign secure channel data (when possible)' policy not found. Set it to 'Enabled'!" -ForegroundColor Red
}


# XPath to find the 'Domain member: Disable machine account password changes' policy within the specific GPO
$disableMachinePasswordChangesPolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Domain member: Disable machine account password changes']", $nsManager)

# Desired setting
$desiredSetting = "false"

# Check and compare the current setting
if ($null -ne $disableMachinePasswordChangesPolicyNode) {
    # Navigate to the setting node to find the DisplayBoolean value
    $currentSettingNode = $disableMachinePasswordChangesPolicyNode.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Domain member: Disable machine account password changes' is set to 'Disabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Domain member: Disable machine account password changes' is not set correctly. Current setting: '$currentSetting'. Set it to 'Disabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Domain member: Disable machine account password changes' current setting not found. Set it to 'Disabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Domain member: Disable machine account password changes' policy not found. Set it to 'Disabled'!" -ForegroundColor Red
}


# XPath to find the 'Domain member: Maximum machine account password age' policy within the specific GPO
$maxPasswordAgePolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Domain member: Maximum machine account password age']", $nsManager)

# Desired setting range
$maxDesiredSetting = 30
$minDesiredSetting = 1

# Check and compare the current setting
if ($null -ne $maxPasswordAgePolicyNode) {
    # Navigate to the setting node to find the DisplayNumber value
    $currentSettingNode = $maxPasswordAgePolicyNode.SelectSingleNode("sec:DisplayNumber", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = [int]$currentSettingNode.InnerText.Trim()
        if ($currentSetting -le $maxDesiredSetting -and $currentSetting -ge $minDesiredSetting) {
            Write-Host "PASSED: 'Domain member: Maximum machine account password age' is set to $currentSetting days, which is within the desired range (1-30 days)." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Domain member: Maximum machine account password age' is not set correctly. Current setting: '$currentSetting'. Set it to a value between 1 and 30 days!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Domain member: Maximum machine account password age' current setting not found. Set it to a value between 1 and 30 days!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Domain member: Maximum machine account password age' policy not found. Set it to a value between 1 and 30 days!" -ForegroundColor Red
}


# XPath to find the 'Domain member: Require strong (Windows 2000 or later) session key' policy within the specific GPO
$strongSessionKeyPolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Domain member: Require strong (Windows 2000 or later) session key']", $nsManager)

# Desired setting
$desiredSetting = "true"

# Check and compare the current setting
if ($null -ne $strongSessionKeyPolicyNode) {
    # Navigate to the setting node to find the DisplayBoolean value
    $currentSettingNode = $strongSessionKeyPolicyNode.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Domain member: Require strong (Windows 2000 or later) session key' is set to 'Enabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Domain member: Require strong (Windows 2000 or later) session key' is not set correctly. Current setting: '$currentSetting'. Set it to 'Enabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Domain member: Require strong (Windows 2000 or later) session key' current setting not found. Set it to 'Enabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Domain member: Require strong (Windows 2000 or later) session key' policy not found. Set it to 'Enabled'!" -ForegroundColor Red
}


# XPath to find the 'Interactive logon: Do not require CTRL+ALT+DEL' policy within the specific GPO
$ctrlAltDelPolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Interactive logon: Do not require CTRL+ALT+DEL']", $nsManager)

# Desired setting
$desiredSetting = "false"

# Check and compare the current setting
if ($null -ne $ctrlAltDelPolicyNode) {
    # Navigate to the setting node to find the DisplayBoolean value
    $currentSettingNode = $ctrlAltDelPolicyNode.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Interactive logon: Do not require CTRL+ALT+DEL' is set to 'Disabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Interactive logon: Do not require CTRL+ALT+DEL' is not set correctly. Current setting: '$currentSetting'. Set it to 'Disabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Interactive logon: Do not require CTRL+ALT+DEL' current setting not found. Set it to 'Disabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Interactive logon: Do not require CTRL+ALT+DEL' policy not found. Set it to 'Disabled'!" -ForegroundColor Red
}


# XPath to find the 'Interactive logon: Don't display last signed-in' policy within the specific GPO
$dontDisplayLastSignedInPolicyNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name=""Interactive logon: Don't display last signed-in""]", $nsManager)

# Desired setting
$desiredSetting = "true"

# Check and compare the current setting
if ($null -ne $dontDisplayLastSignedInPolicyNode) {
    # Navigate to the setting node to find the DisplayBoolean value
    $currentSettingNode = $dontDisplayLastSignedInPolicyNode.SelectSingleNode("sec:DisplayBoolean", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = $currentSettingNode.InnerText.Trim()
        if ($currentSetting -eq $desiredSetting) {
            Write-Host "PASSED: 'Interactive logon: Don't display last signed-in' is set to 'Enabled'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Interactive logon: Don't display last signed-in' is not set correctly. Current setting: '$currentSetting'. Set it to 'Enabled'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Interactive logon: Don't display last signed-in' current setting not found. Set it to 'Enabled'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Interactive logon: Don't display last signed-in' policy not found. Set it to 'Enabled'!" -ForegroundColor Red
}


# XPath to find the 'Interactive logon: Machine account lockout threshold' policy within the specific GPO
$machineAccountLockoutThresholdNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Interactive logon: Machine account lockout threshold']", $nsManager)

# Check and compare the current setting
if ($null -ne $machineAccountLockoutThresholdNode) {
    # Navigate to the setting node to find the SettingNumber value
    $currentSettingNode = $machineAccountLockoutThresholdNode.SelectSingleNode("sec:DisplayNumber", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = [int]$currentSettingNode.InnerText.Trim()
        if ($currentSetting -gt 0 -and $currentSetting -le 10) {
            Write-Host "PASSED: 'Interactive logon: Machine account lockout threshold' is set to '10 or fewer invalid logon attempts, but not 0'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Interactive logon: Machine account lockout threshold' is not set correctly. Current setting: '$currentSetting'. Set it to '10 or fewer invalid logon attempts, but not 0'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Interactive logon: Machine account lockout threshold' current setting not found. Set it to '10 or fewer invalid logon attempts, but not 0'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Interactive logon: Machine account lockout threshold' policy not found. Set it to '10 or fewer invalid logon attempts, but not 0'!" -ForegroundColor Red
}


# XPath to find the 'Interactive logon: Machine inactivity limit' policy within the specific GPO
$machineInactivityLimitNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Interactive logon: Machine inactivity limit']", $nsManager)

# Desired maximum setting
$desiredMaxSetting = 900

# Check and compare the current setting
if ($null -ne $machineInactivityLimitNode) {
    # Navigate to the setting node to find the DisplayNumber value
    $currentSettingNode = $machineInactivityLimitNode.SelectSingleNode("sec:DisplayNumber", $nsManager)
    if ($null -ne $currentSettingNode) {
        $currentSetting = [int]$currentSettingNode.InnerText.Trim()
        if ($currentSetting -gt 0 -and $currentSetting -le $desiredMaxSetting) {
            Write-Host "PASSED: 'Interactive logon: Machine inactivity limit' is set to '900 or fewer seconds, but not 0'." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Interactive logon: Machine inactivity limit' is not set correctly. Current setting: '$currentSetting'. Set it to '900 or fewer seconds, but not 0'!" -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Interactive logon: Machine inactivity limit' current setting not found. Set it to '900 or fewer seconds, but not 0'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Interactive logon: Machine inactivity limit' policy not found. Set it to '900 or fewer seconds, but not 0'!" -ForegroundColor Red
}


# XPath to find the 'Interactive logon: Message text for users attempting to log on' policy within the specific GPO
$messageTextNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Interactive logon: Message text for users attempting to log on']", $nsManager)

# Check and compare the current setting
if ($null -ne $messageTextNode) {
    # Navigate to the setting node to find the SettingStrings value
    $settingStringsNode = $messageTextNode.SelectSingleNode("../sec:SettingStrings/sec:Value", $nsManager)
    if ($null -ne $settingStringsNode) {
        $currentSetting = $settingStringsNode.InnerText.Trim()
        if ($currentSetting -ne "") {
            Write-Host "PASSED: 'Interactive logon: Message text for users attempting to log on' is set to a non-empty value." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Interactive logon: Message text for users attempting to log on' is not set. The message text is empty. Please set it to a desired message." -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Interactive logon: Message text for users attempting to log on' current setting not found. Please set it to a desired message." -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Interactive logon: Message text for users attempting to log on' policy not found. Please set it to a desired message." -ForegroundColor Red
}


# XPath to find the 'Interactive logon: Message title for users attempting to log on' policy within the specific GPO
$messageTitleNode = $xmlData.SelectSingleNode("//sec:Display[sec:Name='Interactive logon: Message title for users attempting to log on']", $nsManager)

# Check and compare the current setting
if ($null -ne $messageTitleNode) {
    # Navigate to the setting node to find the DisplayString value
    $settingStringNode = $messageTitleNode.SelectSingleNode("../sec:SettingString", $nsManager)
    if ($null -ne $settingStringNode) {
        $currentSetting = $settingStringNode.InnerText.Trim()
        if ($currentSetting -ne "") {
            Write-Host "PASSED: 'Interactive logon: Message title for users attempting to log on' is set to a non-empty value." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Interactive logon: Message title for users attempting to log on' is not set. The message title is empty. Please set it to a desired title." -ForegroundColor Red
        }
    } else {
        Write-Host "FAILED: 'Interactive logon: Message title for users attempting to log on' current setting not found. Please set it to a desired title." -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Interactive logon: Message title for users attempting to log on' policy not found. Please set it to a desired title." -ForegroundColor Red
}