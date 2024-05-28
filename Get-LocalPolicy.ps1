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


# XPath to find the 'Access Credential Manager as a trusted caller' policy within the specific GPO
$trustedCallerPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeTrustedCredManAccessPrivilege']", $nsManager)

if ($null -ne $trustedCallerPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $trustedCallerPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    if ($currentAccounts.Count -eq 0) {
        Write-Host "PASSED: The policy 'Access Credential Manager as a trusted caller' is set to 'No One'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: The policy 'Access Credential Manager as a trusted caller' is not set to 'No One'. Current settings: $($currentAccounts -join ', ')" -ForegroundColor Red
    }
} else {
    Write-Host "PASSED: The policy 'Access Credential Manager as a trusted caller' is set to 'No One'." -ForegroundColor Blue
}


# XPath to find the 'Access this computer from the network' policy within the specific GPO
$accessPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeNetworkLogonRight']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "BUILTIN\Remote Desktop Users")

if ($null -ne $accessPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $accessPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $difference = Compare-Object -ReferenceObject $desiredAccounts -DifferenceObject $currentAccounts -IncludeEqual -ExcludeDifferent

    if ($difference.Count -eq $desiredAccounts.Count) {
        Write-Host "PASSED: 'Access this computer from the network' is set to 'Administrators, Remote Desktop Users'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Access this computer from the network' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, Remote Desktop Users'" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Access this computer from the network' policy not found. Set it to 'Administrators, Remote Desktop Users'" -ForegroundColor Red
}


# XPath to find the 'Act as part of the operating system' policy within the specific GPO
$actAsPartPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeTcbPrivilege']", $nsManager)

if ($null -ne $actAsPartPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $actAsPartPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    if ($currentAccounts.Count -eq 0) {
        Write-Host "PASSED: 'Act as part of the operating system' is set to 'No One'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Act as part of the operating system' is not set to 'No One'. Current settings: $($currentAccounts -join ', ')" -ForegroundColor Red
    }
} else {
    Write-Host "PASSED: 'Act as part of the operating system' is set to 'No One'." -ForegroundColor Blue
}


# XPath to find the 'Adjust memory quotas for a process' policy within the specific GPO
$memoryQuotaPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeIncreaseQuotaPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "NT AUTHORITY\LOCAL SERVICE", "NT AUTHORITY\NETWORK SERVICE")

if ($null -ne $memoryQuotaPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $memoryQuotaPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $difference = Compare-Object -ReferenceObject $desiredAccounts -DifferenceObject $currentAccounts -IncludeEqual -ExcludeDifferent

    if ($difference.Count -eq $desiredAccounts.Count) {
        Write-Host "PASSED: 'Adjust memory quotas for a process' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Adjust memory quotas for a process' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Adjust memory quotas for a process' policy not found. Set it to 'Administrators, LOCAL SERVICE, NETWORK SERVICE'!" -ForegroundColor Red
}


# XPath to find the 'Allow log on locally' policy within the specific GPO
$logonPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeInteractiveLogonRight']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "BUILTIN\Users")

if ($null -ne $logonPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $logonPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $difference = Compare-Object -ReferenceObject $desiredAccounts -DifferenceObject $currentAccounts -IncludeEqual -ExcludeDifferent

    if ($difference.Count -eq $desiredAccounts.Count) {
        Write-Host "PASSED: 'Allow log on locally' is set to 'Administrators, Users'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Allow log on locally' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, Users'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Allow log on locally' policy not found. Set it to 'Administrators, Users'!" -ForegroundColor Red
}


# XPath to find the 'Allow log on through Remote Desktop Services' policy within the specific GPO
$rdpPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeRemoteInteractiveLogonRight']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "BUILTIN\Remote Desktop Users")

if ($null -ne $rdpPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $rdpPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $difference = Compare-Object -ReferenceObject $desiredAccounts -DifferenceObject $currentAccounts -IncludeEqual -ExcludeDifferent

    if ($difference.Count -eq $desiredAccounts.Count) {
        Write-Host "PASSED: 'Allow log on through Remote Desktop Services' is set to 'Administrators, Remote Desktop Users'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Allow log on through Remote Desktop Services' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, Remote Desktop Users'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Allow log on through Remote Desktop Services' policy not found. Set it to 'Administrators, Remote Desktop Users'!" -ForegroundColor Red
}


# XPath to find the 'Back up files and directories' policy within the specific GPO
$backupPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeBackupPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $backupPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $backupPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Back up files and directories' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Back up files and directories' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Back up files and directories' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Change the system time' policy within the specific GPO
$changeTimePolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeSystemTimePrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "NT AUTHORITY\LOCAL SERVICE")

if ($null -ne $changeTimePolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $changeTimePolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Change the system time' is set to 'Administrators, LOCAL SERVICE'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Change the system time' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, LOCAL SERVICE'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Change the system time' policy not found. Set it to 'Administrators, LOCAL SERVICE'!" -ForegroundColor Red
}


# XPath to find the 'Change the time zone' policy within the specific GPO
$changeTimeZonePolicy = $xmlData.SelectSingleNode("//sec:UserRightsAssignment[sec:Name='SeTimeZonePrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "NT AUTHORITY\LOCAL SERVICE", "BUILTIN\Users")

if ($null -ne $changeTimeZonePolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $changeTimeZonePolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Change the time zone' is set to 'Administrators, LOCAL SERVICE, Users'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Change the time zone' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, LOCAL SERVICE, Users'" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Change the time zone' policy not found. Set it to 'Administrators, LOCAL SERVICE, Users'!" -ForegroundColor Red
}


# XPath to find the 'Create a pagefile' policy within the specific GPO
$pagefilePolicy = $xmlData.SelectSingleNode("//sec:UserRightsAssignment[sec:Name='SeCreatePagefilePrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $pagefilePolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $pagefilePolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Create a pagefile' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Create a pagefile' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Create a pagefile' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Create a token object' policy within the specific GPO
$tokenPolicy = $xmlData.SelectSingleNode("//sec:UserRightsAssignment[sec:Name='SeCreateTokenPrivilege']", $nsManager)

if ($null -ne $tokenPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $tokenPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    if ($currentAccounts.Count -eq 0) {
        Write-Host "PASSED: 'Create a token object' is set to 'No One'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Create a token object' is not set to 'No One'. Current settings: $($currentAccounts -join ', ')" -ForegroundColor Red
    }
} else {
    Write-Host "PASSED: 'Create a token object' policy not found, implying it is set to 'No One'." -ForegroundColor Blue
}


# XPath to find the 'Create global objects' policy within the specific GPO
$globalObjectsPolicy = $xmlData.SelectSingleNode("//sec:UserRightsAssignment[sec:Name='SeCreateGlobalPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "NT AUTHORITY\LOCAL SERVICE", "NT AUTHORITY\NETWORK SERVICE", "NT AUTHORITY\SERVICE")

if ($null -ne $globalObjectsPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $globalObjectsPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $difference = Compare-Object -ReferenceObject $desiredAccounts -DifferenceObject $currentAccounts -IncludeEqual -ExcludeDifferent

    if ($difference.Count -eq $desiredAccounts.Count) {
        Write-Host "PASSED: 'Create global objects' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Create global objects' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Create global objects' policy not found. Set it to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'!" -ForegroundColor Red
}


# XPath to find the 'Create permanent shared objects' policy within the specific GPO
$sharedObjectsPolicy = $xmlData.SelectSingleNode("//sec:UserRightsAssignment[sec:Name='SeCreatePermanentPrivilege']", $nsManager)

if ($null -ne $sharedObjectsPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $sharedObjectsPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    if ($currentAccounts.Count -eq 0) {
        Write-Host "PASSED: 'Create permanent shared objects' is set to 'No One'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Create permanent shared objects' is not set to 'No One'. Current settings: $($currentAccounts -join ', ')" -ForegroundColor Red
    }
} else {
    Write-Host "PASSED: 'Create permanent shared objects' policy not found, which implies it is set to 'No One'." -ForegroundColor Blue
}


# XPath to find the 'Create symbolic links' policy within the specific GPO
$symbolicLinksPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeCreateSymbolicLinkPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")
$hyperVFeature = Get-WindowsFeature -Name Hyper-V

if ($hyperVFeature.Installed -eq $true) {
    $desiredAccounts += "NT VIRTUAL MACHINE\Virtual Machines"
}

if ($null -ne $symbolicLinksPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $symbolicLinksPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Create symbolic links' is set to 'Administrators'" -ForegroundColor Blue
        if ($desiredAccounts.Contains("NT VIRTUAL MACHINE\Virtual Machines")) {
            Write-Host ", NT VIRTUAL MACHINE\Virtual Machines" -ForegroundColor Blue
        }
    } else {
        Write-Host "FAILED: 'Create symbolic links' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators and also Virtual Machines if Hyper-v is installed" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Create symbolic links' policy not found. Set it to 'Administrators" -ForegroundColor Red
    if ($desiredAccounts.Contains("NT VIRTUAL MACHINE\Virtual Machines")) {
        Write-Host ", NT VIRTUAL MACHINE\Virtual Machines" -ForegroundColor Red
    }
    Write-Host "!"
}


# XPath to find the 'Debug programs' policy within the specific GPO
$debugProgramsPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeDebugPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $debugProgramsPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $debugProgramsPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Debug programs' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Debug programs' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Debug programs' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Deny access to this computer from the network' policy within the specific GPO
$denyNetworkAccessPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeDenyNetworkLogonRight']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Guests", "NT AUTHORITY\Local account")

if ($null -ne $denyNetworkAccessPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $denyNetworkAccessPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Deny access to this computer from the network' includes 'Guests, Local account'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Deny access to this computer from the network' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Guests, Local account'" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Deny access to this computer from the network' policy not found. Set it to 'Guests, Local account'!" -ForegroundColor Red
    Write-Host "The security identifier Local account is not available in Windows 7 and Windows 8.0 unless MSKB 2871997 has been installed." -ForegroundColor Yellow
}


# XPath to find the 'Deny log on as a batch job' policy within the specific GPO
$denyBatchJobPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeDenyBatchLogonRight']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Guests")

if ($null -ne $denyBatchJobPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $denyBatchJobPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Deny log on as a batch job' includes 'Guests'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Deny log on as a batch job' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Guests'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Deny log on as a batch job' policy not found. Set it to 'Guests'!" -ForegroundColor Red
}


# XPath to find the 'Deny log on as a service' policy within the specific GPO
$denyServicePolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeDenyServiceLogonRight']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Guests")

if ($null -ne $denyServicePolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $denyServicePolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Deny log on as a service' includes 'Guests'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Deny log on as a service' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Guests'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Deny log on as a service' policy not found. Set it to 'Guests'!" -ForegroundColor Red
}


# XPath to find the 'Deny log on locally' policy within the specific GPO
$denyLogonLocallyPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeDenyInteractiveLogonRight']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Guests")

if ($null -ne $denyLogonLocallyPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $denyLogonLocallyPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Deny log on locally' includes 'Guests'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Deny log on locally' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Guests'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Deny log on locally' policy not found. Set it to 'Guests'!" -ForegroundColor Red
}


# XPath to find the 'Deny log on through Remote Desktop Services' policy within the specific GPO
$denyRDPPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeDenyRemoteInteractiveLogonRight']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Guests", "BUILTIN\Local account")

if ($null -ne $denyRDPPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $denyRDPPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Deny log on through Remote Desktop Services' includes 'Guests, Local account'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Deny log on through Remote Desktop Services' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Guests, Local account'!" -ForegroundColor Red
        Write-Host "The security identifier Local account is not available in Windows 7 and Windows 8.0 unless MSKB 2871997 has been installed." -ForegroundColor Yellow
    }
} else {
    Write-Host "FAILED: 'Deny log on through Remote Desktop Services' policy not found. Set it to 'Guests, Local account'!" -ForegroundColor Red
    Write-Host "The security identifier Local account is not available in Windows 7 and Windows 8.0 unless MSKB 2871997 has been installed." -ForegroundColor Yellow
}


# XPath to find the 'Enable computer and user accounts to be trusted for delegation' policy within the specific GPO
$trustedForDelegationPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeEnableDelegationPrivilege']", $nsManager)

if ($null -ne $trustedForDelegationPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $trustedForDelegationPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    if ($currentAccounts.Count -eq 0) {
        Write-Host "PASSED: 'Enable computer and user accounts to be trusted for delegation' is set to 'No One'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Enable computer and user accounts to be trusted for delegation' is not set to 'No One'. Current settings: $($currentAccounts -join ', ')" -ForegroundColor Red
    }
} else {
    Write-Host "PASSED: 'Enable computer and user accounts to be trusted for delegation' policy not found, implying it is set to 'No One'." -ForegroundColor Blue
}


# XPath to find the 'Force shutdown from a remote system' policy within the specific GPO
$shutdownPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeRemoteShutdownPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $shutdownPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $shutdownPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Force shutdown from a remote system' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Force shutdown from a remote system' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Force shutdown from a remote system' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Generate security audits' policy within the specific GPO
$auditPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeAuditPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("NT AUTHORITY\LOCAL SERVICE", "NT AUTHORITY\NETWORK SERVICE")

if ($null -ne $auditPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $auditPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Generate security audits' is set to 'LOCAL SERVICE, NETWORK SERVICE'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Generate security audits' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'LOCAL SERVICE, NETWORK SERVICE'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Generate security audits' policy not found. Set it to 'LOCAL SERVICE, NETWORK SERVICE'!" -ForegroundColor Red
}


# XPath to find the 'Impersonate a client after authentication' policy within the specific GPO
$impersonatePolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeImpersonatePrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "NT AUTHORITY\LOCAL SERVICE", "NT AUTHORITY\NETWORK SERVICE", "NT AUTHORITY\SERVICE")

if ($null -ne $impersonatePolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $impersonatePolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Impersonate a client after authentication' is set to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Impersonate a client after authentication' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Impersonate a client after authentication' policy not found. Set it to 'Administrators, LOCAL SERVICE, NETWORK SERVICE, SERVICE'!" -ForegroundColor Red
}


# XPath to find the 'Increase scheduling priority' policy within the specific GPO
$schedulingPriorityPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeIncreaseBasePriorityPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "Window Manager\Window Manager Group")

if ($null -ne $schedulingPriorityPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $schedulingPriorityPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Increase scheduling priority' is set to 'Administrators, Window Manager\Window Manager Group'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Increase scheduling priority' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, Window Manager\Window Manager Group'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Increase scheduling priority' policy not found. Set it to 'Administrators, Window Manager\Window Manager Group'!" -ForegroundColor Red
}


# XPath to find the 'Load and unload device drivers' policy within the specific GPO
$deviceDriversPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeLoadDriverPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $deviceDriversPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $deviceDriversPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Load and unload device drivers' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Load and unload device drivers' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Load and unload device drivers' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Lock pages in memory' policy within the specific GPO
$lockPagesPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeLockMemoryPrivilege']", $nsManager)

if ($null -ne $lockPagesPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $lockPagesPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    if ($currentAccounts.Count -eq 0) {
        Write-Host "PASSED: 'Lock pages in memory' is set to 'No One'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Lock pages in memory' is not set to 'No One'. Current settings: $($currentAccounts -join ', '). Set it to 'No One'!" -ForegroundColor Red
    }
} else {
    Write-Host "PASSED: 'Lock pages in memory' policy not found, which implies it is set to 'No One'." -ForegroundColor Blue
}


# XPath to find the 'Log on as a batch job' policy within the specific GPO
$batchJobPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeBatchLogonRight']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $batchJobPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $batchJobPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Log on as a batch job' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Log on as a batch job' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Log on as a batch job' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Log on as a service' policy within the specific GPO
$serviceLogonPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeServiceLogonRight']", $nsManager)

# Define desired accounts based on the conditions
$desiredAccounts = @()
if ((Get-WindowsFeature -Name Hyper-V).Installed -eq $true) {
    $desiredAccounts += "NT VIRTUAL MACHINE\Virtual Machines"
}

if ($null -ne $serviceLogonPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $serviceLogonPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    if ($desiredAccounts.Count -eq 0 -and $currentAccounts.Count -eq 0) {
        Write-Host "PASSED: 'Log on as a service' is set to 'No One'." -ForegroundColor Blue
    } else {
        # Compare current settings with desired settings
        $isCorrect = $true
        foreach ($account in $desiredAccounts) {
            if ($currentAccounts -notcontains $account) {
                $isCorrect = $false
                break
            }
        }
        foreach ($account in $currentAccounts) {
            if ($desiredAccounts -notcontains $account) {
                $isCorrect = $false
                break
            }
        }

        if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
            Write-Host "PASSED: 'Log on as a service' is set to $($desiredAccounts -join ', ')." -ForegroundColor Blue
        } else {
            Write-Host "FAILED: 'Log on as a service' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to $($desiredAccounts -join ', ') or 'No One' if Hyper-V is not used!" -ForegroundColor Red
        }
    }
} else {
    Write-Host "NEUTRAL: 'Log on as a service' policy not found. Set it to 'Virtual Machines' if Hyper-V is installed! If Hyper-V isn't installed, leave it as it is." -ForegroundColor Yellow
}


# XPath to find the 'Manage auditing and security log' policy within the specific GPO
$auditLogPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeSecurityPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $auditLogPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $auditLogPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Manage auditing and security log' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Manage auditing and security log' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Manage auditing and security log' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Modify an object label' policy within the specific GPO
$modifyObjectLabelPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeRelabelPrivilege']", $nsManager)

if ($null -ne $modifyObjectLabelPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $modifyObjectLabelPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    if ($currentAccounts.Count -eq 0) {
        Write-Host "PASSED: 'Modify an object label' is set to 'No One'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Modify an object label' is not set to 'No One'. Current settings: $($currentAccounts -join ', '). Set it to 'No One'!" -ForegroundColor Red
    }
} else {
    Write-Host "PASSED: 'Modify an object label' policy not found, which implies it is set to 'No One'." -ForegroundColor Blue
}


# XPath to find the 'Modify firmware environment values' policy within the specific GPO
$firmwarePolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeSystemEnvironmentPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $firmwarePolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $firmwarePolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Modify firmware environment values' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Modify firmware environment values' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Modify firmware environment values' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Perform volume maintenance tasks' policy within the specific GPO
$volumeMaintenancePolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeManageVolumePrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $volumeMaintenancePolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $volumeMaintenancePolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Perform volume maintenance tasks' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Perform volume maintenance tasks' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Perform volume maintenance tasks' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Profile single process' policy within the specific GPO
$profileSingleProcessPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeProfileSingleProcessPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $profileSingleProcessPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $profileSingleProcessPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Profile single process' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Profile single process' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Profile single process' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Profile system performance' policy within the specific GPO
$profileSystemPerformancePolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeSystemProfilePrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "NT SERVICE\WdiServiceHost")

if ($null -ne $profileSystemPerformancePolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $profileSystemPerformancePolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Profile system performance' is set to 'Administrators, NT SERVICE\WdiServiceHost'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Profile system performance' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, NT SERVICE\WdiServiceHost'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Profile system performance' policy not found. Set it to 'Administrators, NT SERVICE\WdiServiceHost'!" -ForegroundColor Red
}


# XPath to find the 'Replace a process level token' policy within the specific GPO
$replaceTokenPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeAssignPrimaryTokenPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("NT AUTHORITY\LOCAL SERVICE", "NT AUTHORITY\NETWORK SERVICE")

if ($null -ne $replaceTokenPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $replaceTokenPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Replace a process level token' is set to 'LOCAL SERVICE, NETWORK SERVICE'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Replace a process level token' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'LOCAL SERVICE, NETWORK SERVICE'!" -ForegroundColor Red
        Write-Host "On most computers, this is the default configuration and there will be no negative impact. However, if you have installed Web Server (IIS), you will need to allow the IIS application pool(s) to be granted this User Right Assignment." -ForegroundColor Yellow
    }
} else {
    Write-Host "FAILED: 'Replace a process level token' policy not found. Set it to 'LOCAL SERVICE, NETWORK SERVICE'!" -ForegroundColor Red  
}


# XPath to find the 'Restore files and directories' policy within the specific GPO
$restoreFilesPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeRestorePrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $restoreFilesPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $restoreFilesPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Restore files and directories' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Restore files and directories' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Restore files and directories' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}


# XPath to find the 'Shut down the system' policy within the specific GPO
$shutdownPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeShutdownPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators", "BUILTIN\Users")

if ($null -ne $shutdownPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $shutdownPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Shut down the system' is set to 'Administrators, Users'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Shut down the system' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators, Users'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Shut down the system' policy not found. Set it to 'Administrators, Users'!" -ForegroundColor Red
}


# XPath to find the 'Take ownership of files or other objects' policy within the specific GPO
$takeOwnershipPolicy = $xmlData.SelectSingleNode("//gp:GPO/gp:Computer/gp:ExtensionData/gp:Extension/sec:UserRightsAssignment[sec:Name='SeTakeOwnershipPrivilege']", $nsManager)

# Desired accounts
$desiredAccounts = @("BUILTIN\Administrators")

if ($null -ne $takeOwnershipPolicy) {
    # Extract current accounts assigned to the policy
    $currentAccounts = $takeOwnershipPolicy.SelectNodes("sec:Member/types:Name", $nsManager) | ForEach-Object { $_.InnerText.Trim() }

    # Compare current settings with desired settings
    $isCorrect = $true
    foreach ($account in $desiredAccounts) {
        if ($currentAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }
    foreach ($account in $currentAccounts) {
        if ($desiredAccounts -notcontains $account) {
            $isCorrect = $false
            break
        }
    }

    if ($isCorrect -and ($currentAccounts.Count -eq $desiredAccounts.Count)) {
        Write-Host "PASSED: 'Take ownership of files or other objects' is set to 'Administrators'." -ForegroundColor Blue
    } else {
        Write-Host "FAILED: 'Take ownership of files or other objects' is not set correctly. Current settings: $($currentAccounts -join ', '). Set it to 'Administrators'!" -ForegroundColor Red
    }
} else {
    Write-Host "FAILED: 'Take ownership of files or other objects' policy not found. Set it to 'Administrators'!" -ForegroundColor Red
}