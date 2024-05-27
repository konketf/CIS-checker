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