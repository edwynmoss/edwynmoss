# Advanced Security Automation Script
# Author: Edwyn Moss
# Description: Comprehensive Windows security assessment and automation tool

param(
    [string]$ComputerName = $env:COMPUTERNAME,
    [switch]$FullScan,
    [switch]$QuickScan,
    [string]$OutputPath = ".\SecurityReport.html",
    [switch]$ExportJSON,
    [switch]$EmailReport,
    [string]$SMTPServer,
    [string]$EmailTo
)

# Initialize variables
$ErrorActionPreference = "Continue"
$VerbosePreference = "Continue"
$WarningPreference = "Continue"

# Security assessment results
$SecurityResults = @{
    ComputerInfo = @{}
    SecurityPolicies = @{}
    Services = @()
    Updates = @()
    Firewall = @{}
    AntiVirus = @{}
    UserAccounts = @()
    NetworkShares = @()
    Vulnerabilities = @()
    Recommendations = @()
}

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    
    $originalColor = $Host.UI.RawUI.ForegroundColor
    $Host.UI.RawUI.ForegroundColor = $Color
    Write-Output $Message
    $Host.UI.RawUI.ForegroundColor = $originalColor
}

function Get-SystemInformation {
    Write-ColorOutput "Gathering system information..." "Green"
    
    try {
        $computerInfo = Get-ComputerInfo
        $SecurityResults.ComputerInfo = @{
            ComputerName = $computerInfo.CsName
            Domain = $computerInfo.CsDomain
            Manufacturer = $computerInfo.CsManufacturer
            Model = $computerInfo.CsModel
            TotalPhysicalMemory = [math]::Round($computerInfo.CsTotalPhysicalMemory / 1GB, 2)
            OSName = $computerInfo.OsName
            OSVersion = $computerInfo.OsVersion
            OSArchitecture = $computerInfo.OsArchitecture
            LastBootUpTime = $computerInfo.OsLastBootUpTime
            InstallDate = $computerInfo.OsInstallDate
            WindowsDirectory = $computerInfo.OsWindowsDirectory
            SystemDirectory = $computerInfo.OsSystemDirectory
        }
        
        Write-ColorOutput "✓ System information collected" "Green"
    }
    catch {
        Write-ColorOutput "✗ Failed to collect system information: $($_.Exception.Message)" "Red"
    }
}

function Test-SecurityPolicies {
    Write-ColorOutput "Analyzing security policies..." "Green"
    
    try {
        # Password policy
        $passwordPolicy = net accounts 2>$null | Where-Object { $_ -match ":" }
        $SecurityResults.SecurityPolicies.PasswordPolicy = $passwordPolicy
        
        # Local security policy
        $securityPolicy = @{}
        $localPolicies = @(
            "PasswordComplexity",
            "MinimumPasswordLength",
            "MaximumPasswordAge",
            "MinimumPasswordAge",
            "PasswordHistorySize",
            "LockoutDuration",
            "LockoutThreshold",
            "ResetLockoutCounterAfter"
        )
        
        foreach ($policy in $localPolicies) {
            try {
                $value = (Get-ItemProperty -Path "HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters" -Name $policy -ErrorAction SilentlyContinue).$policy
                $securityPolicy[$policy] = $value
            }
            catch {
                $securityPolicy[$policy] = "Not configured"
            }
        }
        
        $SecurityResults.SecurityPolicies.LocalPolicies = $securityPolicy
        Write-ColorOutput "✓ Security policies analyzed" "Green"
    }
    catch {
        Write-ColorOutput "✗ Failed to analyze security policies: $($_.Exception.Message)" "Red"
    }
}

function Get-ServiceStatus {
    Write-ColorOutput "Checking critical services..." "Green"
    
    try {
        $criticalServices = @(
            "Winlogon", "BITS", "Eventlog", "MpsSvc", "WinDefend", 
            "wscsvc", "WinRM", "TermService", "Spooler", "W32Time"
        )
        
        foreach ($serviceName in $criticalServices) {
            $service = Get-Service -Name $serviceName -ErrorAction SilentlyContinue
            if ($service) {
                $SecurityResults.Services += @{
                    Name = $service.Name
                    DisplayName = $service.DisplayName
                    Status = $service.Status
                    StartType = $service.StartType
                    CanStop = $service.CanStop
                    CanPauseAndContinue = $service.CanPauseAndContinue
                }
                
                # Check for suspicious services
                if ($service.Status -eq "Stopped" -and $service.Name -in @("WinDefend", "wscsvc", "MpsSvc")) {
                    $SecurityResults.Vulnerabilities += "Critical security service '$($service.DisplayName)' is stopped"
                }
            }
        }
        
        Write-ColorOutput "✓ Service status checked" "Green"
    }
    catch {
        Write-ColorOutput "✗ Failed to check services: $($_.Exception.Message)" "Red"
    }
}

function Test-WindowsUpdates {
    Write-ColorOutput "Checking Windows Updates..." "Green"
    
    try {
        if (Get-Module -ListAvailable -Name PSWindowsUpdate) {
            Import-Module PSWindowsUpdate
            $updates = Get-WUList -MicrosoftUpdate
            
            foreach ($update in $updates) {
                $SecurityResults.Updates += @{
                    Title = $update.Title
                    Size = $update.Size
                    Description = $update.Description
                    IsDownloaded = $update.IsDownloaded
                    IsInstalled = $update.IsInstalled
                    IsMandatory = $update.IsMandatory
                }
            }
            
            if ($updates.Count -gt 0) {
                $SecurityResults.Vulnerabilities += "$($updates.Count) pending Windows updates found"
            }
        }
        else {
            Write-ColorOutput "⚠ PSWindowsUpdate module not available. Install with: Install-Module PSWindowsUpdate" "Yellow"
        }
        
        Write-ColorOutput "✓ Windows Updates checked" "Green"
    }
    catch {
        Write-ColorOutput "✗ Failed to check Windows Updates: $($_.Exception.Message)" "Red"
    }
}

function Test-FirewallStatus {
    Write-ColorOutput "Analyzing Windows Firewall..." "Green"
    
    try {
        $firewallProfiles = Get-NetFirewallProfile
        
        foreach ($profile in $firewallProfiles) {
            $SecurityResults.Firewall[$profile.Name] = @{
                Enabled = $profile.Enabled
                DefaultInboundAction = $profile.DefaultInboundAction
                DefaultOutboundAction = $profile.DefaultOutboundAction
                AllowInboundRules = $profile.AllowInboundRules
                AllowLocalFirewallRules = $profile.AllowLocalFirewallRules
                AllowLocalIPsecRules = $profile.AllowLocalIPsecRules
                AllowUserApps = $profile.AllowUserApps
                AllowUserPorts = $profile.AllowUserPorts
                AllowUnicastResponseToMulticast = $profile.AllowUnicastResponseToMulticast
                NotifyOnListen = $profile.NotifyOnListen
                EnableStealthModeForIPsec = $profile.EnableStealthModeForIPsec
                LogAllowed = $profile.LogAllowed
                LogBlocked = $profile.LogBlocked
                LogIgnored = $profile.LogIgnored
                LogMaxSizeKilobytes = $profile.LogMaxSizeKilobytes
            }
            
            if (-not $profile.Enabled) {
                $SecurityResults.Vulnerabilities += "Windows Firewall is disabled for $($profile.Name) profile"
            }
        }
        
        Write-ColorOutput "✓ Firewall status analyzed" "Green"
    }
    catch {
        Write-ColorOutput "✗ Failed to analyze firewall: $($_.Exception.Message)" "Red"
    }
}

function Test-AntiVirusStatus {
    Write-ColorOutput "Checking antivirus status..." "Green"
    
    try {
        # Windows Defender status
        $defenderStatus = Get-MpComputerStatus -ErrorAction SilentlyContinue
        if ($defenderStatus) {
            $SecurityResults.AntiVirus.WindowsDefender = @{
                AntivirusEnabled = $defenderStatus.AntivirusEnabled
                AMServiceEnabled = $defenderStatus.AMServiceEnabled
                AntiSpywareEnabled = $defenderStatus.AntiSpywareEnabled
                BehaviorMonitorEnabled = $defenderStatus.BehaviorMonitorEnabled
                IoavProtectionEnabled = $defenderStatus.IoavProtectionEnabled
                NISEnabled = $defenderStatus.NISEnabled
                OnAccessProtectionEnabled = $defenderStatus.OnAccessProtectionEnabled
                RealTimeProtectionEnabled = $defenderStatus.RealTimeProtectionEnabled
                AntivirusSignatureLastUpdated = $defenderStatus.AntivirusSignatureLastUpdated
                AntiSpywareSignatureLastUpdated = $defenderStatus.AntiSpywareSignatureLastUpdated
                FullScanAge = $defenderStatus.FullScanAge
                QuickScanAge = $defenderStatus.QuickScanAge
            }
            
            if (-not $defenderStatus.RealTimeProtectionEnabled) {
                $SecurityResults.Vulnerabilities += "Windows Defender Real-time protection is disabled"
            }
            
            if ($defenderStatus.AntivirusSignatureLastUpdated -lt (Get-Date).AddDays(-7)) {
                $SecurityResults.Vulnerabilities += "Antivirus signatures are older than 7 days"
            }
        }
        
        # Check for other antivirus products
        $antivirusProducts = Get-WmiObject -Namespace "root\SecurityCenter2" -Class AntiVirusProduct -ErrorAction SilentlyContinue
        if ($antivirusProducts) {
            $SecurityResults.AntiVirus.InstalledProducts = @()
            foreach ($av in $antivirusProducts) {
                $SecurityResults.AntiVirus.InstalledProducts += @{
                    DisplayName = $av.displayName
                    InstanceGuid = $av.instanceGuid
                    PathToSignedProductExe = $av.pathToSignedProductExe
                    PathToSignedReportingExe = $av.pathToSignedReportingExe
                    ProductState = $av.productState
                }
            }
        }
        
        Write-ColorOutput "✓ Antivirus status checked" "Green"
    }
    catch {
        Write-ColorOutput "✗ Failed to check antivirus status: $($_.Exception.Message)" "Red"
    }
}

function Get-UserAccountSecurity {
    Write-ColorOutput "Analyzing user accounts..." "Green"
    
    try {
        $users = Get-LocalUser
        
        foreach ($user in $users) {
            $SecurityResults.UserAccounts += @{
                Name = $user.Name
                Enabled = $user.Enabled
                AccountExpires = $user.AccountExpires
                Description = $user.Description
                FullName = $user.FullName
                LastLogon = $user.LastLogon
                PasswordChangeableDate = $user.PasswordChangeableDate
                PasswordExpires = $user.PasswordExpires
                PasswordLastSet = $user.PasswordLastSet
                PasswordRequired = $user.PasswordRequired
                UserMayChangePassword = $user.UserMayChangePassword
                PrincipalSource = $user.PrincipalSource
            }
            
            # Check for security issues
            if ($user.Enabled -and -not $user.PasswordRequired) {
                $SecurityResults.Vulnerabilities += "User '$($user.Name)' is enabled but has no password requirement"
            }
            
            if ($user.Enabled -and $user.PasswordLastSet -lt (Get-Date).AddDays(-90)) {
                $SecurityResults.Vulnerabilities += "User '$($user.Name)' password is older than 90 days"
            }
        }
        
        # Check for administrative users
        $adminGroup = Get-LocalGroupMember -Group "Administrators" -ErrorAction SilentlyContinue
        if ($adminGroup) {
            $adminCount = ($adminGroup | Where-Object { $_.ObjectClass -eq "User" }).Count
            if ($adminCount -gt 2) {
                $SecurityResults.Vulnerabilities += "$adminCount users have administrative privileges (consider reducing)"
            }
        }
        
        Write-ColorOutput "✓ User accounts analyzed" "Green"
    }
    catch {
        Write-ColorOutput "✗ Failed to analyze user accounts: $($_.Exception.Message)" "Red"
    }
}

function Get-NetworkShares {
    Write-ColorOutput "Checking network shares..." "Green"
    
    try {
        $shares = Get-SmbShare
        
        foreach ($share in $shares) {
            $SecurityResults.NetworkShares += @{
                Name = $share.Name
                Path = $share.Path
                Description = $share.Description
                ShareType = $share.ShareType
                ShareState = $share.ShareState
                Availability = $share.Availability
                CachingMode = $share.CachingMode
                ContinuouslyAvailable = $share.ContinuouslyAvailable
            }
            
            # Check for security issues
            if ($share.Name -like "*$" -and $share.ShareType -eq "FileSystemDriver") {
                # This is expected for administrative shares
            }
            elseif ($share.ShareType -eq "FileSystemDriver") {
                $permissions = Get-SmbShareAccess -Name $share.Name
                $everyoneAccess = $permissions | Where-Object { $_.AccountName -eq "Everyone" }
                if ($everyoneAccess) {
                    $SecurityResults.Vulnerabilities += "Share '$($share.Name)' has 'Everyone' permissions"
                }
            }
        }
        
        Write-ColorOutput "✓ Network shares checked" "Green"
    }
    catch {
        Write-ColorOutput "✗ Failed to check network shares: $($_.Exception.Message)" "Red"
    }
}

function Generate-Recommendations {
    Write-ColorOutput "Generating security recommendations..." "Green"
    
    $SecurityResults.Recommendations = @(
        "Enable Windows Defender Real-time Protection",
        "Keep Windows and antivirus signatures up to date",
        "Enable Windows Firewall on all profiles",
        "Use strong passwords and enable password complexity",
        "Limit administrative privileges to necessary users only",
        "Remove or secure unnecessary network shares",
        "Enable account lockout policies",
        "Regular security audits and vulnerability assessments",
        "Implement principle of least privilege",
        "Enable audit logging for security events",
        "Use Windows Update for Business or WSUS for update management",
        "Consider implementing BitLocker for disk encryption",
        "Enable User Account Control (UAC)",
        "Disable unnecessary services and features",
        "Implement network segmentation where possible"
    )
}

function Export-SecurityReport {
    param(
        [string]$Format = "HTML"
    )
    
    Write-ColorOutput "Generating security report..." "Green"
    
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    
    if ($Format -eq "HTML") {
        $html = @"
<!DOCTYPE html>
<html>
<head>
    <title>Security Assessment Report - $($SecurityResults.ComputerInfo.ComputerName)</title>
    <style>
        body { font-family: Arial, sans-serif; margin: 20px; }
        h1 { color: #2E8B57; }
        h2 { color: #4682B4; border-bottom: 2px solid #4682B4; }
        h3 { color: #CD853F; }
        .vulnerability { background-color: #FFE4E1; padding: 10px; margin: 5px 0; border-left: 4px solid #DC143C; }
        .recommendation { background-color: #F0F8FF; padding: 10px; margin: 5px 0; border-left: 4px solid #4682B4; }
        .info-table { border-collapse: collapse; width: 100%; }
        .info-table th, .info-table td { border: 1px solid #ddd; padding: 8px; text-align: left; }
        .info-table th { background-color: #f2f2f2; }
        .summary { background-color: #F5F5DC; padding: 15px; margin: 10px 0; border-radius: 5px; }
    </style>
</head>
<body>
    <h1>Security Assessment Report</h1>
    <div class="summary">
        <h3>Executive Summary</h3>
        <p><strong>Computer:</strong> $($SecurityResults.ComputerInfo.ComputerName)</p>
        <p><strong>Assessment Date:</strong> $timestamp</p>
        <p><strong>Vulnerabilities Found:</strong> $($SecurityResults.Vulnerabilities.Count)</p>
        <p><strong>OS:</strong> $($SecurityResults.ComputerInfo.OSName) $($SecurityResults.ComputerInfo.OSVersion)</p>
    </div>
    
    <h2>Vulnerabilities Identified</h2>
"@
        
        if ($SecurityResults.Vulnerabilities.Count -gt 0) {
            foreach ($vuln in $SecurityResults.Vulnerabilities) {
                $html += "<div class='vulnerability'>⚠️ $vuln</div>`n"
            }
        } else {
            $html += "<p style='color: green;'>✅ No critical vulnerabilities identified</p>`n"
        }
        
        $html += "`n<h2>Security Recommendations</h2>`n"
        foreach ($rec in $SecurityResults.Recommendations) {
            $html += "<div class='recommendation'>💡 $rec</div>`n"
        }
        
        $html += @"
    
    <h2>System Information</h2>
    <table class="info-table">
        <tr><th>Property</th><th>Value</th></tr>
        <tr><td>Computer Name</td><td>$($SecurityResults.ComputerInfo.ComputerName)</td></tr>
        <tr><td>Domain</td><td>$($SecurityResults.ComputerInfo.Domain)</td></tr>
        <tr><td>OS Name</td><td>$($SecurityResults.ComputerInfo.OSName)</td></tr>
        <tr><td>OS Version</td><td>$($SecurityResults.ComputerInfo.OSVersion)</td></tr>
        <tr><td>Architecture</td><td>$($SecurityResults.ComputerInfo.OSArchitecture)</td></tr>
        <tr><td>Total Memory (GB)</td><td>$($SecurityResults.ComputerInfo.TotalPhysicalMemory)</td></tr>
        <tr><td>Last Boot</td><td>$($SecurityResults.ComputerInfo.LastBootUpTime)</td></tr>
    </table>
    
    <h2>Service Status</h2>
    <table class="info-table">
        <tr><th>Service Name</th><th>Display Name</th><th>Status</th><th>Start Type</th></tr>
"@
        
        foreach ($service in $SecurityResults.Services) {
            $statusColor = if ($service.Status -eq "Running") { "green" } else { "red" }
            $html += "<tr><td>$($service.Name)</td><td>$($service.DisplayName)</td><td style='color: $statusColor'>$($service.Status)</td><td>$($service.StartType)</td></tr>`n"
        }
        
        $html += @"
    </table>
    
    <p><em>Report generated by Security Automation Script v1.0 - Author: Edwyn Moss</em></p>
    <p><em>Generated on: $timestamp</em></p>
</body>
</html>
"@
        
        $html | Out-File -FilePath $OutputPath -Encoding UTF8
        Write-ColorOutput "✅ HTML report saved to: $OutputPath" "Green"
    }
    
    if ($ExportJSON) {
        $jsonPath = $OutputPath -replace '\.html$', '.json'
        $SecurityResults | ConvertTo-Json -Depth 10 | Out-File -FilePath $jsonPath -Encoding UTF8
        Write-ColorOutput "✅ JSON report saved to: $jsonPath" "Green"
    }
}

function Send-EmailReport {
    param(
        [string]$SMTPServer,
        [string]$EmailTo,
        [string]$EmailFrom = "security@$($env:COMPUTERNAME).local",
        [string]$Subject = "Security Assessment Report - $($SecurityResults.ComputerInfo.ComputerName)"
    )
    
    if (-not $SMTPServer -or -not $EmailTo) {
        Write-ColorOutput "⚠ SMTP server and email recipient required for email functionality" "Yellow"
        return
    }
    
    try {
        $body = @"
Security Assessment Report

Computer: $($SecurityResults.ComputerInfo.ComputerName)
Assessment Date: $(Get-Date -Format "yyyy-MM-dd HH:mm:ss")
Vulnerabilities Found: $($SecurityResults.Vulnerabilities.Count)

This is an automated security assessment report. Please see the attached HTML report for detailed findings.

Generated by Security Automation Script v1.0
Author: Edwyn Moss
"@
        
        Send-MailMessage -SmtpServer $SMTPServer -To $EmailTo -From $EmailFrom -Subject $Subject -Body $body -Attachments $OutputPath
        Write-ColorOutput "✅ Email report sent to: $EmailTo" "Green"
    }
    catch {
        Write-ColorOutput "✗ Failed to send email: $($_.Exception.Message)" "Red"
    }
}

# Main execution
function Main {
    Write-ColorOutput "Security Automation Script v1.0" "Cyan"
    Write-ColorOutput "Author: Edwyn Moss" "Cyan"
    Write-ColorOutput "=" * 50 "Cyan"
    Write-ColorOutput "Target Computer: $ComputerName" "Yellow"
    Write-ColorOutput "Scan Type: $(if ($FullScan) { 'Full Scan' } else { 'Quick Scan' })" "Yellow"
    Write-ColorOutput "Output Path: $OutputPath" "Yellow"
    Write-ColorOutput "=" * 50 "Cyan"
    
    $startTime = Get-Date
    
    # Core assessments
    Get-SystemInformation
    Test-SecurityPolicies
    Get-ServiceStatus
    Test-FirewallStatus
    Test-AntiVirusStatus
    Get-UserAccountSecurity
    Get-NetworkShares
    
    # Full scan additional checks
    if ($FullScan) {
        Test-WindowsUpdates
    }
    
    Generate-Recommendations
    Export-SecurityReport -Format "HTML"
    
    if ($EmailReport) {
        Send-EmailReport -SMTPServer $SMTPServer -EmailTo $EmailTo
    }
    
    $endTime = Get-Date
    $duration = $endTime - $startTime
    
    Write-ColorOutput "=" * 50 "Cyan"
    Write-ColorOutput "Assessment completed in $($duration.TotalMinutes.ToString('F2')) minutes" "Green"
    Write-ColorOutput "Vulnerabilities found: $($SecurityResults.Vulnerabilities.Count)" $(if ($SecurityResults.Vulnerabilities.Count -eq 0) { "Green" } else { "Red" })
    Write-ColorOutput "Report saved to: $OutputPath" "Green"
    Write-ColorOutput "=" * 50 "Cyan"
}

# Execute main function
Main 