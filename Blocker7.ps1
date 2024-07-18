# Ensure the script is running with elevated privileges
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

if (-not (Test-Admin)) {
    Start-Process powershell "-File `"$PSCommandPath`"" -Verb RunAs
    exit
}

# Import System.Windows.Forms for file dialog and GUI
Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# Define the log file
$logFile = "$PSScriptRoot\FirewallRulesLog.txt"
$monitorLogFile = "$PSScriptRoot\FirewallMonitorLog.txt"

# Function to log messages
function Log-Message {
    param (
        [string]$message,
        [string]$level = "info"
    )
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    if ($LogLevel -eq "verbose" -or $level -eq "info") {
        Add-Content -Path $logFile -Value "$timestamp - $message"
    }
    if ($LogLevel -eq "verbose") {
        Write-Host "$timestamp - $message"
    }
}

# Backup existing firewall rules
function Backup-FirewallRules {
    $backupPath = "$PSScriptRoot\FirewallRulesBackup.wfw"
    netsh advfirewall export "$backupPath"
    Log-Message "Firewall rules backed up to $backupPath"
    Write-Host "Firewall rules backed up to $backupPath"
}

# Function to add firewall rules
function Add-FirewallRule {
    param (
        [string]$exePath,
        [string]$exeName
    )
    $ruleNameIn = "$RulePrefix $exeName in"
    $ruleNameOut = "$RulePrefix $exeName out"
    try {
        netsh advfirewall firewall add rule name=$ruleNameIn dir=in action=block program=$exePath enable=yes
        netsh advfirewall firewall add rule name="$ruleNameIn TCP" dir=in action=block program=$exePath protocol=TCP localport=any remoteport=any enable=yes
        netsh advfirewall firewall add rule name="$ruleNameIn UDP" dir=in action=block program=$exePath protocol=UDP localport=any remoteport=any enable=yes
        netsh advfirewall firewall add rule name=$ruleNameOut dir=out action=block program=$exePath enable=yes
        netsh advfirewall firewall add rule name="$ruleNameOut TCP" dir=out action=block program=$exePath protocol=TCP localport=any remoteport=any enable=yes
        netsh advfirewall firewall add rule name="$ruleNameOut UDP" dir=out action=block program=$exePath protocol=UDP localport=any remoteport=any enable=yes
        Log-Message "Successfully added rules for: $exeName"
    } catch {
        Log-Message "Failed to add rules for: $exeName - $_" "error"
    }
}

# Function to remove firewall rules
function Remove-FirewallRule {
    param (
        [string]$exeName
    )
    $ruleNameIn = "$RulePrefix $exeName in"
    $ruleNameOut = "$RulePrefix $exeName out"
    try {
        netsh advfirewall firewall delete rule name=$ruleNameIn
        netsh advfirewall firewall delete rule name="$ruleNameIn TCP"
        netsh advfirewall firewall delete rule name="$ruleNameIn UDP"
        netsh advfirewall firewall delete rule name=$ruleNameOut
        netsh advfirewall firewall delete rule name="$ruleNameOut TCP"
        netsh advfirewall firewall delete rule name="$ruleNameOut UDP"
        Log-Message "Successfully removed rules for: $exeName"
    } catch {
        Log-Message "Failed to remove rules for: $exeName - $_" "error"
    }
}

# Function to block Adobe domains and IPs
function Block-AdobeDomainsAndIPs {
    $adobeDomains = @(
        "adobe.com",
        "adobelogin.com",
        "adobeid-na1.services.adobe.com",
        "adobeid-na2.services.adobe.com",
        "lm.licenses.adobe.com",
        "na1r.services.adobe.com",
        "na2r.services.adobe.com",
        "cc-api-data.adobe.io",
        "na1r.services.adobe.com",
        "adobe.demdex.net",
        "assets.adobedtm.com",
        "adobeid.services.adobe.com",
        "ims-na1.adobelogin.com",
        "account.adobe.com",
        "entitlement.adobe.com",
        "ims-na1.adobelogin.com",
        "adobe-stg1.com",
        "adobe-stg2.com",
        "assets2.adobetm.com",
        "cc-api-data.adobe.io",
        "cdn.adobe.io",
        "creative.adobe.com",
        "exchange.adobe.com",
        "na1r.services.adobe.com",
        "outgoing.adobe.com",
        "packages.adobe.com",
        "prod-rel-ffc-cc-us-east-1-cc-us-east-1.adobe.io",
        "prod-rel-ffc-cc-us-east-1-cc-us-east-1.adobe.io",
        "status.adobe.com",
        "upload-prod.adobe.io",
        "users.services.adobe.com",
        "video.adobe.io",
        "cc-asset.adobe.io",
        "cc-api-storage.adobe.io",
        "creativecloud.adobe.com",
        "feedback.adobe.com",
        "fonts.adobe.com",
        "images.adobe.com",
        "learn.adobe.com",
        "my.adobe.io",
        "static.adobe.io",
        "training.adobe.com",
        "typekit.com",
        "use.typekit.net",
        "video.adobe.com"
    )
    foreach ($domain in $adobeDomains) {
        netsh advfirewall firewall add rule name="Block $domain" dir=out action=block remoteip=$domain enable=yes
        Log-Message "Blocked domain: $domain"
    }

    $adobeIPs = @(
        "192.147.130.0/24",
        "192.243.240.0/24",
        "192.243.248.0/24",
        "193.104.215.0/24",
        "203.81.19.0/24",
        "2606:2a00:1010::/48",
        "2606:2a00:1012::/48",
        "2606:2a00:1014::/48"
    )
    foreach ($ip in $adobeIPs) {
        netsh advfirewall firewall add rule name="Block $ip" dir=out action=block remoteip=$ip enable=yes
        Log-Message "Blocked IP range: $ip"
    }
}

# Function to get user confirmation
function Get-UserConfirmation {
    param (
        [string]$message
    )
    do {
        $response = Read-Host "$message (y/n)"
    } while ($response -ne 'y' -and $response -ne 'n')
    return $response -eq 'y'
}

# Function to schedule the script
function Schedule-Script {
    param (
        [string]$scriptPath,
        [datetime]$scheduleTime
    )
    $action = New-ScheduledTaskAction -Execute "powershell.exe" -Argument "-File `"$scriptPath`""
    $trigger = New-ScheduledTaskTrigger -Once -At $scheduleTime
    $principal = New-ScheduledTaskPrincipal -UserId "SYSTEM" -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -StartWhenAvailable
    Register-ScheduledTask -TaskName "BlockAdobeApps" -Action $action -Trigger $trigger -Principal $principal -Settings $settings
    Log-Message "Scheduled script to run at $scheduleTime"
    Write-Host "Scheduled script to run at $scheduleTime"
}

# Function to add entries to the hosts file
function Add-HostsFileEntry {
    param (
        [string[]]$entries
    )
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $tempHostsPath = "$env:SystemRoot\System32\drivers\etc\hosts.temp"

    # Read the current hosts file
    $hostsContent = Get-Content -Path $hostsPath -ErrorAction Stop

    # Create a backup of the current hosts file
    $hostsContent | Set-Content -Path $tempHostsPath -Force

    # Add new entries
    foreach ($entry in $entries) {
        if (-not ($hostsContent -match "127.0.0.1\s+$entry")) {
            Add-Content -Path $tempHostsPath -Value "127.0.0.1 $entry"
            Log-Message "Added $entry to hosts file"
            Write-Host "Added $entry to hosts file"
        } else {
            Log-Message "$entry already exists in hosts file"
            Write-Host "$entry already exists in hosts file"
        }
    }

    # Replace the original hosts file with the modified one
    Move-Item -Path $tempHostsPath -Destination $hostsPath -Force
}

# Function to remove entries from the hosts file
function Remove-HostsFileEntry {
    param (
        [string[]]$entries
    )
    $hostsPath = "$env:SystemRoot\System32\drivers\etc\hosts"
    $tempHostsPath = "$env:SystemRoot\System32\drivers\etc\hosts.temp"

    # Read the current hosts file
    $hostsContent = Get-Content -Path $hostsPath -ErrorAction Stop

    # Create a backup of the current hosts file
    $hostsContent | Set-Content -Path $tempHostsPath -Force

    # Remove entries
    foreach ($entry in $entries) {
        $hostsContent = $hostsContent -replace "127.0.0.1\s+$entry", ""
    }

    # Save the modified content to the temporary hosts file
    $hostsContent | Set-Content -Path $tempHostsPath -Force

    # Replace the original hosts file with the modified one
    Move-Item -Path $tempHostsPath -Destination $hostsPath -Force

    foreach ($entry in $entries) {
        Log-Message "Removed $entry from hosts file"
        Write-Host "Removed $entry from hosts file"
    }
}

# Function to block Adobe services by modifying the hosts file
function Block-AdobeHosts {
    $adobeDomains = @(
        "adobe.com",
        "adobelogin.com",
        "adobeid-na1.services.adobe.com",
        "adobeid-na2.services.adobe.com",
        "lm.licenses.adobe.com",
        "na1r.services.adobe.com",
        "na2r.services.adobe.com",
        "cc-api-data.adobe.io",
        "na1r.services.adobe.com",
        "adobe.demdex.net",
        "assets.adobedtm.com",
        "adobeid.services.adobe.com",
        "ims-na1.adobelogin.com",
        "account.adobe.com",
        "entitlement.adobe.com",
        "ims-na1.adobelogin.com",
        "adobe-stg1.com",
        "adobe-stg2.com",
        "assets2.adobetm.com",
        "cc-api-data.adobe.io",
        "cdn.adobe.io",
        "creative.adobe.com",
        "exchange.adobe.com",
        "na1r.services.adobe.com",
        "outgoing.adobe.com",
        "packages.adobe.com",
        "prod-rel-ffc-cc-us-east-1-cc-us-east-1.adobe.io",
        "prod-rel-ffc-cc-us-east-1-cc-us-east-1.adobe.io",
        "status.adobe.com",
        "upload-prod.adobe.io",
        "users.services.adobe.com",
        "video.adobe.io",
        "cc-asset.adobe.io",
        "cc-api-storage.adobe.io",
        "creativecloud.adobe.com",
        "feedback.adobe.com",
        "fonts.adobe.com",
        "images.adobe.com",
        "learn.adobe.com",
        "my.adobe.io",
        "static.adobe.io",
        "training.adobe.com",
        "typekit.com",
        "use.typekit.net",
        "video.adobe.com"
    )
    Add-HostsFileEntry -entries $adobeDomains
}

# Function to unblock Adobe services by modifying the hosts file
function Unblock-AdobeHosts {
    $adobeDomains = @(
        "adobe.com",
        "adobelogin.com",
        "adobeid-na1.services.adobe.com",
        "adobeid-na2.services.adobe.com",
        "lm.licenses.adobe.com",
        "na1r.services.adobe.com",
        "na2r.services.adobe.com",
        "cc-api-data.adobe.io",
        "na1r.services.adobe.com",
        "adobe.demdex.net",
        "assets.adobedtm.com",
        "adobeid.services.adobe.com",
        "ims-na1.adobelogin.com",
        "account.adobe.com",
        "entitlement.adobe.com",
        "ims-na1.adobelogin.com",
        "adobe-stg1.com",
        "adobe-stg2.com",
        "assets2.adobetm.com",
        "cc-api-data.adobe.io",
        "cdn.adobe.io",
        "creative.adobe.com",
        "exchange.adobe.com",
        "na1r.services.adobe.com",
        "outgoing.adobe.com",
        "packages.adobe.com",
        "prod-rel-ffc-cc-us-east-1-cc-us-east-1.adobe.io",
        "prod-rel-ffc-cc-us-east-1-cc-us-east-1.adobe.io",
        "status.adobe.com",
        "upload-prod.adobe.io",
        "users.services.adobe.com",
        "video.adobe.io",
        "cc-asset.adobe.io",
        "cc-api-storage.adobe.io",
        "creativecloud.adobe.com",
        "feedback.adobe.com",
        "fonts.adobe.com",
        "images.adobe.com",
        "learn.adobe.com",
        "my.adobe.io",
        "static.adobe.io",
        "training.adobe.com",
        "typekit.com",
        "use.typekit.net",
        "video.adobe.com"
    )
    Remove-HostsFileEntry -entries $adobeDomains
}

# Function to add entries from a .txt file to the hosts file
function Add-EntriesFromTxtFile {
    [System.Windows.Forms.OpenFileDialog]$fileDialog = New-Object System.Windows.Forms.OpenFileDialog
    $fileDialog.Filter = "Text files (*.txt)|*.txt"
    $fileDialog.Title = "Select a .txt file containing domains/IPs to block"
    
    if ($fileDialog.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $filePath = $fileDialog.FileName
        $entries = Get-Content -Path $filePath
        Add-HostsFileEntry -entries $entries
    } else {
        Write-Host "No file selected" -ForegroundColor Yellow
    }
}

# Function to send email notifications
function Send-EmailNotification {
    param (
        [string]$subject,
        [string]$body
    )
    $smtpServer = "smtp.example.com"
    $smtpFrom = "admin@example.com"
    $smtpTo = "user@example.com"
    $message = New-Object system.net.mail.mailmessage
    $message.from = $smtpFrom
    $message.To.add($smtpTo)
    $message.Subject = $subject
    $message.Body = $body
    $smtp = New-Object Net.Mail.SmtpClient($smtpServer)
    try {
        $smtp.Send($message)
        Log-Message "Email notification sent: $subject"
        Write-Host "Email notification sent: $subject"
    } catch {
        Log-Message "Failed to send email: $_" "error"
        Write-Host "Failed to send email: $_" -ForegroundColor Red
    }
}

# Function to monitor and log blocked connections
function Monitor-BlockedConnections {
    Write-Host "Starting to monitor blocked connections..."
    $logFile = "$PSScriptRoot\FirewallMonitorLog.txt"
    $startDate = Get-Date
    $filter = "NOT Action='Allow' AND EventID=5157 AND TimeCreated>='$startDate'"
    Get-WinEvent -FilterHashtable @{LogName='Security'; StartTime=$startDate} -FilterXPath $filter -MaxEvents 1000 -ErrorAction SilentlyContinue | ForEach-Object {
        $entry = "$($_.TimeCreated) - $($_.Message)"
        Add-Content -Path $logFile -Value $entry
        Write-Host $entry
    }
}

# Function to show the intro
function Show-Intro {
    Write-Host " "
    Write-Host "*************************************************************" -ForegroundColor Green
    Write-Host "*                                                           *" -ForegroundColor Green
    Write-Host "*                     FIREWALL MANAGER                      *" -ForegroundColor Green
    Write-Host "*                                                           *" -ForegroundColor Green
    Write-Host "*************************************************************" -ForegroundColor Green
    Write-Host " "
    Write-Host " 'Hacking is not about the destination, it's about the journey.'" -ForegroundColor Cyan
    Write-Host " "
}

# Interactive Menu
function Show-Menu {
    Write-Host "Select an action:"
    Write-Host "1. Block Adobe applications"
    Write-Host "2. Unblock Adobe applications"
    Write-Host "3. Change directory"
    Write-Host "4. Schedule this script"
    Write-Host "5. Block Adobe services via hosts file"
    Write-Host "6. Unblock Adobe services via hosts file"
    Write-Host "7. Add entries from a .txt file to hosts file"
    Write-Host "8. Monitor blocked connections"
    Write-Host "9. Exit"
}

function Get-MenuSelection {
    param (
        [string]$prompt
    )
    $selection = Read-Host $prompt
    switch ($selection) {
        1 { return "block" }
        2 { return "unblock" }
        3 { return "changeDir" }
        4 { return "schedule" }
        5 { return "blockHosts" }
        6 { return "unblockHosts" }
         7 { return "addFromTxt" }
        8 { return "monitor" }
        9 { exit 0 }
        default { Write-Host "Invalid selection. Please try again." -ForegroundColor Red }
    }
}

# Main script execution
function Main {
    Show-Intro

    $global:BaseDir = "C:\Program Files\Adobe"
    $global:LogLevel = "info"
    $global:RulePrefix = "Adobe"

    while ($true) {
        Show-Menu
        $Action = Get-MenuSelection -prompt "Enter your choice:"

        if ($Action -eq "block" -or $Action -eq "unblock") {
            # Validate the base directory
            if (-Not (Test-Path -Path $BaseDir -PathType Container)) {
                Write-Host "The specified base directory does not exist: $BaseDir" -ForegroundColor Yellow
                continue
            }

            # Get a list of all executable files in the Adobe directory and its subdirectories
            $executables = Get-ChildItem -Path $BaseDir -Recurse -Include *.exe

            if ($executables.Count -eq 0) {
                Write-Host "No executable files found in the specified directory: $BaseDir" -ForegroundColor Yellow
                continue
            }

            $selectedExecutables = @()
            foreach ($exe in $executables) {
                if (Get-UserConfirmation "Do you want to $Action $($exe.FullName)?") {
                    $selectedExecutables += $exe
                }
            }

            if ($selectedExecutables.Count -eq 0) {
                Write-Host "No executables selected for action: $Action" -ForegroundColor Yellow
                continue
            }

            if ($Action -eq "block") {
                Log-Message "Starting to add firewall rules for Adobe applications..."
                Write-Host "Starting to add firewall rules for Adobe applications..."

                Backup-FirewallRules

                foreach ($exe in $selectedExecutables) {
                    Add-FirewallRule -exePath $exe.FullName -exeName $exe.BaseName
                }

                Block-AdobeDomainsAndIPs

                Log-Message "Finished adding firewall rules for Adobe applications."
                Write-Host "Finished adding firewall rules for Adobe applications."

                # Send email notification
                Send-EmailNotification -subject "Firewall Rules Added" -body "Firewall rules for Adobe applications have been added."

            } elseif ($Action -eq "unblock") {
                Log-Message "Starting to remove firewall rules for Adobe applications..."
                Write-Host "Starting to remove firewall rules for Adobe applications..."

                foreach ($exe in $selectedExecutables) {
                    Remove-FirewallRule -exeName $exe.BaseName
                }

                Log-Message "Finished removing firewall rules for Adobe applications."
                Write-Host "Finished removing firewall rules for Adobe applications."

                # Send email notification
                Send-EmailNotification -subject "Firewall Rules Removed" -body "Firewall rules for Adobe applications have been removed."

            }
        } elseif ($Action -eq "changeDir") {
            $newDir = Read-Host "Enter the new directory path"
            if (Test-Path -Path $newDir -PathType Container) {
                $global:BaseDir = $newDir
                Write-Host "Base directory changed to: $BaseDir"
            } else {
                Write-Host "The specified directory does not exist: $newDir" -ForegroundColor Red
            }
        } elseif ($Action -eq "schedule") {
            $scheduleTime = Read-Host "Enter the schedule time (yyyy-MM-dd HH:mm):"
            try {
                $parsedScheduleTime = [datetime]::ParseExact($scheduleTime, "yyyy-MM-dd HH:mm", $null)
                Schedule-Script -scriptPath $MyInvocation.MyCommand.Definition -scheduleTime $parsedScheduleTime
            } catch {
                Write-Host "Invalid date format. Please use yyyy-MM-dd HH:mm." -ForegroundColor Red
            }
        } elseif ($Action -eq "blockHosts") {
            Block-AdobeHosts

            # Send email notification
            Send-EmailNotification -subject "Hosts File Updated" -body "Adobe domains have been blocked in the hosts file."

        } elseif ($Action -eq "unblockHosts") {
            Unblock-AdobeHosts

            # Send email notification
            Send-EmailNotification -subject "Hosts File Updated" -body "Adobe domains have been unblocked in the hosts file."

        } elseif ($Action -eq "addFromTxt") {
            Add-EntriesFromTxtFile

            # Send email notification
            Send-EmailNotification -subject "Hosts File Updated" -body "Entries from the specified .txt file have been added to the hosts file."

        } elseif ($Action -eq "monitor") {
            Monitor-BlockedConnections
        }
    }
}

Main
