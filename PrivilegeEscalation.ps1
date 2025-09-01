[CmdletBinding()]
param(
    [string]$Target = "localhost",
    [string]$Username = "",
    [string]$Password = "",
    [string]$Domain = "",
    [switch]$LocalOnly,
    [switch]$RemoteOnly,
    [switch]$Verbose,
    [string]$OutputFile = ""
)

function Write-ColorOutput {
    param(
        [string]$Message,
        [string]$Color = "White"
    )
    Write-Host $Message -ForegroundColor $Color
}

function Test-AdminPrivileges {
    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
    return $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

function Get-SystemInfo {
    Write-ColorOutput "[+] Gathering system information..." "Green"
    
    try {
        $systemInfo = Get-WmiObject -Class Win32_OperatingSystem | Select-Object Caption, Version, BuildNumber, OSArchitecture, LastBootUpTime
        $computerInfo = Get-WmiObject -Class Win32_ComputerSystem | Select-Object Name, Domain, TotalPhysicalMemory, NumberOfProcessors
        
        Write-ColorOutput "    OS: $($systemInfo.Caption) $($systemInfo.Version)" "Yellow"
        Write-ColorOutput "    Architecture: $($systemInfo.OSArchitecture)" "Yellow"
        Write-ColorOutput "    Computer: $($computerInfo.Name)" "Yellow"
        Write-ColorOutput "    Domain: $($computerInfo.Domain)" "Yellow"
        Write-ColorOutput "    Memory: $([math]::Round($computerInfo.TotalPhysicalMemory/1GB, 2)) GB" "Yellow"
        Write-ColorOutput "    Processors: $($computerInfo.NumberOfProcessors)" "Yellow"
        
        return @{
            OS = $systemInfo
            Computer = $computerInfo
        }
    }
    catch {
        Write-ColorOutput "[-] Error gathering system info: $($_.Exception.Message)" "Red"
        return $null
    }
}

function Get-UserPrivileges {
    Write-ColorOutput "[+] Checking current user privileges..." "Green"
    
    try {
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        $principal = New-Object Security.Principal.WindowsPrincipal($currentUser)
        
        Write-ColorOutput "    Current User: $($currentUser.Name)" "Yellow"
        Write-ColorOutput "    SID: $($currentUser.User.Value)" "Yellow"
        Write-ColorOutput "    Is Admin: $($principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))" "Yellow"
        
        $groups = $currentUser.Groups | ForEach-Object {
            try {
                $_.Translate([Security.Principal.SecurityIdentifier])
            }
            catch {
                $_.Value
            }
        }
        
        Write-ColorOutput "    Groups:" "Yellow"
        foreach ($group in $groups) {
            Write-ColorOutput "      - $group" "Cyan"
        }
        
        return @{
            Username = $currentUser.Name
            SID = $currentUser.User.Value
            IsAdmin = $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
            Groups = $groups
        }
    }
    catch {
        Write-ColorOutput "[-] Error checking user privileges: $($_.Exception.Message)" "Red"
        return $null
    }
}

function Find-WritableDirectories {
    Write-ColorOutput "[+] Searching for writable directories..." "Green"
    
    try {
        $writableDirs = @()
        $commonPaths = @(
            "$env:TEMP",
            "$env:TMP",
            "$env:USERPROFILE\Desktop",
            "$env:USERPROFILE\Downloads",
            "$env:USERPROFILE\Documents",
            "C:\Windows\Temp",
            "C:\ProgramData"
        )
        
        foreach ($path in $commonPaths) {
            if (Test-Path $path) {
                try {
                    $testFile = Join-Path $path "test_write_$(Get-Random).tmp"
                    New-Item -ItemType File -Path $testFile -Force | Out-Null
                    Remove-Item $testFile -Force
                    $writableDirs += $path
                    Write-ColorOutput "    [+] Writable: $path" "Green"
                }
                catch {
                    Write-ColorOutput "    [-] Not writable: $path" "Red"
                }
            }
        }
        
        return $writableDirs
    }
    catch {
        Write-ColorOutput "[-] Error searching writable directories: $($_.Exception.Message)" "Red"
        return @()
    }
}

function Find-ServiceVulnerabilities {
    Write-ColorOutput "[+] Checking for vulnerable services..." "Green"
    
    try {
        $vulnerableServices = @()
        
        $services = Get-WmiObject -Class Win32_Service | Where-Object {
            $_.StartName -eq "LocalSystem" -or 
            $_.StartName -eq "NT AUTHORITY\SYSTEM" -or
            $_.StartName -eq "NT AUTHORITY\LocalService" -or
            $_.StartName -eq "NT AUTHORITY\NetworkService"
        }
        
        foreach ($service in $services) {
            try {
                $servicePath = $service.PathName
                if ($servicePath -and $servicePath -ne "") {
                    $serviceDir = Split-Path $servicePath -Parent
                    if (Test-Path $serviceDir) {
                        $acl = Get-Acl $serviceDir
                        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
                        
                        foreach ($access in $acl.Access) {
                            if ($access.IdentityReference -eq $currentUser.Name -and 
                                ($access.FileSystemRights -match "FullControl" -or 
                                 $access.FileSystemRights -match "Modify" -or
                                 $access.FileSystemRights -match "Write")) {
                                
                                $vulnerableServices += @{
                                    Name = $service.Name
                                    DisplayName = $service.DisplayName
                                    Path = $servicePath
                                    Directory = $serviceDir
                                    StartName = $service.StartName
                                    Vulnerability = "Writable service directory"
                                }
                                
                                Write-ColorOutput "    [+] Vulnerable service: $($service.Name)" "Red"
                                Write-ColorOutput "        Path: $servicePath" "Yellow"
                                Write-ColorOutput "        Directory: $serviceDir" "Yellow"
                                Write-ColorOutput "        StartName: $($service.StartName)" "Yellow"
                                break
                            }
                        }
                    }
                }
            }
            catch {
                continue
            }
        }
        
        return $vulnerableServices
    }
    catch {
        Write-ColorOutput "[-] Error checking service vulnerabilities: $($_.Exception.Message)" "Red"
        return @()
    }
}

function Find-ScheduledTaskVulnerabilities {
    Write-ColorOutput "[+] Checking for vulnerable scheduled tasks..." "Green"
    
    try {
        $vulnerableTasks = @()
        
        $tasks = Get-ScheduledTask | Where-Object {
            $_.Principal.UserId -eq "SYSTEM" -or
            $_.Principal.UserId -eq "NT AUTHORITY\SYSTEM"
        }
        
        foreach ($task in $tasks) {
            try {
                $taskInfo = Get-ScheduledTaskInfo -TaskName $task.TaskName
                $taskPath = $taskInfo.TaskPath
                
                if ($taskPath -and (Test-Path $taskPath)) {
                    $acl = Get-Acl $taskPath
                    $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
                    
                    foreach ($access in $acl.Access) {
                        if ($access.IdentityReference -eq $currentUser.Name -and 
                            ($access.FileSystemRights -match "FullControl" -or 
                             $access.FileSystemRights -match "Modify" -or
                             $access.FileSystemRights -match "Write")) {
                            
                            $vulnerableTasks += @{
                                Name = $task.TaskName
                                Path = $taskPath
                                UserId = $task.Principal.UserId
                                Vulnerability = "Writable task directory"
                            }
                            
                            Write-ColorOutput "    [+] Vulnerable task: $($task.TaskName)" "Red"
                            Write-ColorOutput "        Path: $taskPath" "Yellow"
                            Write-ColorOutput "        UserId: $($task.Principal.UserId)" "Yellow"
                            break
                        }
                    }
                }
            }
            catch {
                continue
            }
        }
        
        return $vulnerableTasks
    }
    catch {
        Write-ColorOutput "[-] Error checking scheduled task vulnerabilities: $($_.Exception.Message)" "Red"
        return @()
    }
}

function Find-RegistryVulnerabilities {
    Write-ColorOutput "[+] Checking for vulnerable registry keys..." "Green"
    
    try {
        $vulnerableKeys = @()
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        
        $registryPaths = @(
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer\Run",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\ShellExecuteHooks",
            "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon",
            "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced\Folder\Hidden\SHOWALL"
        )
        
        foreach ($path in $registryPaths) {
            try {
                if (Test-Path $path) {
                    $acl = Get-Acl $path
                    
                    foreach ($access in $acl.Access) {
                        if ($access.IdentityReference -eq $currentUser.Name -and 
                            ($access.RegistryRights -match "FullControl" -or 
                             $access.RegistryRights -match "SetValue" -or
                             $access.RegistryRights -match "CreateSubKey")) {
                            
                            $vulnerableKeys += @{
                                Path = $path
                                Identity = $access.IdentityReference
                                Rights = $access.RegistryRights
                                Vulnerability = "Writable registry key"
                            }
                            
                            Write-ColorOutput "    [+] Vulnerable registry: $path" "Red"
                            Write-ColorOutput "        Identity: $($access.IdentityReference)" "Yellow"
                            Write-ColorOutput "        Rights: $($access.RegistryRights)" "Yellow"
                            break
                        }
                    }
                }
            }
            catch {
                continue
            }
        }
        
        return $vulnerableKeys
    }
    catch {
        Write-ColorOutput "[-] Error checking registry vulnerabilities: $($_.Exception.Message)" "Red"
        return @()
    }
}

function Find-DriverVulnerabilities {
    Write-ColorOutput "[+] Checking for vulnerable drivers..." "Green"
    
    try {
        $vulnerableDrivers = @()
        
        $drivers = Get-WmiObject -Class Win32_SystemDriver | Where-Object {
            $_.State -eq "Running" -and $_.PathName -ne ""
        }
        
        foreach ($driver in $drivers) {
            try {
                $driverPath = $driver.PathName
                if ($driverPath -and (Test-Path $driverPath)) {
                    $driverDir = Split-Path $driverPath -Parent
                    if (Test-Path $driverDir) {
                        $acl = Get-Acl $driverDir
                        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
                        
                        foreach ($access in $acl.Access) {
                            if ($access.IdentityReference -eq $currentUser.Name -and 
                                ($access.FileSystemRights -match "FullControl" -or 
                                 $access.FileSystemRights -match "Modify" -or
                                 $access.FileSystemRights -match "Write")) {
                                
                                $vulnerableDrivers += @{
                                    Name = $driver.Name
                                    DisplayName = $driver.DisplayName
                                    Path = $driverPath
                                    Directory = $driverDir
                                    State = $driver.State
                                    Vulnerability = "Writable driver directory"
                                }
                                
                                Write-ColorOutput "    [+] Vulnerable driver: $($driver.Name)" "Red"
                                Write-ColorOutput "        Path: $driverPath" "Yellow"
                                Write-ColorOutput "        Directory: $driverDir" "Yellow"
                                Write-ColorOutput "        State: $($driver.State)" "Yellow"
                                break
                            }
                        }
                    }
                }
            }
            catch {
                continue
            }
        }
        
        return $vulnerableDrivers
    }
    catch {
        Write-ColorOutput "[-] Error checking driver vulnerabilities: $($_.Exception.Message)" "Red"
        return @()
    }
}

function Find-ProcessVulnerabilities {
    Write-ColorOutput "[+] Checking for vulnerable processes..." "Green"
    
    try {
        $vulnerableProcesses = @()
        
        $processes = Get-Process | Where-Object {
            $_.ProcessName -notmatch "^(Idle|System|Registry|smss|csrss|wininit|services|lsass|winlogon|explorer|conhost)$"
        }
        
        foreach ($process in $processes) {
            try {
                $processPath = $process.Path
                if ($processPath -and (Test-Path $processPath)) {
                    $processDir = Split-Path $processPath -Parent
                    if (Test-Path $processDir) {
                        $acl = Get-Acl $processDir
                        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
                        
                        foreach ($access in $acl.Access) {
                            if ($access.IdentityReference -eq $currentUser.Name -and 
                                ($access.FileSystemRights -match "FullControl" -or 
                                 $access.FileSystemRights -match "Modify" -or
                                 $access.FileSystemRights -match "Write")) {
                                
                                $vulnerableProcesses += @{
                                    Name = $process.ProcessName
                                    Id = $process.Id
                                    Path = $processPath
                                    Directory = $processDir
                                    Vulnerability = "Writable process directory"
                                }
                                
                                Write-ColorOutput "    [+] Vulnerable process: $($process.ProcessName) (PID: $($process.Id))" "Red"
                                Write-ColorOutput "        Path: $processPath" "Yellow"
                                Write-ColorOutput "        Directory: $processDir" "Yellow"
                                break
                            }
                        }
                    }
                }
            }
            catch {
                continue
            }
        }
        
        return $vulnerableProcesses
    }
    catch {
        Write-ColorOutput "[-] Error checking process vulnerabilities: $($_.Exception.Message)" "Red"
        return @()
    }
}

function Find-NetworkVulnerabilities {
    Write-ColorOutput "[+] Checking for network vulnerabilities..." "Green"
    
    try {
        $networkVulns = @()
        
        $listeners = netstat -an | Select-String "LISTENING"
        $currentUser = [Security.Principal.WindowsIdentity]::GetCurrent()
        
        foreach ($listener in $listeners) {
            $parts = $listener -split '\s+'
            if ($parts.Length -ge 4) {
                $localAddress = $parts[2]
                $port = ($parts[2] -split ':')[-1]
                
                if ($port -match '^\d+$' -and [int]$port -lt 1024) {
                    $networkVulns += @{
                        Port = $port
                        Address = $localAddress
                        Vulnerability = "Privileged port listening"
                    }
                    
                    Write-ColorOutput "    [+] Privileged port: $port" "Yellow"
                }
            }
        }
        
        $shares = Get-WmiObject -Class Win32_Share | Where-Object {
            $_.Name -notmatch "^(ADMIN\$|C\$|IPC\$|PRINT\$)$"
        }
        
        foreach ($share in $shares) {
            try {
                $sharePath = $share.Path
                if ($sharePath -and (Test-Path $sharePath)) {
                    $acl = Get-Acl $sharePath
                    
                    foreach ($access in $acl.Access) {
                        if ($access.IdentityReference -eq $currentUser.Name -and 
                            ($access.FileSystemRights -match "FullControl" -or 
                             $access.FileSystemRights -match "Modify" -or
                             $access.FileSystemRights -match "Write")) {
                            
                            $networkVulns += @{
                                Share = $share.Name
                                Path = $sharePath
                                Vulnerability = "Writable network share"
                            }
                            
                            Write-ColorOutput "    [+] Vulnerable share: $($share.Name)" "Red"
                            Write-ColorOutput "        Path: $sharePath" "Yellow"
                            break
                        }
                    }
                }
            }
            catch {
                continue
            }
        }
        
        return $networkVulns
    }
    catch {
        Write-ColorOutput "[-] Error checking network vulnerabilities: $($_.Exception.Message)" "Red"
        return @()
    }
}

function Generate-ExploitSuggestions {
    Write-ColorOutput "[+] Generating exploit suggestions..." "Green"
    
    $suggestions = @()
    
    if ($script:serviceVulns.Count -gt 0) {
        $suggestions += "Service DLL Hijacking: Replace vulnerable service binaries"
        $suggestions += "Service Path Hijacking: Modify service paths to point to malicious executables"
    }
    
    if ($script:taskVulns.Count -gt 0) {
        $suggestions += "Scheduled Task Hijacking: Modify task definitions to execute malicious code"
    }
    
    if ($script:registryVulns.Count -gt 0) {
        $suggestions += "Registry Run Key Modification: Add malicious executables to startup keys"
        $suggestions += "Shell Execute Hook: Install malicious shell hooks"
    }
    
    if ($script:driverVulns.Count -gt 0) {
        $suggestions += "Driver Replacement: Replace vulnerable drivers with malicious ones"
    }
    
    if ($script:processVulns.Count -gt 0) {
        $suggestions += "Process Injection: Inject malicious code into vulnerable processes"
        $suggestions += "DLL Hijacking: Replace DLLs used by vulnerable processes"
    }
    
    if ($script:networkVulns.Count -gt 0) {
        $suggestions += "Port Hijacking: Bind to privileged ports"
        $suggestions += "Share Exploitation: Use writable shares for persistence"
    }
    
    foreach ($suggestion in $suggestions) {
        Write-ColorOutput "    [+] $suggestion" "Cyan"
    }
    
    return $suggestions
}

function Save-Results {
    param([string]$OutputFile)
    
    if ($OutputFile -eq "") {
        return
    }
    
    try {
        $results = @{
            Timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
            SystemInfo = $script:systemInfo
            UserInfo = $script:userInfo
            WritableDirectories = $script:writableDirs
            ServiceVulnerabilities = $script:serviceVulns
            TaskVulnerabilities = $script:taskVulns
            RegistryVulnerabilities = $script:registryVulns
            DriverVulnerabilities = $script:driverVulns
            ProcessVulnerabilities = $script:processVulns
            NetworkVulnerabilities = $script:networkVulns
            ExploitSuggestions = $script:suggestions
        }
        
        $results | ConvertTo-Json -Depth 10 | Out-File -FilePath $OutputFile -Encoding UTF8
        Write-ColorOutput "[+] Results saved to: $OutputFile" "Green"
    }
    catch {
        Write-ColorOutput "[-] Error saving results: $($_.Exception.Message)" "Red"
    }
}

function Start-PrivilegeEscalationScan {
    Write-ColorOutput "===============================================" "Magenta"
    Write-ColorOutput "    XILLEN Privilege Escalation Scanner" "Magenta"
    Write-ColorOutput "===============================================" "Magenta"
    Write-ColorOutput ""
    
    $script:systemInfo = Get-SystemInfo
    $script:userInfo = Get-UserPrivileges
    $script:writableDirs = Find-WritableDirectories
    $script:serviceVulns = Find-ServiceVulnerabilities
    $script:taskVulns = Find-ScheduledTaskVulnerabilities
    $script:registryVulns = Find-RegistryVulnerabilities
    $script:driverVulns = Find-DriverVulnerabilities
    $script:processVulns = Find-ProcessVulnerabilities
    $script:networkVulns = Find-NetworkVulnerabilities
    $script:suggestions = Generate-ExploitSuggestions
    
    Write-ColorOutput ""
    Write-ColorOutput "===============================================" "Magenta"
    Write-ColorOutput "              SCAN SUMMARY" "Magenta"
    Write-ColorOutput "===============================================" "Magenta"
    
    $totalVulns = $script:serviceVulns.Count + $script:taskVulns.Count + 
                  $script:registryVulns.Count + $script:driverVulns.Count + 
                  $script:processVulns.Count + $script:networkVulns.Count
    
    Write-ColorOutput "Total vulnerabilities found: $totalVulns" "Yellow"
    Write-ColorOutput "Writable directories: $($script:writableDirs.Count)" "Yellow"
    Write-ColorOutput "Exploit suggestions: $($script:suggestions.Count)" "Yellow"
    
    if ($totalVulns -gt 0) {
        Write-ColorOutput ""
        Write-ColorOutput "CRITICAL: System appears vulnerable to privilege escalation!" "Red"
        Write-ColorOutput "Review all findings and implement security controls immediately." "Red"
    } else {
        Write-ColorOutput ""
        Write-ColorOutput "No obvious privilege escalation vectors found." "Green"
        Write-ColorOutput "Continue monitoring and maintain security posture." "Green"
    }
    
    if ($OutputFile -ne "") {
        Save-Results -OutputFile $OutputFile
    }
}

try {
    Start-PrivilegeEscalationScan
}
catch {
    Write-ColorOutput "[-] Fatal error during scan: $($_.Exception.Message)" "Red"
    exit 1
}
