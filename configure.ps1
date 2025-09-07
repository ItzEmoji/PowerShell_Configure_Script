# Function to check if running as administrator
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# Function to generate a random password
function New-RandomPassword {
    $length = 12
    $chars = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()"
    $password = -join ((1..$length) | ForEach-Object { $chars[(Get-Random -Minimum 0 -Maximum $chars.Length)] })
    return $password
}

# Function to post to GitHub Gist
function New-Gist {
    param ($Content, $FileName, $AccessToken, $IsPublic = $false)
    try {
        $uri = "https://api.github.com/gists"
        $body = @{
            description = "Service export from configure.ps1"
            public = $IsPublic
            files = @{
                "$FileName" = @{
                    content = $Content
                }
            }
        } | ConvertTo-Json
        $headers = @{
            Authorization = "token $AccessToken"
            Accept = "application/vnd.github.v3+json"
        }
        $response = Invoke-RestMethod -Uri $uri -Method Post -Body $body -Headers $headers -ContentType "application/json"
        Write-Host "Gist created successfully: $($response.html_url)"
        return $response.html_url
    } catch {
        Write-Host "Error creating Gist: $($_.Exception.Message)"
        return $null
    }
}

# Function to post to Pastebin
function New-Pastebin {
    param (
        [Parameter(Mandatory=$true)] $Content,
        [Parameter(Mandatory=$true)] $Title,
        [Parameter(Mandatory=$true)] $ApiKey,
        $Password,
        $UserKey = "",
        $ExpireDate = "1M"
    )
    try {
        $uri = "https://pastebin.com/api/api_post.php"
        # Check content size (Pastebin free account limit: ~500 KB)
        $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($Content)
        if ($contentBytes.Length -gt 500000) {
            Write-Host "Error: Paste content exceeds 500 KB limit for free Pastebin accounts."
            return $null
        }
        # Build body as a hashtable
        $bodyParams = @{
            api_dev_key = $ApiKey
            api_option = "paste"
            api_paste_code = $Content
            api_paste_name = $Title
            api_paste_expire_date = $ExpireDate
            api_paste_format = "json"
        }
        if ($Password) {
            if (-not $UserKey) {
                Write-Host "Warning: Private pastes (with password) require an api_user_key. Using unlisted (api_paste_private=1) instead."
                $bodyParams.api_paste_private = "1"
                $bodyParams.api_paste_password = $Password
            } else {
                $bodyParams.api_paste_private = "2"
                $bodyParams.api_paste_password = $Password
                $bodyParams.api_user_key = $UserKey
            }
        } else {
            $bodyParams.api_paste_private = "1"
        }
        # Convert to URL-encoded string
        $body = ($bodyParams.GetEnumerator() | ForEach-Object {
            "$($_.Key)=$([System.Web.HttpUtility]::UrlEncode($_.Value))"
        }) -join "&"
        
        # Save body for debugging
        $debugFile = [System.IO.Path]::GetTempFileName() + ".txt"
        $body | Out-File -FilePath $debugFile -Encoding UTF8
        Write-Host "Debug: Request body saved to $debugFile"

        $response = Invoke-WebRequest -Uri $uri -Method Post -Body $body -ContentType "application/x-www-form-urlencoded; charset=UTF-8" -ErrorAction Stop
        if ($response.StatusCode -eq 200 -and $response.Content -match "^https://pastebin.com/") {
            Write-Host "Pastebin created successfully: $($response.Content)"
            if ($Password) {
                Write-Host "Pastebin password: $Password"
            }
            return $response.Content
        } else {
            Write-Host "Pastebin API returned unexpected response: $($response.Content)"
            return $null
        }
    } catch {
        Write-Host "Error creating Pastebin: $($_.Exception.Message)"
        if ($_.Exception.Response) {
            Write-Host "HTTP Status: $($_.Exception.Response.StatusCode)"
            try {
                $stream = $_.Exception.Response.GetResponseStream()
                $reader = New-Object System.IO.StreamReader($stream)
                $responseContent = $reader.ReadToEnd()
                Write-Host "Response Content: $responseContent"
            } catch {
                Write-Host "Unable to read response content."
            }
        }
        Write-Host "Check the request body in $debugFile for issues."
        return $null
    }
}

# Main script function
function Invoke-SuperTool {
    # If not running as admin, relaunch with elevation
    if (-not (Test-Admin)) {
        $scriptPath = $PSCommandPath
        $isIex = $MyInvocation.Line -like '*iex*'
        if (-not $scriptPath -or $isIex) {
            try {
                $scriptContent = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ItzEmoji/Powershell_Configure_Script/master/configure.ps1" -UseBasicParsing).Content
                $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
                Set-Content -Path $tempScript -Value $scriptContent -Force
                $scriptPath = $tempScript
            } catch {
                Write-Host "Error creating temporary script file."
                return
            }
        }

        try {
            Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Wait
            return
        } catch {
            Write-Host "Error restarting with UAC."
            return
        }
    }

    # Main menu loop
    while ($true) {
        Write-Host "Welcome ItzEmoji!"
        Write-Host "Options:"
        Write-Host "1: Start WinUtil"
        Write-Host "2: Miscellaneous"
        Write-Host "c: Clear Screen"
        Write-Host "q: Quit"
        $menuInput = Read-Host "Enter your choice"

        if ($menuInput -eq 'q') {
            # Clean up temporary script if it exists
            if ($scriptPath -and $scriptPath -like "*.tmp.ps1") {
                Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
            }
            return
        } elseif ($menuInput -eq 'c') {
            Clear-Host
            continue
        } elseif ($menuInput -eq '1') {
            # Run WinUtil
            try {
                $winUtilUrl = "https://christitus.com/win"
                $winUtilPath = [System.IO.Path]::GetTempFileName() + ".ps1"
                Invoke-WebRequest -Uri $winUtilUrl -OutFile $winUtilPath
                Start-Process powershell.exe -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$winUtilPath`"" -Wait -NoNewWindow
                Remove-Item $winUtilPath -Force
                Write-Host "WinUtil completed."
            } catch {
                Write-Host "Error running WinUtil: $($_.Exception.Message)"
            }
        } elseif ($menuInput -eq '2') {
            # Miscellaneous submenu
            while ($true) {
                Write-Host "Miscellaneous Options:"
                Write-Host "1: Install Package Manager"
                Write-Host "2: Install SystemInformer"
                Write-Host "3: Registry Loader"
                Write-Host "4: Manage Services"
                Write-Host "5: Run CrapFixer"
                Write-Host "6: Run NAppClean"
                Write-Host "c: Clear Screen"
                Write-Host "q: Quit to main menu"
                $miscInput = Read-Host "Enter your choice"

                if ($miscInput -eq 'q') {
                    break
                } elseif ($miscInput -eq 'c') {
                    Clear-Host
                    continue
                } elseif ($miscInput -eq '1') {
                    # Package Manager submenu
                    while ($true) {
                        Write-Host "Choose a package manager to install:"
                        Write-Host "1: Chocolatey"
                        Write-Host "2: Scoop"
                        Write-Host "c: Clear Screen"
                        Write-Host "q: Quit to Miscellaneous menu"
                        $pkgInput = Read-Host "Enter your choice"

                        if ($pkgInput -eq 'q') {
                            break
                        } elseif ($pkgInput -eq 'c') {
                            Clear-Host
                            continue
                        } elseif ($pkgInput -eq '1') {
                            try {
                                $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
                                if ($currentPolicy -ne 'RemoteSigned' -and $currentPolicy -ne 'Unrestricted' -and $currentPolicy -ne 'Bypass') {
                                    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
                                    Write-Host "Execution policy set to RemoteSigned for Chocolatey installation."
                                }
                                $chocoInstallerUrl = "https://community.chocolatey.org/install.ps1"
                                $chocoInstallerPath = [System.IO.Path]::GetTempFileName() + ".ps1"
                                Invoke-WebRequest -Uri $chocoInstallerUrl -OutFile $chocoInstallerPath
                                & $chocoInstallerPath
                                Remove-Item $chocoInstallerPath -Force
                                Write-Host "Chocolatey installed successfully."
                            } catch {
                                Write-Host "Error installing Chocolatey: $($_.Exception.Message)"
                                Write-Host "Try running 'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser' manually and then retry."
                            }
                        } elseif ($pkgInput -eq '2') {
                            try {
                                $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
                                if ($currentPolicy -ne 'RemoteSigned' -and $currentPolicy -ne 'Unrestricted' -and $currentPolicy -ne 'Bypass') {
                                    Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
                                    Write-Host "Execution policy set to RemoteSigned for Scoop installation."
                                }
                                $scoopInstallerUrl = "https://get.scoop.sh"
                                $scoopInstallerPath = [System.IO.Path]::GetTempFileName() + ".ps1"
                                Invoke-WebRequest -Uri $scoopInstallerUrl -OutFile $scoopInstallerPath
                                & $scoopInstallerPath -RunAsAdmin
                                Remove-Item $scoopInstallerPath -Force
                                Write-Host "Scoop installed successfully."
                            } catch {
                                Write-Host "Error installing Scoop: $($_.Exception.Message)"
                                Write-Host "Try running 'Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser' manually and then retry."
                            }
                        } else {
                            Write-Host "Invalid choice. Please try again."
                        }
                    }
                } elseif ($miscInput -eq '2') {
                    try {
                        Write-Host "Installing SystemInformer via winget..."
                        Start-Process winget -ArgumentList "install --id WinsiderSS.SystemInformer.Canary --silent --accept-source-agreements --accept-package-agreements" -Wait -NoNewWindow
                        Write-Host "SystemInformer installed successfully."
                        $response = Read-Host "Do you want to replace Task Manager with SystemInformer by adding a registry key? (y/n)"
                        if ($response -eq 'y' -or $response -eq 'Y') {
                            try {
                                $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"
                                $debuggerValue = "C:\Program Files\SystemInformer\SystemInformer.exe"
                                if (-not (Test-Path $regPath)) {
                                    New-Item -Path $regPath -Force | Out-Null
                                }
                                Set-ItemProperty -Path $regPath -Name "Debugger" -Value $debuggerValue -Type String
                                Write-Host "Registry key added successfully. Task Manager will now use SystemInformer."
                            } catch {
                                Write-Host "Error adding registry key: $($_.Exception.Message)"
                            }
                        } else {
                            Write-Host "Registry key addition skipped."
                        }
                    } catch {
                        Write-Host "Error installing SystemInformer: $($_.Exception.Message)"
                    }
                } elseif ($miscInput -eq '3') {
                    $baseUrl = "https://files.itzemoji.tech/regfiles/"
                    while ($true) {
                        try {
                            $response = Invoke-WebRequest -Uri $baseUrl -UseBasicParsing
                            $links = $response.Links | Where-Object { $_.href -like "*.reg" } | Select-Object -ExpandProperty href
                            if ($links.Count -eq 0) {
                                Write-Host "No .reg files found in the directory."
                            } else {
                                Write-Host "Available .reg files:"
                                for ($i = 0; $i -lt $links.Count; $i++) {
                                    Write-Host "$($i + 1): $($links[$i])"
                                }
                            }
                            $input = Read-Host "Enter the number of the file to apply, 'a' to apply all, 'c' to clear screen, 'q' to quit, or press Enter to reload"
                            if ($input -eq 'q') {
                                break
                            } elseif ($input -eq 'c') {
                                Clear-Host
                                continue
                            } elseif ($input -eq '') {
                                continue
                            } elseif ($input -eq 'a') {
                                foreach ($file in $links) {
                                    $fullUrl = $baseUrl + $file
                                    $tempPath = [System.IO.Path]::GetTempFileName() + ".reg"
                                    Invoke-WebRequest -Uri $fullUrl -OutFile $tempPath
                                    Start-Process reg.exe -ArgumentList "import `"$tempPath`"" -Wait -NoNewWindow
                                    Remove-Item $tempPath -Force
                                    Write-Host "$file applied successfully."
                                }
                            } else {
                                try {
                                    $num = [int]$input
                                    if ($num -ge 1 -and $num -le $links.Count) {
                                        $selectedFile = $links[$num - 1]
                                        $fullUrl = $baseUrl + $selectedFile
                                        $tempPath = [System.IO.Path]::GetTempFileName() + ".reg"
                                        Invoke-WebRequest -Uri $fullUrl -OutFile $tempPath
                                        Start-Process reg.exe -ArgumentList "import `"$tempPath`"" -Wait -NoNewWindow
                                        Remove-Item $tempPath -Force
                                        Write-Host "$selectedFile applied successfully."
                                    } else {
                                        Write-Host "Invalid input. Please enter a valid number."
                                    }
                                } catch {
                                    Write-Host "Error: Please enter a valid number."
                                }
                            }
                        } catch {
                            Write-Host "Error fetching file list or applying file: $($_.Exception.Message)"
                        }
                    }
                } elseif ($miscInput -eq '4') {
                    # Manage Services submenu
                    while ($true) {
                        try {
                            $input = Read-Host "Enter a service name (or partial name) to search, 'i' to import, 'e' to export, 'c' to clear screen, 'q' to quit, or press Enter to repeat"
                            if ($input -eq 'q') {
                                break
                            } elseif ($input -eq 'c') {
                                Clear-Host
                                continue
                            } elseif ($input -eq '') {
                                continue
                            } elseif ($input -eq 'e') {
                                try {
                                    Write-Host "Collecting service data..."
                                    $services = Get-WmiObject -Class Win32_Service -ErrorAction Stop
                                    if (-not $services) {
                                        Write-Host "Error: Get-WmiObject Win32_Service returned no data."
                                        $debugFile = [System.IO.Path]::GetTempFileName() + ".txt"
                                        "No services returned by Get-WmiObject" | Out-File -FilePath $debugFile -Encoding UTF8
                                        Write-Host "Debug info saved to $debugFile."
                                        continue
                                    }
                                    $serviceData = @()
                                    foreach ($service in $services) {
                                        $name = $service.Name
                                        if (-not $name) {
                                            Write-Host "Debug: Skipping service with null Name."
                                            continue
                                        }
                                        $status = if ($service.State -eq "Running") { "Running" } else { "Stopped" }
                                        $startType = switch ($service.StartMode) {
                                            "Auto" { "Automatic" }
                                            "Manual" { "Manual" }
                                            "Disabled" { "Disabled" }
                                            default { "Unknown" }
                                        }
                                        $serviceData += [PSCustomObject]@{
                                            Name = $name
                                            Status = $status
                                            StartupType = $startType
                                        }
                                    }
                                    if ($serviceData.Count -eq 0) {
                                        Write-Host "No valid service data found. Export aborted."
                                        $debugFile = [System.IO.Path]::GetTempFileName() + ".txt"
                                        $services | Format-Table Name, State, StartMode -AutoSize | Out-File -FilePath $debugFile -Encoding UTF8
                                        Write-Host "Raw service data saved to $debugFile for debugging."
                                        continue
                                    }
                                    Write-Host "Exported $($serviceData.Count) services."
                                    $fileType = Read-Host "Enter output type (json/j=JSON, yaml/y=YAML, gist/g=GitHub Gist, pastebin/p=Pastebin, or q to cancel)"
                                    $fileType = $fileType.ToLower()
                                    if ($fileType -eq 'q') {
                                        continue
                                    }
                                    $fileTypeMap = @{
                                        'json' = 'json'
                                        'j' = 'json'
                                        'yaml' = 'yaml'
                                        'y' = 'yaml'
                                        'gist' = 'gist'
                                        'g' = 'gist'
                                        'pastebin' = 'pastebin'
                                        'p' = 'pastebin'
                                    }
                                    if (-not $fileTypeMap.ContainsKey($fileType)) {
                                        Write-Host "Invalid output type. Please enter json, j, yaml, y, gist, g, pastebin, or p."
                                        continue
                                    }
                                    $extension = $fileTypeMap[$fileType]
                                    if ($extension -in @('json', 'yaml')) {
                                        $fileLocation = Read-Host "Enter output file location (e.g., C:\Users\YourName\Desktop, or q to cancel)"
                                        if ($fileLocation -eq 'q') {
                                            continue
                                        }
                                        $fileName = Read-Host "Enter output file name (without extension, or q to cancel)"
                                        if ($fileName -eq 'q') {
                                            continue
                                        }
                                        try {
                                            if (-not (Test-Path -Path $fileLocation)) {
                                                New-Item -Path $fileLocation -ItemType Directory -Force | Out-Null
                                                Write-Host "Created directory: $fileLocation"
                                            }
                                        } catch {
                                            Write-Host "Error creating directory '$fileLocation': $($_.Exception.Message)"
                                            continue
                                        }
                                        $filePath = Join-Path $fileLocation "$fileName.$extension"
                                        try {
                                            if ($extension -eq 'yaml') {
                                                if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
                                                    Install-Module -Name powershell-yaml -Scope CurrentUser -Force -Confirm:$false
                                                }
                                                Import-Module powershell-yaml
                                                $serviceData | ConvertTo-Yaml | Out-File -FilePath $filePath -Encoding UTF8 -ErrorAction Stop
                                            } elseif ($extension -eq 'json') {
                                                $serviceData | ConvertTo-Json | Out-File -FilePath $filePath -Encoding UTF8 -ErrorAction Stop
                                            }
                                            Write-Host "Service states exported to $filePath."
                                        } catch {
                                            Write-Host "Error saving file to '$filePath': $($_.Exception.Message)"
                                        }
                                    } elseif ($extension -eq 'gist') {
                                        $fileName = Read-Host "Enter Gist file name (e.g., services.json, or q to cancel)"
                                        if ($fileName -eq 'q') {
                                            continue
                                        }
                                        $accessToken = Read-Host "Enter GitHub Personal Access Token (or q to cancel)"
                                        if ($accessToken -eq 'q') {
                                            continue
                                        }
                                        $public = Read-Host "Make Gist public? (y/n, default n)"
                                        $isPublic = $public -eq 'y' -or $public -eq 'Y'
                                        $content = $serviceData | ConvertTo-Json
                                        $result = New-Gist -Content $content -FileName $fileName -AccessToken $accessToken -IsPublic $isPublic
                                        if ($result) {
                                            Write-Host "Service states exported to Gist."
                                        }
                                    } elseif ($extension -eq 'pastebin') {
                                        $title = Read-Host "Enter Pastebin title (or q to cancel)"
                                        if ($title -eq 'q') {
                                            continue
                                        }
                                        $apiKey = Read-Host "Enter Pastebin API key (or q to cancel)"
                                        if ($apiKey -eq 'q') {
                                            continue
                                        }
                                        $usePassword = Read-Host "Use a password for Pastebin? (y/n, default n)"
                                        $password = $null
                                        $userKey = ""
                                        if ($usePassword -eq 'y' -or $usePassword -eq 'Y') {
                                            $passwordChoice = Read-Host "Enter a password or press Enter to generate a random one"
                                            if ($passwordChoice) {
                                                $password = $passwordChoice
                                            } else {
                                                $password = New-RandomPassword
                                            }
                                            $usePrivate = Read-Host "Create as private paste? (y/n, default n; requires api_user_key)"
                                            if ($usePrivate -eq 'y' -or $usePrivate -eq 'Y') {
                                                $userKey = Read-Host "Enter Pastebin api_user_key (or q to cancel)"
                                                if ($userKey -eq 'q') {
                                                    continue
                                                }
                                            }
                                        }
                                        $expire = Read-Host "Enter Pastebin expiration (N=Never, 10M=10 Minutes, 1H=1 Hour, 1D=1 Day, 1W=1 Week, 2W=2 Weeks, 1M=1 Month, 6M=6 Months, 1Y=1 Year, default 1M)"
                                        if (-not $expire) { $expire = "1M" }
                                        if ($expire -notin @("N", "10M", "1H", "1D", "1W", "2W", "1M", "6M", "1Y")) {
                                            Write-Host "Invalid expiration, using default 1M."
                                            $expire = "1M"
                                        }
                                        $content = $serviceData | ConvertTo-Json
                                        $result = New-Pastebin -Content $content -Title $title -ApiKey $apiKey -Password $password -UserKey $userKey -ExpireDate $expire
                                        if ($result) {
                                            Write-Host "Service states exported to Pastebin."
                                        }
                                    }
                                } catch {
                                    Write-Host "Error collecting services: $($_.Exception.Message)"
                                    $debugFile = [System.IO.Path]::GetTempFileName() + ".txt"
                                    "WMI Error: $($_.Exception.Message)" | Out-File -FilePath $debugFile -Encoding UTF8
                                    Write-Host "Debug info saved to $debugFile."
                                    continue
                                }
                            } elseif ($input -eq 'i') {
                                try {
                                    $filePath = Read-Host "Import service states: Enter URL or local file path (or q to cancel)"
                                    if ($filePath -eq 'q') {
                                        continue
                                    }
                                    $content = if ($filePath -match '^https?://') {
                                        (Invoke-WebRequest -Uri $filePath -UseBasicParsing).Content
                                    } else {
                                        Get-Content -Path $filePath -Raw -ErrorAction Stop
                                    }
                                    $fileType = if ($filePath -match '\.ya?ml$') { 'yaml' }
                                                elseif ($filePath -match '\.json$') { 'json' }
                                                else {
                                                    Read-Host "Enter file type (json/j=JSON, yaml/y=YAML, or q to cancel)"
                                                }
                                    $fileType = $fileType.ToLower()
                                    if ($fileType -eq 'q') {
                                        continue
                                    }
                                    $fileTypeMap = @{
                                        'json' = 'json'
                                        'j' = 'json'
                                        'yaml' = 'yaml'
                                        'y' = 'yaml'
                                    }
                                    if (-not $fileTypeMap.ContainsKey($fileType)) {
                                        Write-Host "Invalid file type. Please enter json, j, yaml, or y."
                                        continue
                                    }
                                    $fileType = $fileTypeMap[$fileType]
                                    $services = if ($fileType -eq 'yaml') {
                                        if (-not (Get-Module -ListAvailable -Name powershell-yaml)) {
                                            Install-Module -Name powershell-yaml -Scope CurrentUser -Force -Confirm:$false
                                        }
                                        Import-Module powershell-yaml
                                        ConvertFrom-Yaml -Yaml $content
                                    } elseif ($fileType -eq 'json') {
                                        ConvertFrom-Json -InputObject $content
                                    }
                                    foreach ($service in $services) {
                                        $serviceName = $service.Name
                                        try {
                                            $existingService = Get-Service -Name $serviceName -ErrorAction Stop
                                            if ($service.StartupType -in @('Automatic', 'Manual', 'Disabled')) {
                                                Set-Service -Name $serviceName -StartupType $service.StartupType -ErrorAction Stop
                                                Write-Host "Set $serviceName startup type to $($service.StartupType)."
                                            }
                                            if ($service.Status -eq 'Running' -and $existingService.Status -ne 'Running') {
                                                Start-Service -Name $serviceName -ErrorAction Stop
                                                Write-Host "Started $serviceName."
                                            } elseif ($service.Status -eq 'Stopped' -and $existingService.Status -eq 'Running') {
                                                Stop-Service -Name $serviceName -Force -ErrorAction Stop
                                                Write-Host "Stopped $serviceName."
                                            }
                                        } catch {
                                            Write-Host "Service $serviceName not found, skipping."
                                        }
                                    }
                                    Write-Host "Service states import completed."
                                } catch {
                                    Write-Host "Error importing services: $($_.Exception.Message)"
                                }
                            } else {
                                $services = Get-Service -Name "*$input*" -ErrorAction Stop | Sort-Object DisplayName
                                if ($services.Count -eq 0) {
                                    Write-Host "No services found matching '$input'."
                                    continue
                                }
                                Write-Host "Matching services:"
                                for ($i = 0; $i -lt $services.Count; $i++) {
                                    $status = $services[$i].Status
                                    $startupType = $services[$i].StartType
                                    if ($startupType -eq "AutomaticDelayedStart") { $startupType = "Automatic" }
                                    Write-Host "$($i + 1): $($services[$i].DisplayName) (Status: $status, Startup: $startupType)"
                                }
                                $selectInput = Read-Host "Enter the number of the service to manage, 'c' to clear screen, 'q' to quit, or press Enter to search again"
                                if ($selectInput -eq 'q') {
                                    break
                                } elseif ($selectInput -eq 'c') {
                                    Clear-Host
                                    continue
                                } elseif ($selectInput -eq '') {
                                    continue
                                }
                                try {
                                    $num = [int]$selectInput
                                    if ($num -ge 1 -and $num -le $services.Count) {
                                        $selectedService = $services[$num - 1]
                                        $serviceName = $selectedService.Name
                                        $serviceStatus = $selectedService.Status
                                        $serviceStartupType = $selectedService.StartType
                                        if ($serviceStartupType -eq "AutomaticDelayedStart") { $serviceStartupType = "Automatic" }
                                        while ($true) {
                                            Write-Host "Managing: $($selectedService.DisplayName) (Status: $serviceStatus, Startup: $serviceStartupType)"
                                            Write-Host "Options:"
                                            if ($serviceStatus -eq 'Running') {
                                                Write-Host "1: Stop Service"
                                            } else {
                                                Write-Host "1: Start Service"
                                            }
                                            Write-Host "2: Change Startup Type"
                                            Write-Host "c: Clear Screen"
                                            Write-Host "q: Quit to service search"
                                            $actionInput = Read-Host "Enter your choice"
                                            if ($actionInput -eq 'q') {
                                                break
                                            } elseif ($actionInput -eq 'c') {
                                                Clear-Host
                                                continue
                                            } elseif ($actionInput -eq '1') {
                                                try {
                                                    if ($serviceStatus -eq 'Running') {
                                                        Stop-Service -Name $serviceName -Force -ErrorAction Stop
                                                        Write-Host "$($selectedService.DisplayName) stopped successfully."
                                                    } else {
                                                        Start-Service -Name $serviceName -ErrorAction Stop
                                                        Write-Host "$($selectedService.DisplayName) started successfully."
                                                    }
                                                    $selectedService = Get-Service -Name $serviceName -ErrorAction Stop
                                                    $serviceStatus = $selectedService.Status
                                                } catch {
                                                    Write-Host "Error modifying service: $($_.Exception.Message)"
                                                }
                                            } elseif ($actionInput -eq '2') {
                                                try {
                                                    Write-Host "Enter new startup type (a=Automatic, m=Manual, d=Disabled, or q to cancel)"
                                                    $startupInput = Read-Host
                                                    if ($startupInput -eq 'q') {
                                                        continue
                                                    }
                                                    $startupTypeMap = @{
                                                        'a' = 'Automatic'
                                                        'm' = 'Manual'
                                                        'd' = 'Disabled'
                                                    }
                                                    $startupInputLower = $startupInput.ToLower()
                                                    if ($startupTypeMap.ContainsKey($startupInputLower)) {
                                                        $selectedStartupType = $startupTypeMap[$startupInputLower]
                                                        Set-Service -Name $serviceName -StartupType $selectedStartupType -ErrorAction Stop
                                                        Write-Host "$($selectedService.DisplayName) startup type set to $selectedStartupType."
                                                        $selectedService = Get-Service -Name $serviceName -ErrorAction Stop
                                                        $serviceStartupType = $selectedService.StartType
                                                        if ($serviceStartupType -eq "AutomaticDelayedStart") { $serviceStartupType = "Automatic" }
                                                    } else {
                                                        Write-Host "Invalid startup type. Please enter a, m, or d."
                                                    }
                                                } catch {
                                                    Write-Host "Error setting startup type: $($_.Exception.Message)"
                                                }
                                            } else {
                                                Write-Host "Invalid choice. Please try again."
                                            }
                                        }
                                    } else {
                                        Write-Host "Invalid input. Please enter a valid number."
                                    }
                                } catch {
                                    Write-Host "Error: Please enter a valid number."
                                }
                            }
                        } catch {
                            Write-Host "Error searching services: $($_.Exception.Message)"
                        }
                    }
                } elseif ($miscInput -eq '5') {
                    # Run CrapFixer
                    try {
                        Write-Host "Fetching latest CrapFixer release from GitHub..."
                        $releaseUrl = "https://api.github.com/repos/builtbybel/CrapFixer/releases/latest"
                        $releaseData = Invoke-RestMethod -Uri $releaseUrl -UseBasicParsing
                        $zipAsset = $releaseData.assets | Where-Object { $_.name -like "*.zip" } | Select-Object -First 1
                        if (-not $zipAsset) {
                            Write-Host "Error: No .zip file found in the latest CrapFixer release."
                            continue
                        }
                        $zipUrl = $zipAsset.browser_download_url
                        $zipName = $zipAsset.name
                        $tempZipPath = Join-Path $env:TEMP "$zipName"
                        $extractPath = Join-Path $env:TEMP "CrapFixer"
                        
                        Write-Host "Downloading $zipName..."
                        Invoke-WebRequest -Uri $zipUrl -OutFile $tempZipPath -UseBasicParsing
                        
                        Write-Host "Extracting $zipName..."
                        if (Test-Path $extractPath) {
                            Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                        }
                        Expand-Archive -Path $tempZipPath -DestinationPath $extractPath -Force
                        Remove-Item $tempZipPath -Force
                        
                        $exePath = Join-Path $extractPath "CrapFixer.exe"
                        if (-not (Test-Path $exePath)) {
                            Write-Host "Error: CrapFixer.exe not found in extracted files."
                            continue
                        }
                        
                        Write-Host "Running CrapFixer..."
                        Start-Process -FilePath $exePath -Verb RunAs -Wait
                        Write-Host "CrapFixer completed."
                        
                        # Clean up extracted files
                        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                    } catch {
                        Write-Host "Error running CrapFixer: $($_.Exception.Message)"
                    }
                } elseif ($miscInput -eq '6') {
                    # Run NAppClean
                    try {
                        Write-Host "Fetching latest NAppClean release from GitHub..."
                        $releaseUrl = "https://api.github.com/repos/builtbybel/NAppClean/releases/latest"
                        $releaseData = Invoke-RestMethod -Uri $releaseUrl -UseBasicParsing
                        $exeAsset = $releaseData.assets | Where-Object { $_.name -eq "NAppClean.exe" } | Select-Object -First 1
                        $txtAsset = $releaseData.assets | Where-Object { $_.name -eq "PolicyPatterns.txt" } | Select-Object -First 1
                        if (-not $exeAsset -or -not $txtAsset) {
                            Write-Host "Error: NAppClean.exe or PolicyPatterns.txt not found in the latest release."
                            continue
                        }
                        $exeUrl = $exeAsset.browser_download_url
                        $txtUrl = $txtAsset.browser_download_url
                        $extractPath = Join-Path $env:TEMP "NAppClean"
                        $exePath = Join-Path $extractPath "NAppClean.exe"
                        $txtPath = Join-Path $extractPath "PolicyPatterns.txt"
                        
                        # Create temp folder
                        if (-not (Test-Path $extractPath)) {
                            New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
                        } else {
                            Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                            New-Item -Path $extractPath -ItemType Directory -Force | Out-Null
                        }
                        
                        Write-Host "Downloading NAppClean.exe..."
                        Invoke-WebRequest -Uri $exeUrl -OutFile $exePath -UseBasicParsing
                        Write-Host "Downloading PolicyPatterns.txt..."
                        Invoke-WebRequest -Uri $txtUrl -OutFile $txtPath -UseBasicParsing
                        
                        if (-not (Test-Path $exePath) -or -not (Test-Path $txtPath)) {
                            Write-Host "Error: Failed to download NAppClean.exe or PolicyPatterns.txt."
                            continue
                        }
                        
                        Write-Host "Running NAppClean..."
                        Start-Process -FilePath $exePath -Verb RunAs -Wait
                        Write-Host "NAppClean completed."
                        
                        # Clean up extracted files
                        Remove-Item $extractPath -Recurse -Force -ErrorAction SilentlyContinue
                    } catch {
                        Write-Host "Error running NAppClean: $($_.Exception.Message)"
                    }
                } else {
                    Write-Host "Invalid choice. Please try again."
                }
            }
        } else {
            Write-Host "Invalid choice. Please try again."
        }
    }
}

# Check if running via iwr | iex and invoke as function
if ($MyInvocation.Line -like '*iex*') {
    Invoke-SuperTool
} else {
    Invoke-SuperTool
    exit
}
