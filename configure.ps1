# Function to check if running as administrator
function Test-Admin {
    $currentUser = New-Object Security.Principal.WindowsPrincipal([Security.Principal.WindowsIdentity]::GetCurrent())
    return $currentUser.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
}

# If not running as admin, relaunch with elevation
if (-not (Test-Admin)) {
    $scriptPath = $PSCommandPath
    $isIex = $MyInvocation.Line -like '*iex*'
    if (-not $scriptPath -or $isIex) {
        try {
            $scriptContent = (Invoke-WebRequest -Uri "https://raw.githubusercontent.com/ItzEmoji/Powershell_Configure_Script/main/configure.ps1" -UseBasicParsing).Content
            $tempScript = [System.IO.Path]::GetTempFileName() + ".ps1"
            Set-Content -Path $tempScript -Value $scriptContent -Force
            $scriptPath = $tempScript
        } catch {
            Write-Host "Error creating temporary script file."
            if ($isIex) { return } else { exit }
        }
    }

    try {
        Start-Process powershell.exe -Verb RunAs -ArgumentList "-NoProfile -ExecutionPolicy Bypass -File `"$scriptPath`"" -Wait
        if ($isIex) { return } else { exit }
    } catch {
        Write-Host "Error restarting with UAC."
        if ($isIex) { return } else { exit }
    }
}

# Main menu loop
while ($true) {
    Write-Host "Welcome to SuperTool"
    Write-Host "Options:"
    Write-Host "1: Run WinUtil"
    Write-Host "2: Install Package Manager"
    Write-Host "3: Install SystemInformer"
    Write-Host "4: Registry Loader"
    Write-Host "q: Quit"
    $menuInput = Read-Host "Enter your choice"

    $isIex = $MyInvocation.Line -like '*iex*'
    if ($menuInput -eq 'q') {
        # Clean up temporary script if it exists
        if ($scriptPath -and $scriptPath -like "*.tmp.ps1") {
            Remove-Item $scriptPath -Force -ErrorAction SilentlyContinue
        }
        if ($isIex) { return } else { exit }
    } elseif ($menuInput -eq '1') {
        # Run WinUtil
        try {
            Invoke-RestMethod https://christitus.com/win | Invoke-Expression
        } catch {
            Write-Host "Error running WinUtil: $($_.Exception.Message)"
        }
    } elseif ($menuInput -eq '2') {
        # Package Manager submenu
        while ($true) {
            Write-Host "Choose a package manager to install:"
            Write-Host "1: Chocolatey"
            Write-Host "2: Scoop"
            Write-Host "q: Quit to main menu"
            $pkgInput = Read-Host "Enter your choice"

            if ($pkgInput -eq 'q') {
                break  # Return to main menu
            } elseif ($pkgInput -eq '1') {
                # Install Chocolatey
                try {
                    # Ensure execution policy allows script execution
                    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
                    if ($currentPolicy -ne 'RemoteSigned' -and $currentPolicy -ne 'Unrestricted' -and $currentPolicy -ne 'Bypass') {
                        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
                        Write-Host "Execution policy set to RemoteSigned for Chocolatey installation."
                    }

                    # Download and run Chocolatey installer
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
                # Install Scoop
                try {
                    # Ensure execution policy allows script execution
                    $currentPolicy = Get-ExecutionPolicy -Scope CurrentUser
                    if ($currentPolicy -ne 'RemoteSigned' -and $currentPolicy -ne 'Unrestricted' -and $currentPolicy -ne 'Bypass') {
                        Set-ExecutionPolicy -ExecutionPolicy RemoteSigned -Scope CurrentUser -Force
                        Write-Host "Execution policy set to RemoteSigned for Scoop installation."
                    }

                    # Download and run Scoop installer with -RunAsAdmin flag
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
    } elseif ($menuInput -eq '4') {
        # Registry Loader submenu
        $baseUrl = "https://files.itzemoji.tech/regfiles/"

        while ($true) {
            try {
                # Fetch the directory listing
                $response = Invoke-WebRequest -Uri $baseUrl -UseBasicParsing

                # Parse links for .reg files
                $links = $response.Links | Where-Object { $_.href -like "*.reg" } | Select-Object -ExpandProperty href

                if ($links.Count -eq 0) {
                    Write-Host "No .reg files found in the directory."
                } else {
                    Write-Host "Available .reg files:"
                    for ($i = 0; $i -lt $links.Count; $i++) {
                        Write-Host "$($i + 1): $($links[$i])"
                    }
                }

                # Prompt user
                $input = Read-Host "Enter the number of the file to apply, 'a' to apply all, 'q' to quit, or press Enter to reload"

                if ($input -eq 'q') {
                    break  # Return to main menu
                } elseif ($input -eq '') {
                    continue  # Reload the list
                } elseif ($input -eq 'a') {
                    # Apply all .reg files
                    foreach ($file in $links) {
                        $fullUrl = $baseUrl + $file
                        $tempPath = [System.IO.Path]::GetTempFileName() + ".reg"
                        Invoke-WebRequest -Uri $fullUrl -OutFile $tempPath
                        Start-Process reg.exe -ArgumentList "import `"$tempPath`"" -Wait -NoNewWindow
                        Remove-Item $tempPath -Force
                        Write-Host "$file applied successfully."
                    }
                } else {
                    # Check if input is a valid number
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
    } elseif ($menuInput -eq '3') {
        # Install SystemInformer
        try {
            Write-Host "Installing SystemInformer via winget..."
            Start-Process winget -ArgumentList "install --id SystemInformer.SystemInformer --silent --accept-package-agreements --accept-source-agreements" -Wait -NoNewWindow
            Write-Host "SystemInformer installed successfully."

            # Prompt user to add registry key for Task Manager replacement
            $response = Read-Host "Do you want to replace Task Manager with SystemInformer by adding a registry key? (y/n)"
            if ($response -eq 'y' -or $response -eq 'Y') {
                try {
                    $regPath = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\taskmgr.exe"
                    $debuggerValue = "C:\Program Files\SystemInformer\SystemInformer.exe"

                    # Create or update the registry key
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
    } else {
        Write-Host "Invalid choice. Please try again."
    }
}
