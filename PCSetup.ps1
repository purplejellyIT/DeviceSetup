Set-ExecutionPolicy remotesigned
function SetPCName {
    Add-Type -AssemblyName Microsoft.VisualBasic
    $ComputerName = [Microsoft.VisualBasic.Interaction]::InputBox('Enter desired Computer Name', 'Computer Name')
    Rename-Computer -NewName "$ComputerName"
}

function InstallChoco {
            # Ask for elevated permissions if required
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit
    }    
    Set-ExecutionPolicy Bypass -Scope Process -Force; iex ((New-Object System.Net.WebClient).DownloadString('https://chocolatey.org/install.ps1'))
    choco install adobereader googlechrome -y
    choco install microsoft-office-deployment --params="'/Channel:Monthly /Language:en-us /64bit /Product:O365BusinessRetail /Exclude:Lync,Groove'" -y
}

function ReclaimWindows10 {

        # Ask for elevated permissions if required
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit
    }
}

    ##########
    # Privacy Settings
    ##########

    # Disable Telemetry
    Write-Host "Disabling Telemetry..."
    Set-ItemProperty -Path "HKLM:\Software\Policies\Microsoft\Windows\DataCollection" -Name "AllowTelemetry" -Type DWord -Value 0

    # Disable Wi-Fi Sense
    Write-Host "Disabling Wi-Fi Sense..."
    If (!(Test-Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting")) {
        New-Item -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowWiFiHotSpotReporting" -Name "Value" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\PolicyManager\default\WiFi\AllowAutoConnectToWiFiSenseHotspots" -Name "Value" -Type DWord -Value 0
  
    # Disable Location Tracking
    Write-Host "Disabling Location Tracking..."
    Set-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Sensor\Overrides\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" -Name "SensorPermissionState" -Type DWord -Value 0
    Set-ItemProperty -Path "HKLM:\System\CurrentControlSet\Services\lfsvc\Service\Configuration" -Name "Status" -Type DWord -Value 0
   
    # Disable Feedback
    Write-Host "Disabling Feedback..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Siuf\Rules")) {
        New-Item -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Siuf\Rules" -Name "NumberOfSIUFInPeriod" -Type DWord -Value 0

    # Disable Advertising ID
    Write-Host "Disabling Advertising ID..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" -Name "Enabled" -Type DWord -Value 0

    # Disable Cortana
    Write-Host "Disabling Cortana..."
    If (!(Test-Path "HKCU:\Software\Microsoft\Personalization\Settings")) {
        New-Item -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Personalization\Settings" -Name "AcceptedPrivacyPolicy" -Type DWord -Value 0
    If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization")) {
        New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitTextCollection" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization" -Name "RestrictImplicitInkCollection" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore")) {
        New-Item -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Force | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\InputPersonalization\TrainedDataStore" -Name "HarvestContacts" -Type DWord -Value 0

    # Restrict Windows Update P2P only to local network
    Write-Host "Restricting Windows Update P2P only to local network..."
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization\Config" -Name "DODownloadMode" -Type DWord -Value 1
    If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization")) {
        New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\DeliveryOptimization" -Name "SystemSettingsDownloadMode" -Type DWord -Value 3

    # Stop and disable Diagnostics Tracking Service
    Write-Host "Stopping and disabling Diagnostics Tracking Service..."
    Stop-Service "DiagTrack"
    Set-Service "DiagTrack" -StartupType Disabled

    ##########
    # Service Tweaks
    ##########

    # Raise UAC level
	Write-Host "Setting UAC level..."
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "ConsentPromptBehaviorAdmin" -Type DWord -Value 5
    Set-ItemProperty -Path "HKLM:\Software\Microsoft\Windows\CurrentVersion\Policies\System" -Name "PromptOnSecureDesktop" -Type DWord -Value 1


    ##########
    # UI Tweaks
    ##########

    # Disable Action Center
    Write-Host "Disabling Action Center..."
    If (!(Test-Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer")) {
      New-Item -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" | Out-Null
    }
    Set-ItemProperty -Path "HKCU:\Software\Policies\Microsoft\Windows\Explorer" -Name "DisableNotificationCenter" -Type DWord -Value 1
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\PushNotifications" -Name "ToastEnabled" -Type DWord -Value 0

     # Disable Autoplay
    Write-Host "Disabling Autoplay..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" -Name "DisableAutoplay" -Type DWord -Value 1

    # Disable Autorun for all drives
     Write-Host "Disabling Autorun for all drives..."
     If (!(Test-Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer")) {
       New-Item -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" | Out-Null
    }
     Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" -Name "NoDriveTypeAutoRun" -Type DWord -Value 255

    # Hide Search button / box
    Write-Host "Hiding Search Box / Button..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Search" -Name "SearchboxTaskbarMode" -Type DWord -Value 0

    # Hide Task View button
    Write-Host "Hiding Task View button..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "ShowTaskViewButton" -Type DWord -Value 0

    # Change default Explorer view to "Computer"
    Write-Host "Changing default Explorer view to `"Computer`"..."
    Set-ItemProperty -Path "HKCU:\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" -Name "LaunchTo" -Type DWord -Value 1

    # Uninstall default Microsoft applications
    Write-Host "Uninstalling default Microsoft applications..."
    Get-AppxPackage "Microsoft.3DBuilder" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingFinance" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingNews" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingSports" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.BingWeather" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Getstarted" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftOfficeHub" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.MicrosoftSolitaireCollection" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Office.OneNote" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.People" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.SkypeApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Windows.Photos" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsAlarms" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsCamera" | Remove-AppxPackage
    Get-AppxPackage "microsoft.windowscommunicationsapps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsMaps" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsPhone" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.WindowsSoundRecorder" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.XboxApp" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneMusic" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ZuneVideo" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.AppConnector" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.ConnectivityStore" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Office.Sway" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.Messaging" | Remove-AppxPackage
    Get-AppxPackage "Microsoft.CommsPhone" | Remove-AppxPackage
    Get-AppxPackage "9E2F88E3.Twitter" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushSodaSaga" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushSaga" | Remove-AppxPackage
    Get-AppxPackage "king.com.CandyCrushFriends" | Remove-AppxPackage    

function LayoutDesign {
    If (!([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]"Administrator")) {
        Start-Process powershell.exe "-NoProfile -ExecutionPolicy Bypass -File `"$PSCommandPath`"" -Verb RunAs
        Exit
    }
    Import-StartLayout -LayoutPath "c:\build\PC-Build-Script-master\LayoutModification.xml" -MountPath $env:SystemDrive\
    dism /online /Import-DefaultAppAssociations:c:\build\PC-Build-Script-master\AppAssociations.xml
}

function IntechPower {
    POWERCFG -DUPLICATESCHEME 381b4222-f694-41f0-9685-ff5bb260df2e 381b4222-f694-41f0-9685-ff5bb260aaaa
    POWERCFG -CHANGENAME 381b4222-f694-41f0-9685-ff5bb260aaaa "PurpleJelly Power Management"
    POWERCFG -SETACTIVE 381b4222-f694-41f0-9685-ff5bb260aaaa
    POWERCFG -Change -monitor-timeout-ac 15
    POWERCFG -CHANGE -monitor-timeout-dc 0
    POWERCFG -CHANGE -disk-timeout-ac 30
    POWERCFG -CHANGE -disk-timeout-dc 0
    POWERCFG -CHANGE -standby-timeout-ac 0
    POWERCFG -CHANGE -standby-timeout-dc 0
    POWERCFG -CHANGE -hibernate-timeout-ac 0
    POWERCFG -CHANGE -hibernate-timeout-dc 0
	powercfg -h off
	REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V HiberbootEnabled /T REG_dWORD /D 0 /F
	
}

function AutomateInstall{
msiexec /i "c:\PurpleJelly\DeviceSetup-main\Agent_Install.msi" /quiet
}

function DisableFastStartup{
powercfg -h off
REG ADD "HKLM\SYSTEM\CurrentControlSet\Control\Session Manager\Power" /V HiberbootEnabled /T REG_dWORD /D 0 /F
}

function PoolTimeSync{
w32TM /config /syncfromflags:manual /manualpeerlist:uk.pool.ntp.org
w32tm /config /update
w32tm /resync
}

function Bitlocker{
Start-Process "cmd.exe" "/c C:\PurpleJelly\DeviceSetup-main\BitlokerConfigurator.bat"
}

function Reboot{
shutdown -r -f -t 300 -c "Automatic Restart in 5 mins"
}


SetPCName
InstallChoco
LayoutDesign
ReclaimWindows10
IntechPower
DisableFastStartup
PoolTimeSync
AutomateInstall
Bitlocker
#Reboot

