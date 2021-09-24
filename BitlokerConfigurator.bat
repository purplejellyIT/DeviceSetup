@echo off
echo Disabling the pre-set Encryption
manage-bde -off c:
echo Encryption will be turned back on after 10 Minutes, please let it auto resume.....
timeout 600 /nobreak
echo Checking Hardware compactibilites
wmic /namespace:\\root\cimv2\security\microsofttpm path win32_tpm get IsEnabled_InitialValue
wmic /namespace:\\root\cimv2\security\microsofttpm path win32_tpm get IsActivated_InitialValue
wmic /namespace:\\root\cimv2\security\microsofttpm path win32_tpm get IsOwned_InitialValue
manage-bde -status
echo Preparing partition for Bitlocker
powershell.exe -Command "BdeHdCfg.exe -target %SystemDrive% shrink >> C:\PurpleJelly\%computername%_bitlockerlog.txt"
echo Creating a recovery key (for emergency access only, stored in AD)
powershell.exe -Command "manage-bde.exe -protectors -add c: -recoverypassword >> C:\PurpleJelly\%computername%_bitlockerlog.txt"
echo Creating the TPM key (used to auto boot encrypted OS)
powershell.exe -Command "manage-bde.exe -protectors -add %SystemDrive% -tpm >> C:\PurpleJelly\%computername%_bitlockerlog.txt"
echo Enabling BitLocker Encryption
powershell.exe -Command "manage-bde.exe -on %systemdrive% >> C:\PurpleJelly\%computername%_bitlockerlog.txt"
timeout 10
echo Copying Bitlocker Log to BD-Server "\\bd-server\BitlockerLogs"
cd C:\PurpleJelly 
copy "*_bitlockerlog.txt" \\bd-server\BitlockerLogs
shutdown /r /f /t 300 /c "PC will restart in 300 Seconds, please allow it to Auto restart for Automate to install, Encryption will commence on the reboot.... Please make a copy of the Bitlocker log from C:\PurpleJelly to the USB"