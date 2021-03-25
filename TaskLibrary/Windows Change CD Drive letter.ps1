# Powershell
# change drive letter of CD
Write-Host "Changing drive letter for cdrom" -ForegroundColor Green
Get-WmiObject -Class Win32_volume -Filter 'DriveType=5' | Select-Object -First 1 | Set-WmiInstance -Arguments @{DriveLetter='B:'}