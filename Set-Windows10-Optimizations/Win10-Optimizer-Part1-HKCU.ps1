if ($PSVersionTable.BuildVersion.Major -lt 10)
{
    Write-Host This OS is not supported -ForegroundColor Red
    exit
}
$ErrorActionPreference = "SilentlyContinue"

####################################
#
# 1. Applying HKCU Settings to Registry
#
Write-Host "1. Applying HKCU Settings to Registry"
# Load default user registry
reg load "hklm\temp" "C:\Users\Default\NTUSER.DAT"
if ($?)
{
	Write-Host "SUCCESS: The default hive is now loaded"
} 
else 
{
	SchTasks.exe /Create /TN "DefaultUserRegLoad" /SC ONSTART /TR "reg.exe load hklm\temp C:\users\default\NTUSER.DAT" /RU "System" /RL HIGHEST >$null
	SchTasks.exe /Run /TN "DefaultUserRegLoad" >$null
	SchTasks.exe /delete /tn "DefaultUserRegLoad" /F >$null
	Start-Sleep 1
	reg query hklm\temp > $null
	if ($?)
	{
		Write-Host "SUCCESS: The default hive is now loaded"
	}
}


# Change Explorer View to This PC
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "LaunchTo" /t REG_DWORD /d "1" /f >$null

# OneDrive (see #6)
reg delete "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Run" /v "OneDriveSetup" /f >$null 2>$null
reg delete "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Desktop\NameSpace\{018D5C66-4533-4307-9B53-224DE2ED1FE6}" /f >$null 2>$null

# Disable autoplay for all media and devices & Disable Autorun
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\AutoplayHandlers" /v "DisableAutoplay" /t REG_DWORD /d "1" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "NoDriveTypeAutoRun" /t REG_DWORD /d "255" /f >$null

# Disable Feedback
reg add "hklm\temp\Software\Microsoft\Siuf\Rules" /v "NumberOfSIUFInPeriod" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Siuf\Rules" /v "PeriodInNanoSeconds" /t REG_DWORD /d "0" /f >$null

# Disable show most used apps at start menu
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackProgs" /t REG_DWORD /d "0" /f >$null

# Disable show recent items at start menu
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Start_TrackDocs" /t REG_DWORD /d "0" /f >$null

# Show recently used files & folders in Quick Access
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowRecent" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "ShowFrequent" /t REG_DWORD /d "0" /f >$null

# RSS Feeds - Disable
reg add "hklm\temp\Software\Microsoft\Feeds" /v "SyncStatus" /t REG_DWORD /d "0" /f >$null

# Disable Bing Search
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Search" /v "BingSearchEnabled" /t REG_DWORD /d "0" /f >$null

# Advertising Info disable
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\AdvertisingInfo" /v "Enabled" /t REG_DWORD /d "0" /f >$null

# Disable Cortana
reg add "hklm\temp\Software\Microsoft\Personalization\Settings" /v "AcceptedPrivacyPolicy" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\InputPersonalization" /v "RestrictImplicitTextCollection" /t REG_DWORD /d "1" /f >$null
reg add "hklm\temp\Software\Microsoft\InputPersonalization" /v "RestrictImplicitInkCollection" /t REG_DWORD /d "1" /f >$null
reg add "hklm\temp\Software\Microsoft\InputPersonalization\TrainedDataStore" /v "HarvestContacts" /t REG_DWORD /d "0" /f >$null
# Cortana history disable
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Search" /v "HistoryViewEnabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Search" /v "DeviceHistoryEnabled" /t REG_DWORD /d "0" /f >$null

# Turn On Quiet Hours Action Center
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Notifications\Settings" /v "NOC_GLOBAL_SETTING_TOASTS_ENABLED" /t REG_DWORD /d "0" /f >$null

# Disable Startup Run
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "OneDrive"  /t REG_BINARY /d "0300000064A102EF4C3ED101" /f >$null
reg add "HKCU\Software\Microsoft\Windows\CurrentVersion\Explorer\StartupApproved\Run" /v "OneDrive"  /t REG_BINARY /d "0300000064A102EF4C3ED101" /f >$null

# Disable Access to Devices to Modern Apps
# location sensor:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Camera:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E5323777-F976-4f5b-9B55-B94699C46E44}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Mic:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2EEF81BE-33FA-4800-9670-1CD474972C3F}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Calendar: 
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{D89823BA-7180-4B81-B50C-7E471E6121A3}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# SMS, MMS:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{992AFA70-6F47-4148-B3E9-3003349C1548}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Wireless interfaces:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{A8804298-2D5F-42E3-9531-9C8C39EB29CE}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Account info:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{C1D23ACC-752B-43E5-8448-8D0E519CD6D6}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Diagnostics:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{2297E4E2-5DBE-466D-A12B-0F8286F0D9CA}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Call History:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{8BC668CF-7728-45BD-93F8-CF2B3B41D7AB}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Email:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{9231CB4C-BF57-4AF3-8C55-FDA7BFCC04C5}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Tasks:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{E390DF20-07DF-446D-B962-F5C953062741}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# App notifications:
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{52079E78-A92B-413F-B213-E8FE35712E72}" /v "Value" /t REG_SZ /d "Deny" /f >$null
# Disable apps share and sync non-explicitly paired wireless devices over uPnP
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\LooselyCoupled" /v "Value" /t REG_SZ /d "Deny" /f >$null
# ..Settings
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync" /v "SyncPolicy" /t REG_DWORD /d "5" /f >$null
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync" "BackupPolicy" /t REG_DWORD /d "60" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Accessibility" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\AppSync" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\BrowserSettings" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Credentials" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\DesktopTheme" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Language" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Personalization" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\StartLayout" /v "Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\SettingSync\Groups\Windows" /v "Enabled" /t REG_DWORD /d "0" /f >$null
# ..Location
reg add "hklm\temp\Software\Microsoft\Windows NT\CurrentVersion\Sensor\Permissions\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "SensorPermissionState" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\DeviceAccess\Global\{BFA794E4-F964-4FDB-90F6-51056BFE4B44}" /v "Value" /t REG_SZ /d "Deny" /f >$null

# Disabling typing info
reg add "hklm\temp\Software\Microsoft\Input\TIPC" /v "Enabled" /t REG_DWORD /d "0" /f >$null 

# Disable access to language list
reg add "hklm\temp\Control Panel\International\User Profile" /v "HttpAcceptLanguageOptOut" /t REG_DWORD /d "0" /f >$null

# Smart Screen disable
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\AppHost" /v "EnableWebContentEvaluation" /t REG_DWORD /d "0" /f >$null 

# Push notification disable
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\PushNotifications" /v "ToastEnabled" /t REG_DWORD /d "0" /f >$null 

# Show known file extensions
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "HideFileExt" /t REG_DWORD /d "0" /f >$null

# Show hidden files
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "Hidden" /t REG_DWORD /d "1" /f >$null

# Hide sync provider notifications 
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >$null

# Disable simple sharing wizard
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SharingWizardOn" /t REG_DWORD /d "0" /f >$null

# Show System Protected files
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced" /v "SuperHidden" /t REG_DWORD /d "1" /f >$null

# Disable Network Thumbs
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Policies\Explorer" /v "DisableThumbnailsOnNetworkFolders" /t REG_DWORD /d "1" /f >$null

# Disable Let apps run in the background, since Creators Update
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" /v "GlobalUserDisabled" /t REG_DWORD /d "1" /f >$null
Get-ChildItem "hklm:\temp\Software\Microsoft\Windows\CurrentVersion\BackgroundAccessApplications" | ForEach-Object {
		Set-ItemProperty -Path $_.PsPath -Name "Disabled" -Type DWord -Value 1
		Set-ItemProperty -Path $_.PsPath -Name "DisabledByUser" -Type DWord -Value 1
	}

# Disable downloaded files from being blocked
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Policies\Attachments" /v "SaveZoneInformation" /t REG_DWORD /d "1" /f >$null

# Disable ADS
# https://winaero.com/blog/disable-ads-windows-10/
# Stop installing unwanted apps
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ContentDeliveryAllowed" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "OemPreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEnabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "PreInstalledAppsEverEnabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SilentInstalledAppsEnabled" /t REG_DWORD /d "0" /f >$null
# Start menu suggestions
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SystemPaneSuggestionsEnabled" /t REG_DWORD /d "0" /f >$null
# Ads in explorer
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "ShowSyncProviderNotifications" /t REG_DWORD /d "0" /f >$null
# Tips about Windows
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SoftLandingEnabled" /t REG_DWORD /d "0" /f >$null
# Locksreen images & tips
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenEnabled" /t REG_DWORD /d "0" /f >$null        # problems on logon
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "RotatingLockScreenOverlayEnabled" /t REG_DWORD /d "0" /f >$null # problems on logon
# 
# Various Ads disable
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContentEnabled" /t REG_DWORD /d "0" /f >$null
reg delete "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager\SuggestedApps" /f >$null 2>$null
# Welcome page
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-310093Enabled" /t REG_DWORD /d "0" /f >$null
# Settings ads
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338388Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338389Enabled" /t REG_DWORD /d "0" /f >$null
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\ContentDeliveryManager" /v "SubscribedContent-338393Enabled" /t REG_DWORD /d "0" /f >$null

# 1. Disable 3rd party ads for Enterprise
reg add "hklm\temp\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableThirdPartySuggestions" /t REG_DWORD /d "1" /f >$null
# 2. Disable Windows Spotlight notifications in Action Center
reg add "hklm\temp\Software\Policies\Microsoft\Windows\CloudContent" /v "DisableWindowsSpotlightOnActionCenter" /t REG_DWORD /d "1" /f >$null

# Disable Storage Sense
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\StorageSense\Parameters\StoragePolicy" /v "01" /t REG_DWORD /d "1" /f >$null

# Disable Shared Experiences
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\CDP" /v "RomeSdkChannelUserAuthzPolicy" /t REG_DWORD /d "0" /f >$null


### UI Settings
# Menu Show Delay Reduce
reg add "hklm\temp\Control Panel\Desktop" /v "MenuShowDelay" /t REG_SZ /d "200" /f >$null
# Hide Taskbar People icon
reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer\Advanced\People" /v "PeopleBand" /t REG_DWORD /d "0" /f >$null
# Show all tray icons
# reg add "hklm\temp\Software\Microsoft\Windows\CurrentVersion\Explorer" /v "EnableAutoTray" /t REG_DWORD /d "0" /f >$null 2>$null


# Unload Default User Registry
[gc]::Collect()
reg unload "hklm\temp" # >$null
if ($?)
{
	Write-Host "SUCCESS: The default hive is now unloaded"
}
else
{
	SchTasks.exe /Create /TN "DefaultUserRegUnload" /SC ONSTART /TR "reg.exe unload hklm\temp" /RU "System" /RL HIGHEST >$null
	SchTasks.exe /Run /TN "DefaultUserRegUnload" # >$null
	SchTasks.exe /delete /tn "DefaultUserRegUnload" /F >$null
	Start-Sleep 2
	reg query hklm\temp >$null
	if (!$?)
	{
		Write-Host "SUCCESS: The default hive is now unloaded"
		# icacls C:\Users\Default\NTUSER.DAT  /grant Everyone:RX
	}
	else 
	{
		Write-Host "ERROR: Default hive is not unloaded"
	}
}
