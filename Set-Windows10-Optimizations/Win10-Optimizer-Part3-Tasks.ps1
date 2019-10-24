if ($PSVersionTable.BuildVersion.Major -lt 10)
{
    Write-Host This OS is not supported -ForegroundColor Red
    exit
}
$ErrorActionPreference = "SilentlyContinue"

##################
#
# 3. Disabling Tasks
#
Write-Host "3. Disabling Tasks"

schtasks /Change /TN "Microsoft\Windows\AppID\SmartScreenSpecific" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\AitAgent" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\Microsoft Compatibility Appraiser" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\ProgramDataUpdater" /Disable 
schtasks /Change /TN "Microsoft\Windows\Application Experience\StartupAppTask" /Disable 
schtasks /Change /TN "Microsoft\Windows\Autochk\Proxy" /Disable 
schtasks /Change /tn "Microsoft\Windows\CloudExperienceHost\CreateObjectTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\Consolidator" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\KernelCeipTask" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\UsbCeip" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\BthSQM" /Disable 
schtasks /Change /TN "Microsoft\Windows\Customer Experience Improvement Program\HypervisorFlightingTask" /Disable 
schtasks /Change /TN "Microsoft\Windows\Feedback\Siuf\DmClient" /Disable
schtasks /Change /TN "Microsoft\Windows\Location\Notifications" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsToastTask" /Disable
schtasks /Change /TN "Microsoft\Windows\Maps\MapsUpdateTask" /Disable
schtasks /Change /TN "Microsoft\Windows\NetTrace\GatherNetworkInfo" /Disable 
schtasks /Change /TN "Microsoft\Windows\PI\Sqm-Tasks" /Disable 
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyMonitor" /Disable 
schtasks /Change /TN "Microsoft\Windows\Shell\FamilySafetyRefresh" /Disable 
schtasks /Change /TN "Microsoft\Windows\Windows Error Reporting\QueueReporting" /Disable 

####################
#
# 4. Disabling Services
#
Write-Host "4. Disabling Services"

# Set-Service "AppReadiness" -StartupType "Disabled"  -EA 0 # for Modern Apps
Set-Service "DiagTrack" -StartupType "Disabled"  -EA 0 # Diagnostics
Set-Service "diagnosticshub.standardcollector.service" -StartupType "Disabled" -EA 0 # Diagnostics
Set-Service "dmwappushservice" -StartupType "Disabled" -EA 0 # WAP Push Messages
Set-Service "WMPNetworkSvc" -StartupType "Disabled" -EA 0 # Windows Media
Set-Service "HomeGroupListener" -StartupType "Disabled" -EA 0 # HomeGroup
Set-Service "HomeGroupProvider" -StartupType "Disabled" -EA 0 # HomeGroup
## Set-Service "WSearch" -StartupType "Disabled" -EA 0  # Search
## Set-Service "wlidsvc" -StartupType "Disabled" -EA 0  # Microsoft Account Sign-in Assistant 
## XblAuthManager, XblGameSave, XboxNetApiSvc # Xbox Services
