if ($PSVersionTable.BuildVersion.Major -lt 10)
{
    Write-Host This OS is not supported -ForegroundColor Red
    exit
}
$ErrorActionPreference = "SilentlyContinue"

################
#
# 5. Removing Apps
#
# Example: http://www.scconfigmgr.com/2016/03/01/remove-built-in-apps-when-creating-a-windows-10-reference-image/
#
Write-Host "5. Removing Apps"

$Apps = @(
	"Microsoft.3DBuilder",
	"Microsoft.Print3D",
	"Microsoft.BingFinance",
	"Microsoft.BingNews",
	"Microsoft.BingSports",
	"Microsoft.BingFoodAndDrink",
    "Microsoft.BingTravel",
    "Microsoft.BingHealthAndFitness",
	"Microsoft.BingWeather",
    "Microsoft.WindowsReadingList",
	"Microsoft.Getstarted",
	"Microsoft.MicrosoftOfficeHub",
	"Microsoft.MicrosoftSolitaireCollection",
	"Microsoft.Office.OneNote",
	"Microsoft.Office.Sway",
	"Microsoft.People",
	"Microsoft.WindowsCamera",
	"Microsoft.WindowsMaps",
	"Microsoft.WindowsPhone",
	"Microsoft.WindowsSoundRecorder",
	"Microsoft.WindowsFeedbackHub",
	"Microsoft.Messaging",
	"Microsoft.CommsPhone",
	
	"Microsoft.HologramsApp",
	"HoloShell",
	"HoloItemPlayerApp",
	"HoloCamera",
	"Microsoft.MinecraftUWP",
    "Microsoft.NetworkSpeedTest",
	"Microsoft.OneConnect",
	"Microsoft.Microsoft3DViewer",
    "Microsoft.MicrosoftPowerBIForWindows",
	
	# non-Microsoft
    "9E2F88E3.Twitter",
	"AD2F1837.HPPrinterControl",
    "PandoraMediaInc.29680B314EFC2",
    "Flipboard.Flipboard",
    "ShazamEntertainmentLtd.Shazam",
    "king.com.CandyCrushSaga",
    "king.com.CandyCrushSodaSaga",
    "king.com.*",
    "ClearChannelRadioDigital.iHeartRadio",
    "4DF9E0F8.Netflix",
    "6Wunderkinder.Wunderlist",
    "Drawboard.DrawboardPDF",
    "2FE3CB00.PicsArt-PhotoStudio",
    "D52A8D61.FarmVille2CountryEscape",
    "TuneIn.TuneInRadio",
    "GAMELOFTSA.Asphalt8Airborne",
    #"TheNewYorkTimes.NYTCrossword",
    "DB6EA5DB.CyberLinkMediaSuiteEssentials",
    "Facebook.Facebook",
    "flaregamesGmbH.RoyalRevolt2",
    "Playtika.CaesarsSlotsFreeCasino",
    "A278AB0D.MarchofEmpires",
    "KeeperSecurityInc.Keeper",
    "ThumbmunkeysLtd.PhototasticCollage",
    "XINGAG.XING",
    "89006A2E.AutodeskSketchBook",
    "D5EA27B7.Duolingo-LearnLanguagesforFree",
    "46928bounde.EclipseManager",
    "ActiproSoftwareLLC.562882FEEB491", # Code Writer
    "DolbyLaboratories.DolbyAccess",
    "SpotifyAB.SpotifyMusic",
    "A278AB0D.DisneyMagicKingdoms",
    "WinZipComputing.WinZipUniversal"

	# "Microsoft.MSPaint",
	# "Microsoft.SkypeApp",
	# "microsoft.windowscommunicationsapps",
	
	# apps which cannot be removed using Remove-AppxPackage
    #"Microsoft.BioEnrollment"
    #"Microsoft.MicrosoftEdge"
    #"Microsoft.Windows.Cortana"
    #"Microsoft.WindowsFeedback"
    #"Microsoft.XboxGameCallableUI"
    #"Microsoft.XboxIdentityProvider"
    #"Windows.ContactSupport"
	
	)
foreach ($App in $Apps) 
{
	$AppPackageFullName = Get-AppxPackage -AllUsers -Name $App | Select-Object -ExpandProperty PackageFullName
        
    if ($AppPackageFullName -ne $null)
    {
        try 
        {
            Remove-AppxPackage $AppPackageFullName -EA 0
            Write-Host "$($AppPackageFullName) removed from all users" -ForegroundColor Yellow -BackgroundColor Black
        }
        catch [Exception]
        {
            Write-Host "Error Removing $($AppPackageFullName) from all users`n $($_.Exception.Message)" -ForegroundColor Red -BackgroundColor Black
        }
    }
        
	# provisioned apps
	Get-AppxProvisionedPackage -Online -EA 0 | Where-Object { $_.DisplayName -like $App } |  Remove-ProvisionedAppxPackage -Online -EA 0
}

# 5.1 Removing Capabilities
Write-Host "5.1 Removing Capabilities"
Get-WindowsCapability -Online -EA 0 | ? {$_.Name -like '*ContactSupport*' -and $_.State -like "Installed"} | Remove-WindowsCapability -Online -EA 0
Get-WindowsCapability -Online -EA 0 | ? {$_.Name -like '*Holographic*'  -and $_.State -like "Installed"} | Remove-WindowsCapability -Online -EA 0
Get-WindowsCapability -Online -EA 0 | ? {$_.Name -like '*QuickAssist*'  -and $_.State -like "Installed"} | Remove-WindowsCapability -Online -EA 0
