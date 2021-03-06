# Usage:
# Load file into PS: Import-Module Get-PCInventory.ps1 -Force
# Example: Get-PCInfo -Computer 192.168.20.177 -Report
#
# -ADSearch - search in AD location
# -ADSearchBase - set AD location
# -File - input file with pc names list
# -Computer - single ip or dns name to check
# -ReportPath - per PC txt output file
# -Txt - if enabled creates txt file instead of CSV
# -Csv - output CSV file
# if no output switches enabled output will be shown only on screen

function Get-ComputerVirtualStatus {
    param( 
        [string]$ComputerName,
        [string]$BIOSVersion,
        [string]$SerialNumber,
        [string]$Manufacturer,
        [string]$Model
    ) 
    $Results = @()
   
    $ResultProps = @{   
        IsVirtual = $false 
        VirtualType = $null 
    }
    if ($SerialNumber -like "*VMware*") 
    {
        $ResultProps.IsVirtual = $true
        $ResultProps.VirtualType = "Virtual - VMWare"
    }
    else 
    {
        switch -wildcard ($BIOSVersion) 
        {
            'VIRTUAL' 
            { 
                $ResultProps.IsVirtual = $true 
                $ResultProps.VirtualType = "Virtual - Hyper-V" 
            } 
            'A M I' 
            {
                $ResultProps.IsVirtual = $true 
                $ResultProps.VirtualType = "Virtual - Virtual PC" 
            } 
            '*Xen*' 
            { 
                $ResultProps.IsVirtual = $true 
                $ResultProps.VirtualType = "Virtual - Xen" 
            }
        }
    }
    if (-not $ResultProps.IsVirtual) 
    {
        if ($Manufacturer -like "*Microsoft*") 
        { 
            $ResultProps.IsVirtual = $true 
            $ResultProps.VirtualType = "Virtual - Hyper-V" 
        } 
        elseif ($Manufacturer -like "*VMWare*") 
        { 
            $ResultProps.IsVirtual = $true 
            $ResultProps.VirtualType = "Virtual - VMWare" 
        } 
        elseif ($Model -like "*Virtual*") 
        { 
            $ResultProps.IsVirtual = $true
            $ResultProps.VirtualType = "Unknown Virtual Machine"
        }
    }
    $Results += New-Object PsObject -Property $ResultProps
    
    return $Results
}
 



Function Get-PCInventory 
{
    param(
        [string]$s
    )
    
    $videocontrollerlist = $null
    $diskControllerlist = $null
	$disklist = $null
    $logicaldisklist = $null
    $niclist = $null
    $nicmaclist = $null
    $niciplist = $null
    $CPUListName = $null
    $CPUListPhysicalCores = $null
    $CPUListLogicalCores = $null
    $RAMBankList = $null
    

    $infoObject = New-Object PSObject	
	
        if (!($ComputerSystem = Get-WmiObject Win32_ComputerSystem -ComputerName $s -ErrorAction SilentlyContinue)) 
        {
            Add-Member -inputObject $infoObject -memberType NoteProperty -name "Name" -value "$s is online but RPC is closed == possible DNS name mismatch"
            $infoObject #Output to the screen for a visual feedback.
	        $infoColl += $infoObject
            Continue;
        }

        $CPUInfo = Get-WmiObject Win32_Processor -ComputerName $s #Get CPU Information
	    $OSInfo = Get-WmiObject Win32_OperatingSystem -ComputerName $s #Get OS Information
        $OSInstallDate = (([WMI]'').ConvertToDateTime((Get-WmiObject Win32_OperatingSystem -ComputerName $s).InstallDate)).tostring('yyyy-MM-dd')	
        # Motherboard
        $MotherBoard = Get-WmiObject Win32_BaseBoard -ComputerName $s
        #BIOS
        $BIOS =  Get-WmiObject Win32_BIOS -ComputerName $s

        #Get Memory Information. The data will be shown in a table as MB, rounded to the nearest second decimal.
	    $OSTotalVirtualMemory = [math]::round($OSInfo.TotalVirtualMemorySize / 1MB, 2)
	    $OSTotalVisibleMemory = [math]::round(($OSInfo.TotalVisibleMemorySize / 1MB), 2)
	    $PhysicalMemory = Get-WmiObject Win32_PhysicalMemory -ComputerName $s
        $PhysicalMemoryTotal = Get-WmiObject CIM_PhysicalMemory -ComputerName $s | Measure-Object -Property capacity -Sum | % { [Math]::Round(($_.sum / 1GB), 2) }
        $PageFile = (Get-WmiObject -ComputerName $s Win32_PageFileUsage | Select *)

        $VideoController = Get-WmiObject Win32_VideoController -ComputerName $s | Where-Object { $_.AdapterRAM -gt 0 }
        
		$IsUEFI = Get-WmiObject -ComputerName $s -Query 'Select * from Win32_DiskPartition Where Type = "GPT: System"'
		# present if UEFI "HKLM:\SYSTEM\CurrentControlSet\Control\SecureBoot\State"
		$IdeController = Get-WmiObject Win32_IdeController -ComputerName $s
		$HddInfo = Get-WmiObject Win32_DiskDrive -ComputerName $s | Where-Object MediaType -eq 'Fixed hard disk media' | Select Model,@{Name='Size(GB)';Exp={[math]::Round($_.Size /1gb, 2) -as [int]}},InterfaceType
        $LogicalDisks = Get-WmiObject Win32_LogicalDisk -ComputerName $s
        # NIC
        $NicInfo = Get-WmiObject -Class Win32_NetworkAdapter -ComputerName $s | 
            where { $_.speed -and $_.macaddress -and $_.name -notmatch '802\.11|virtual' } # | select Name,Speed
            # wireless|wi-fi|bluetooth
            # -Filter "NetEnabled='True'"
        foreach ($NetworkAdapter in $NicInfo)
        {
            $NicConfig = Get-WmiObject -Class Win32_NetworkAdapterConfiguration -ComputerName $s -Filter "Index = '$($NetworkAdapter.Index)'"
        }

        # Get current logged in user
        $CurrentUser = (Get-WMIObject -Class Win32_ComputerSystem -ComputerName $s | select username).username
         
		

        #The following add data to the infoObjects.	
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Name" -value $ComputerSystem.Name
		
        # CPU
        foreach ($CPU in $CPUInfo)
        {
            $CPU.Name = $CPU.Name -replace "  +"," "
            $CPUListName +=  "$($CPU.Name)`n"
            $CPUListPhysicalCores += "$($CPU.NumberOfCores)`n"
            $CPUListLogicalCores += "$($CPU.NumberOfLogicalProcessors)`n"
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU Model" -value $CPUListName.Substring(0, $CPUListName.Length - 1)
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Physical Cores" -value $CPUListPhysicalCores.Substring(0, $CPUListPhysicalCores.Length - 1)
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Logical Cores" -value $CPUListLogicalCores.Substring(0, $CPUListLogicalCores.Length - 1)

        # Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU Description" -value $CPUInfo.Description
		# Add-Member -inputObject $infoObject -memberType NoteProperty -name "Manufacturer" -value $CPUInfo.Manufacturer
		
		# Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_L2CacheSize" -value $CPUInfo.L2CacheSize
		# Add-Member -inputObject $infoObject -memberType NoteProperty -name "CPU_L3CacheSize" -value $CPUInfo.L3CacheSize
		# Add-Member -inputObject $infoObject -memberType NoteProperty -name "Sockets" -value $CPUInfo.SocketDesignation
		
        
        # MB
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Motherboard Maker" -value $MotherBoard.Manufacturer
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Motherboard Model" -value $MotherBoard.Product
        		
        # BIOS
        # Add-Member -inputObject $infoObject -memberType NoteProperty -name "BIOS Name" -value $BIOS.Name
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "BIOS Ver." -value $BIOS.SMBIOSBIOSVersion

        # RAM		
        foreach ($RAMBank in $PhysicalMemory)
        {
            $RAMBankList += "$([math]::Round($RAMBank.Capacity /1GB, 2)) = $($RAMBank.Speed), "
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Total RAM (GB)" -value $PhysicalMemoryTotal
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "RAM Cap. GB = Speed MHz" -value $RAMBankList.Substring(0, $RAMBankList.Length - 2)
        # Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalVirtual_Memory_MB" -value $OSTotalVirtualMemory
		# Add-Member -inputObject $infoObject -memberType NoteProperty -name "TotalVisable_Memory_MB" -value $OSTotalVisibleMemory
        
        # Pagefile
        $Pagefileinfo = "$($PageFile.Name) = $($PageFile.AllocatedBaseSize)"
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Pagefile = MB" -value $Pagefileinfo
        
        # Video
        foreach ($video in $VideoController)
        {
            $videocontrollerlist += "$($video.Name) = $([math]::Round($video.AdapterRAM/1MB, 1))`n"
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Video Card = RAM (MB)" -value $videocontrollerlist.Substring(0, $videocontrollerlist.Length - 1)
        
		$boottype = "Legacy boot"
		if ($IsUEFI)
		{
			$boottype = "UEFI"
		}
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Boot type" -value $boottype
		
		# disk controller
		foreach ($diskController in $IdeController)
        {
            $diskControllerlist += "$($diskController.Name)`n"
        }
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Disk Controller" -value $diskControllerlist.Substring(0, $diskControllerlist.Length - 1)
		
        # disks
        foreach ($disk in $HddInfo)
        {
            $disklist += "$($disk.Model) = $($disk.'Size(GB)')`n"
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Disk = Size (GB)" -value $disklist.Substring(0, $disklist.Length - 1)

        foreach ($logicaldisk in $LogicalDisks)
        {
            if ($logicaldisk.DriveType -eq 3)
            {
                $logicaldisklist += "$($logicaldisk.DeviceID) $([math]::Round($logicaldisk.FreeSpace / 1GB, 0)) free of $([math]::Round($logicaldisk.Size / 1GB, 0))`n"
            }
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Partitions (GB)" -value $logicaldisklist.Substring(0, $logicaldisklist.Length - 1)

        # NICs
        foreach ($nic in $NicInfo)
        {
            $niclist += "$($nic.Name) = $([math]::Round($nic.speed/1000000,0))`n"
            $nicmaclist +="$($nic.MACAddress)`n"
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC = Speed (Mbit)" -value $niclist.Substring(0, $niclist.Length - 1)
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC MAC" -value $nicmaclist.Substring(0, $nicmaclist.Length - 1)

        # NIC IP
        foreach ($nicip in $NicConfig)
        {
            $niciplist += "$($nicip.IPAddress)`n"
        }
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "NIC IP" -value $niciplist.Substring(0, $niciplist.Length - 1)

        # OS
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Name" -value $OSInfo.Caption
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS Version" -value $OSInfo.Version
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "OS install date" -value $OSInstallDate 
        
        Add-Member -inputObject $infoObject -memberType NoteProperty -name "Current user" -value $CurrentUser
        
		# OS Boot & Uptime
		$BootTime = $OSInfo.ConvertToDateTime($OSInfo.LastBootUpTime)
        $Uptime = $OSInfo.ConvertToDateTime($OSInfo.LocalDateTime) - $BootTime
        $UptimeString = "$($Uptime.Days)days $($Uptime.Hours)h $($Uptime.Minutes)m"
		Add-Member -inputObject $infoObject -memberType NoteProperty -name "Boot time = Uptime" -value "$($BootTime.ToString('yyyy-MM-dd HH:mm:ss')) = $($UptimeString)"
        # Admin users

        # Virtual
        $VirtualStatus = Get-ComputerVirtualStatus -ComputerName $s -BIOSVersion $BIOS.Version -SerialNumber $BIOS.SerialNumber -Manufacturer $ComputerSystem.Manufacturer -Model $ComputerSystem.Model
        # if ($VirtualStatus.IsVirtual)
        #{
            Add-Member -inputObject $infoObject -memberType NoteProperty -name "Virtual Machine?" -value $VirtualStatus.VirtualType
        #}

    return $infoObject
}



Function Get-PCInfo
{
    [CmdletBinding()]
    param(
        [string]$InputFile,
        [string]$Computer,
        [switch]$ADSearch,
        [string]$ADSearchBase = "OU=,OU=,DC=,DC=",
        [string]$ReportPath = "D:\pc_reports",
        [switch]$Txt,
        [switch]$Csv
    )

    # Get pc list from AD or from File
    $PCName = @()
    if ($ADSearch) 
    {
        Import-Module ActiveDirectory
        $PCs = Get-ADComputer -Filter * -SearchBase $ADSearchBase | Select-Object Name | Sort-Object -Property Name
        $PCName = $PCs.Name
    }
    elseif ($InputFile.Length -gt 1)
    {
        $PCName = Get-Content $InputFile
    }
    if ($Computer.Length -gt 1)
    {
        $PCName = $Computer
    }
    

    $infoColl = @()
    Foreach ($pc in $PCName)
    {    
        # it can be comments in txt input file
        if (($pc.StartsWith("#")) -or ($pc.Length -eq 0))
        {
            continue
        } 
        if (Test-Connection -ComputerName $pc -Count 1 -Quiet -ErrorAction SilentlyContinue)
        {
            $infoObject = (Get-PCInventory -s $pc)
            if ($Txt)
            {
                $infoObject | Out-File -File "$ReportPath\$($infoObject.Name).txt" -Encoding Unicode
                Write-host "`n$($infoObject.Name) Report saved at $($ReportPath)\$($infoObject.Name).txt" -ForegroundColor Green
                $infoObject
                Continue
            }
            $infoObject
            $infoColl += $infoObject
        }
        else
        {
            if ($Csv)
            {
                Add-Member -inputObject $infoObject -memberType NoteProperty -name "Name" -value "$pc is offline" -Force
            }
            Write-Host "`n$($pc) is offline`n" -ForegroundColor Red
        }
    }
    
    if ($Csv)
    {
        $infoColl | Export-Csv -path "$ReportPath\_PC_Inventory_$((Get-Date).ToString('yyyy-MM-dd')).csv" -NoTypeInformation -Encoding Unicode
    }

}

# Get-PCInfo -Computer akosarev
