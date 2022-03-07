##############################################################################
# SCRIPT - POWERSHELL
# NAME: AD-ComputerInventory.ps1
# 
# AUTHOR:  	Don Garrison
# DATE:  	2/17/2022
# 
# COMMENT:  Periodic scan of AD-joined computers to collect specific information
#
# VERSION HISTORY
# 	0.1 BETA: 
# 
# LOGGING INFO:
# 	to file: $filename3
#
# TO ADD: <nothing at this time>
#
#
# NOTES:
# 	1. Confirm you have installed underlying module - _____Install-Module ActiveDirectoryModule_____
#	2. To rescan a computer, delete it's row from $filename
#   3. Skips scanning all computers with "server" in $ComputerInfoOperatingSystem
#	4. Added EXCLUDE file to provide a way to skip hosts
#	4. Schedule task to run every 3 hours using ```schtasks /create /tn test /tr "powershell -file <filename>.ps1" /sc minute 180 /it```
#
###############################################################################



clear

#__Variables__
$Inventory = New-Object System.Collections.ArrayList
$OfflineComputers = New-Object System.Collections.ArrayList
$ErrorActionPreference= 'silentlycontinue'
$StartTime = (Get-date)



# ___MOST_IMPORTANT_VARIABLE___Modify this string to determine scope
$ListofAllComputers = Get-ADComputer -Filter {(name -like "ExampleString*")}
$ComputerNamesFromAD = $ListofAllComputers.name

# ___FILE INFORMATION___
[System.IO.Directory]::CreateDirectory('C:\src') | out-null
# Inventory File
$filename="c:\src\AD_Inventory.csv"
if (!(Test-Path $filename)) {
	New-Item -ItemType "file" -Path $filename | out-null 
	$FirstRun = $true
}
# Offline File
$filename2="c:\src\AD_Inventory_Offline.csv"
if (!(Test-Path $filename2)) {New-Item -ItemType "file" -Path $filename2 | out-null}
# Logging File
$filename3="c:\src\AD_Inventory_Logfile.txt"
# Computers to Exclude
$filename4="c:\src\AD_Inventory_Exclude.csv"
if (!(Test-Path $filename4)) {
	New-Item -ItemType "file" -Path $filename4 | out-null; 
	$NamesToExclude = "Name"
	$NamesToExclude | Out-file $filename4 
}



# extract computers which have already been scanned -or- are problematic and need to be skipped
$NamesToRemove = (Import-Csv $filename).name 
$NamesToExclude = (Import-Csv $filename4).name
$AllComputers = $ComputerNamesFromAD | where-object {$NamesToRemove -notcontains $_}
$AllComputers = $AllComputers | where-object {$NamesToExclude -notcontains $_}

# Maths and establish counters
$totalComputersToScan = $ComputerNamesFromAD.count
$totalNewToScan = $AllComputers.count
$totalNew = 0
$totalOffline = 0

#move cursor below progress bar
write-host "`n`n`n`n`n`n"


############################################################################################################################################################
#___BEGIN DATA HARVESTING___
############################################################################################################################################################
Foreach ($ComputerName in $AllComputers) { #<All computers defined in get-adcomputer command above>
# progress bar	
	if ($totalOffline + $totalNew -gt 0) {$i = [math]::round(($totalOffline + $totalNew)/$totalNewToScan*100 )} else {$i = 0}
	$iteration = $totalOffline + $totalNew
	Write-Progress -Activity "Running Inventory" -Status "$iteration out of $totalNewToScan ($i% Complete) - New This Scan: $totalNew - Computer: $ComputerName" -PercentComplete $i 
	
	write-host "Target = $ComputerName (Started at: "(Get-Date -format 'h:mm:ss tt')")"
	
# generate data  
	$PollTimeDate = get-date -format MM-dd-yyyy
	$PollTimeTime = get-date -format HH:mm:ss

# check target for alive
	$Connection = Test-Connection $ComputerName -Count 1 -Quiet

############################################################################################################################################################
#___BEGIN DATA COLLECTION FROM AD___
############################################################################################################################################################
# collect data about target from Active Directory  
	Write-host -nonewline -foreground white "`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
	write-host " Collecting Data From Active Directory"
	$ComputerOS = Get-ADComputer $ComputerName -Properties OperatingSystem,OperatingSystemServicePack,LastLogonDate
	$ComputerInfoOperatingSystem = $ComputerOS.OperatingSystem
	$ComputerInfoOperatingSystemServicePack = $ComputerOS.OperatingSystemServicePack
	$ComputerLastLogonDate = $ComputerOS.LastLogonDate
	
# start building custom object
	$ComputerInfo = New-Object System.Object
	$ComputerInfo | Add-Member -MemberType NoteProperty -Name "Name" -Value "$ComputerName" -Force
	$ComputerInfo | Add-Member -MemberType NoteProperty -Name "OperatingSystem" -Value $ComputerInfoOperatingSystem
	$ComputerInfo | Add-Member -MemberType NoteProperty -Name "ServicePack" -Value $ComputerInfoOperatingSystemServicePack
	$ComputerInfo | Add-Member -MemberType NoteProperty -Name "LastLogonDate" -Value $ComputerLastLogonDate 

# added logic to exclude from targeted scan
	$scanLogic = $true
	if ($ComputerInfoOperatingSystem -like "*server*") {$scanLogic = $false} #Excludes: Servers

############################################################################################################################################################
#___BEGIN SCAN OF TARGET___
############################################################################################################################################################
	if ($Connection -eq "True" -and $scanLogic){ #<online> and <not intentionally skipped>
		$totalNew += 1
		Write-host -nonewline -foreground white "`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host " Collecting Data From Target"
# collect data from target computer
		Write-host -nonewline -foreground white "`t`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host  " Getting Computer Information (Get ComputerInfo)"
		$ComputerInfoAdditional = invoke-command -ComputerName $ComputerName -scriptblock {get-computerinfo | select-object csName,WindowsProductName,WindowsEditionId,OsArchitecture,BiosSeralNumber,CsDomainRole,CsManufacturer,CsModel,OsLastBootUpTime,OsNumberOfUsers,OsInstallDate,OsVersion,OsBuildNumber,WindowsVersion}
		Write-host -nonewline -foreground white "`t`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host  " Getting Services (Get Service)"
		$sysmon = Get-Service -ComputerName $ComputerName -Name *Sysmon*  | Where-Object {($_.name -eq "Sysmon") -or ($_.name -eq "Sysmon64")}
# Sysmon: Get installed sysmon version
		Write-host -nonewline -foreground white "`t`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host " Getting Sysmon Version"
	    $sysmonversion = invoke-command -ComputerName $ComputerName { (sysmon64 -s).split(" ")[3]}
# Sysmon: count references to ImageLoad
		Write-host -nonewline -foreground white "`t`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host " Getting Sysmon ImageLoad Count"
		$sysmonImageLoadCount=invoke-command -ComputerName $ComputerName -scriptblock {((sysmon64 -c | select-string "imageload").count) - 2}
# Sysmon: try to get running Sysmon ConfigFile	
		Write-host -nonewline -foreground white "`t`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host " Getting Sysmon Configuration File"
		$SysmonConfig = invoke-command -ComputerName $ComputerName -scriptblock {(get-itemproperty -Path HKLM:\SYSTEM\CurrentControlSet\Services\SysmonDrv\Parameters\ |select-object -expandproperty ConfigFile).split("\")[-1] }
# IP Address
		Write-host -nonewline -foreground white "`t`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host " Getting Last IP Address"
		$ipaddress = invoke-command -ComputerName $ComputerName -scriptblock {(Get-NetIPConfiguration | Where-Object {$_.IPv4DefaultGateway -ne $null -and $_.NetAdapter.Status -ne "Disconnected"}).IPv4Address.IPAddress}
# Last Logon
		Write-host -nonewline -foreground white "`t`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host " Getting Last Logged On User"
		$LastLoggedOnUser = invoke-command -ComputerName $ComputerName -scriptblock {Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI" | Select-Object -ExpandProperty LastLoggedOnUser}
# collect more data from target computer
		Write-host -nonewline -foreground white "`t`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host " Collecting Hardware Specific Information (Make, Model, Processor, Drives)"
		$ComputerHW = Get-WmiObject -Class Win32_ComputerSystem -ComputerName $ComputerName | select Manufacturer,Model,NumberOfProcessors,@{Expression={$_.TotalPhysicalMemory / 1GB};Label="TotalPhysicalMemoryGB"}
		$ComputerCPU = Get-WmiObject win32_processor -ComputerName $ComputerName | select DeviceID,Name,Manufacturer,NumberOfCores,NumberOfLogicalProcessors
		$ComputerDisks = Get-WmiObject -Class Win32_LogicalDisk -Filter "DriveType=3" -ComputerName $ComputerName | select DeviceID,VolumeName,@{Expression={$_.Size / 1GB};Label="SizeGB"}
# collect more data from target computer
		$ComputerInfoManufacturer = $ComputerHW.Manufacturer
		$ComputerInfoModel = $ComputerHW.Model
		$ComputerInfoNumberOfProcessors = $ComputerHW.NumberOfProcessors
		$ComputerInfoProcessorID = $ComputerCPU.DeviceID
		$ComputerInfoProcessorManufacturer = $ComputerCPU.Manufacturer
		$ComputerInfoProcessorName = $ComputerCPU.Name
		$ComputerInfoNumberOfCores = $ComputerCPU.NumberOfCores
		$ComputerInfoNumberOfLogicalProcessors = $ComputerCPU.NumberOfLogicalProcessors
		$ComputerInfoRAM = $ComputerHW.TotalPhysicalMemoryGB
		$ComputerInfoDiskDrive = $ComputerDisks.DeviceID
		$ComputerInfoDriveName = $ComputerDisks.VolumeName
		$ComputerInfoSize = $ComputerDisks.SizeGB
		write-host "`t`t=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
# validate data for some objects
		Write-host -nonewline -foreground white "`t`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host " Validating Collected Values"
		if ($sysmon.name -eq $Null) {$sysmonname="False"} else {$sysmonname="True"}
		if ($sysmon.name -eq $Null) {$sysmonImageLoadCount="_sysmon_missing_"} else {if ($sysmonImageLoadCount -lt 1) {$sysmonImageLoad="Disabled"} else {$sysmonImageLoad="Enabled"}}
		if ($sysmon.status -eq $Null) {$sysmonstatus=""} else {$sysmonstatus=$sysmon.status}
		if ($sysmon.starttype -eq $Null) {$sysmonstarttype=""} else {$sysmonstarttype=$sysmon.starttype}
		if ($sysmonversion -eq $Null) {$sysmonversion=""} else {$sysmonversion = $sysmonversion}
		write-host "`t`t=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="

# continue building custom object with data collected	   
		Write-host -nonewline -foreground white "`t`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
		write-host " Building Computer Profile"
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "ComputerStatus" -Value "Online" -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "PollTimeDate" -Value "$PollTimeDate" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "PollTimeTime" -Value "$PollTimeTime" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "LogicSkipped" -Value "$scanLogic" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "IPAddress" -Value "$ipaddress" -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "LastUser" -Value $LastLoggedOnUser -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "WindowsProductName" -Value $ComputerInfoAdditional.WindowsProductName -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "WindowsEditionId" -Value $ComputerInfoAdditional.WindowsEditionId -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "OSArchitecture" -Value $ComputerInfoAdditional.OSArchitecture -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "BIOSSerialNumber" -Value $ComputerInfoAdditional.BiosSeralNumber -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "DomainRole" -Value $ComputerInfoAdditional.CsDomainRole -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value $ComputerInfoAdditional.CsManufacturer -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "Model" -Value $ComputerInfoAdditional.CsModel -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "LastBootUpTime" -Value $ComputerInfoAdditional.OsLastBootUpTime -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "NumberOfUsers" -Value $ComputerInfoAdditional.OsNumberOfUsers -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "OsInstallDate" -Value $ComputerInfoAdditional.OsInstallDate -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "OsVersion" -Value $ComputerInfoAdditional.OsVersion -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "OsBuildNumber" -Value $ComputerInfoAdditional.OsBuildNumber -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "WindowsVersion" -Value $ComputerInfoAdditional.WindowsVersion -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "HasSysmon" -Value "$SysmonName" -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "SysmonStatus" -Value "$SysmonStatus" -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "SysmonStartType" -Value "$SysmonStartType" -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "SysmonVersion" -Value "$sysmonversion" -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "SysmonImageLoad" -Value "$sysmonImageLoad" -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "SysmonImageLoadCount" -Value "$sysmonImageLoadCount" -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "SysmonImageLoad" -Value "$sysmonImageLoad" -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "SysmonConfig" -Value "$SysmonConfig" -Force 
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "Manufacturer" -Value "$ComputerInfoManufacturer" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "Model" -Value "$ComputerInfoModel" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "NumberOfProcessors" -Value "$ComputerInfoNumberOfProcessors" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "ProcessorID" -Value "$ComputerInfoProcessorID" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "ProcessorManufacturer" -Value "$ComputerInfoProcessorManufacturer" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "ProcessorName" -Value "$ComputerInfoProcessorName" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "NumberOfCores" -Value "$ComputerInfoNumberOfCores" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "NumberOfLogicalProcessors" -Value "$ComputerInfoNumberOfLogicalProcessors" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "RAM" -Value "$ComputerInfoRAM" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "DiskDrive" -Value "$ComputerInfoDiskDrive" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "DriveName" -Value "$ComputerInfoDriveName" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "Size" -Value "$ComputerInfoSize"-Force 

# add scanned computer to array
		write-host "`t`t=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-="
		if ($FirstRun) {
			Write-host -nonewline -foreground white "`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
			write-host -foreground darkgreen " -- FIRST RUN - Adding Headers to $filename --"
			Write-host -nonewline -foreground white "`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
			write-host -foreground darkgreen " -- SUCCESS - Writing $ComputerName Profile to $filename --"
			$ComputerInfo | ConvertTo-Csv -NoTypeInformation | Add-Content -path $filename
#			$Inventory.Add($ComputerInfo) | Out-Null
			$FirstRun = $false
		}
		else {
			Write-host -nonewline -foreground white "`t[";Write-host -nonewline -foreground blue "+"; write-host -nonewline -foreground white "]"
			write-host -foreground darkgreen " -- SUCCESS - Writing $ComputerName Profile to $filename --"
			while ($true) {
				try {
					[System.IO.File]::OpenWrite($filename).Close()
					$Writable = $true
					}
				catch {
					$Writable = $false   
				}
				if ($Writable) {
					$ComputerInfo | ConvertTo-Csv -NoTypeInformation | Select-Object -skip 1 | Add-Content -path $filename 
					break 
				} 
				else {Write-Host -nonewline -ForegroundColor Yellow "`n`n`n`n`n`n`n`nWARNING: Write Error - Please close Excel (" $filename ")"
					Write-Host -ForegroundColor white -backgroundcolor blue "`n`t   Press any key to continue...   "
					$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
				}
			}
		}
   }
   else { #<not accessible> OR <intentionally skipped>
		write-host -foreground yellow "`t`t -- SKIPPED --"
		$totalOffline += 1
		if ($scanLogic) {$notScannedReason = "Offline"} else {$notScannedReason = "Skipped"}
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "ComputerStatus" -Value "$notScannedReason" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "PollTimeDate" -Value "$PollTimeDate" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "PollTimeTime" -Value "$PollTimeTime" -Force
		$ComputerInfo | Add-Member -MemberType NoteProperty -Name "LogicSkipped" -Value "$scanLogic" -Force

	
# add missing computer to array
	  $OfflineComputers.Add($ComputerInfo) | Out-Null
   }
write-host "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=`n`n"

# reset variable values to blank
$ComputerHW = ""
$ComputerCPU = ""
$ComputerDisks = ""
}

############################################################################################################################################################
#___BEGIN_OUTPUT_OF_DATA_AND_LOGGING___
############################################################################################################################################################

# Test to see of the list of offline computers files is writable and update it; otherwise warn/prompt user
while ($true) {
	try {
		[System.IO.File]::OpenWrite($filename2).Close()
		$Writable = $true
		}
	catch {
		$Writable = $false   
	}
	if ($Writable) {
		$OfflineComputers | export-csv -append $filename2
		break 
	} 
	else {Write-Host -nonewline -ForegroundColor Yellow "`n`n`n`n`n`n`n`nWARNING: Write Error - Please close Excel (" $filename2 ")"
		Write-Host -ForegroundColor white -backgroundcolor blue "`n`t    Press any key to continue...    "
		$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	}
}
#write-host "=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=-=`n`n"
# get completed timestamp and calculate time elapsed
$StopTime = (Get-date)
$TotalTime = $StopTime - $StartTime

# write summary to console
write-host -ForegroundColor Yellow "Inventory Summary:"
write-host -ForegroundColor Yellow "========================================================================"
write-host "Computers Scanned in Prior Scans:           " ($totalComputersToScan - $totalNewToScan)
write-host "New Computers Scanned Successfully:         " $totalNew
write-host "Computers Offline or Skipped Intentionally: " $totalOffline
write-host "                                            ======"
write-host "Total Computers In This Scan:               " $totalComputersToScan
write-host " "
write-host "Start Time:                                 " $StartTime
write-host "End Time:                                   " $StopTime
write-host "Elapsed Time (H:M:S):                       " $TotalTime.Hours ":" $TotalTime.Minutes ":" $TotalTime.Seconds
write-host -ForegroundColor Yellow "========================================================================`n`n"

# build summary for logfile
$logfileOutput = "========================================================================`n" `
			    + (Get-Date) `
				+ "`nInventory Summary:" `
				+ "`n`tComputers Scanned in Prior Scans:           " + ($totalComputersToScan - $totalNewToScan) `
				+ "`n`tNew Computers Scanned Successfully:         " + $totalNew `
				+ "`n`tComputers Offline or Skipped Intentionally: " + $totalOffline `
				+ "`n`t                                           ======" `
				+ "`n`tTotal Computers In This Scan:               " + $totalComputersToScan `
				+ "`n" `
				+ "`n`tStart Time:                                 " + $StartTime `
				+ "`n`tEnd Time:                                   " + $StopTime `
				+ "`n`tElapsed Time (H:M:S):                       " + $TotalTime.Hours + ":" + $TotalTime.Minutes + ":" + $TotalTime.Seconds `
				+ "`n========================================================================`n" 

# Test to see of the list of Logfile file is writable and update it; otherwise warn/prompt user
while ($true) {
	try {
		[System.IO.File]::OpenWrite($filename3).Close()
		$Writable = $true
		}
	catch {
		$Writable = $false   
	}
	if ($Writable) {
		$logfileOutput >> $filename3
		break 
	} 
	else {Write-Host -nonewline -ForegroundColor Yellow "`n`n`n`n`n`n`n`nWARNING: Write Error Accessing File.  Please close Excel (" $filename3 ")"
		Write-Host -ForegroundColor white -backgroundcolor blue "`n`t    Press any key to continue...    "
		$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
	}
}