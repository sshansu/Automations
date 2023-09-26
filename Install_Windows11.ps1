#####################################################################################################
# ALL THE SCRIPTS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED                   #
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR         #
# FITNESS FOR A PARTICULAR PURPOSE.                                                                 #
#                                                                                                   #
# This script is not supported under any Microsoft standard support program or service.             #
# The script is provided AS IS without warranty of any kind.                                        #
#                                                                                                   #
# Script Name : InstallWindows11.ps1                                                                #
# Purpose     : Script used to incremenelty install windows udpates                                 #
#               expects the PSWindowsUpdate module '=]to be installed                               #
#               needs to be run by a packer powershell provisioner at least 4 times in a row with   #
#               reboots in between (4x depends on your OS)                                          #
#               no longer used since https://github.com/rgl/packer-provisioner-windows-update came  #
#               to be with https://github.com/rgl/packer-provisioner-windows-update/pull/4          #
# Version     : v9.0                                                                                #
#####################################################################################################

#variables
$AddDays = "3"
$Module = "PSWindowsUpdate"
$21H2 = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators\CO21H2"
$WorkspaceID = "f8b85f92-be02-4d28-8277-598f8cac639d"
$Primarykey = "uwjlBubN/PQEPWoahVdbHDLmrQdVVjpwPxWg2/SzwCwbfmfCkxyM6zDytK6XA2Tgatjl+btzNvvCvmQ3py5OLA=="
$Category = "SU_Windows11Upgrade"
$UpdateIDReg = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\CommitRequired"

# Reset current log
get-item "C:\windows\Temp\$($env:computername)-WindowsUpdateStatus.Log" -ea 0 | Remove-Item -Force

#################################
##REPORTING AND LOGGING FUNCTIONS
#################################

# Create the function to create the authorization signature
# ref https://docs.microsoft.com/en-us/azure/azure-monitor/logs/data-collector-api
# Function to convert data
Function Build-Signature ($customerId, $sharedKey, $date, $contentLength, $method, $contentType, $resource)
{
    $xHeaders = "x-ms-date:" + $date
    $stringToHash = $method + "`n" + $contentLength + "`n" + $contentType + "`n" + $xHeaders + "`n" + $resource

    $bytesToHash = [Text.Encoding]::UTF8.GetBytes($stringToHash)
    $keyBytes = [Convert]::FromBase64String($sharedKey)

    $sha256 = New-Object System.Security.Cryptography.HMACSHA256
    $sha256.Key = $keyBytes
    $calculatedHash = $sha256.ComputeHash($bytesToHash)
    $encodedHash = [Convert]::ToBase64String($calculatedHash)
    $authorization = 'SharedKey {0}:{1}' -f $customerId,$encodedHash
    return $authorization
}

# Function to Post Status to Log Analytics 
Function Post-LogAnalyticsData($customerId, $sharedKey, $body, $logType)
{
    $method = "POST"
    $contentType = "application/json"
    $resource = "/api/logs"
    $rfc1123date = [DateTime]::UtcNow.ToString("r")
    $contentLength = $body.Length
    $TimeStampField = ""
    $signature = Build-Signature `
        -customerId $customerId `
        -sharedKey $sharedKey `
        -date $rfc1123date `
        -contentLength $contentLength `
        -method $method `
        -contentType $contentType `
        -resource $resource
    $uri = "https://" + $customerId + ".ods.opinsights.azure.com" + $resource + "?api-version=2016-04-01"

    $headers = @{
        "Authorization" = $signature;
        "Log-Type" = $logType;
        "x-ms-date" = $rfc1123date;
        "time-generated-field" = $TimeStampField;
    }

    try {
        $response = Invoke-WebRequest -Uri $uri -Method $method -ContentType $contentType -Headers $headers -Body $body -UseBasicParsing
    }
    catch {
        $response = $_#.Exception.Response
    }
    
    return $response
}

#LogWrite function
Function Write-Log
{

    PARAM(
         [String]$Message,
         [String]$Path = "C:\windows\Temp\$($env:computername)-WindowsUpdateStatus.Log",
         [int]$severity,
         [string]$component
         )
         
         $TimeZoneBias = Get-CimInstance -Query "Select Bias from Win32_TimeZone"
         $Date = Get-Date -Format "HH:mm:ss.fff"
         $Date2 = Get-Date -Format "MM-dd-yyyy"
         $type =1
         
         "<![LOG[$Message]LOG]!><time=$([char]34)$date$($TimeZoneBias.bias)$([char]34) date=$([char]34)$date2$([char]34) component=$([char]34)$component$([char]34) context=$([char]34)$([char]34) type=$([char]34)$severity$([char]34) thread=$([char]34)$([char]34) file=$([char]34)$([char]34)>"| Out-File -FilePath $Path -Append -NoClobber -Encoding default
}

#################################
##MAIN SCRIPT STARTS
#################################

# Create a 'master' custom class to contain REPORTING data
class MasterClass {
    $SU_UpdateLog
}
$MasterClass = [MasterClass]::new()

# Check for PSWindowsUpdate
if(-not (Get-Module $Module -ListAvailable))
    {
        Write-Log -Message "Installing $($Module) module..." -severity 1 -component "InstallModule"
        Install-PackageProvider -Name NuGet -MinimumVersion 2.8.5.201 -Force
        Install-Module $Module -Force -AllowClobber
    }
else
    {
        Write-Log -Message "$($Module) module already installed." -severity 1 -component "InstallModule"
    }

####################################################
##Check for current WU WSUS registry key settings
####################################################
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$WUSUrl = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate"

if((Test-Path -Path $registryPath) -and (Test-Path -Path $WUSUrl))
    {
        Write-Log -Message "Registry key exists: $registryPath" -severity 1 -component "InstallModule"

        # Delete WSUS URL key values
        $CheckWUSUrl = Get-ItemProperty -Path $WUSUrl -Name WUServer -ErrorAction SilentlyContinue
        if($CheckWUSUrl)
            {
                Remove-ItemProperty -Path $WUSUrl -Name WUServer -Confirm:$False -ErrorAction SilentlyContinue
                Remove-ItemProperty -Path $WUSUrl -Name WUStatusServer -Confirm:$False -ErrorAction SilentlyContinue
                Write-Log -Message "Removed WSUS URL registry keys" -severity 1 -component "InstallModule"
            }
        else
            {
                Write-Log -Message "WUServer and WUStatusServer keys don't exist" -severity 1 -component "InstallModule"
            }

        # Reset WU Server value
        $checkWUkey = Get-ItemProperty -Path $registryPath -Name UseWUServer -ErrorAction SilentlyContinue
        if($checkWUkey)
            {
                Set-ItemProperty -Path $registryPath -Name UseWUServer -Value "0" -Confirm:$False -ErrorAction SilentlyContinue
                Write-Log -Message "Reset WUServer setting to 0" -severity 1 -component "InstallModule"   
            }
        else
            {
                Write-Log -Message "UseWUServer key doesn't exist" -severity 1 -component "InstallModule"
            }
        
    } 
else 
    {
        Write-Host "Registry key does not exist: $registryPath"
    }


#####################################################################################
##check for Microsoft Account Sign-In Assistant and Windows Defender Firewall Service
#####################################################################################
$services = "wlidsvc", "mpssvc"
foreach($service in $services)
    {
        #Getting Display names
        $Displayname = (Get-Service -Name $service -ea 0).DisplayName
        If($Displayname -eq $null){$Displayname = $service}
        $exist = (get-service -Name $service -ea 0) 
        
        #Verify/Remediate service startup type "automatic"
        $servicetype = (Get-WmiObject -Class win32_service -ErrorAction SilentlyContinue | where {$_.name -eq "$service"}).startmode
        if($servicetype -eq "Auto")
            {
                Write-Log -Message "$($Displayname) service type: $($servicetype)" -severity 1 -component "InstallUpdate"
            }
        else
            {
                #Change servicetype
                Write-Log -Message "$($Displayname) service type is set to $($servicetype). Changing to Automatic" -severity 1 -component "InstallUpdate"
                $settoAuto = Set-Service -Name $service -StartupType Automatic -ErrorAction SilentlyContinue
            }
        
        #Verify/Remediate WMI service status "running"
        $servicestatus = (get-service -Name $service -ea SilentlyContinue | Select-Object status).status
        If($servicestatus -eq "Stopped")
            {
                Write-Log -Message "$($Displayname) service is $servicestatus. Attempting to start the service." -severity 1 -component "InstallUpdate"
                start-Service -Name $service -ErrorAction SilentlyContinue
                Write-Log -Message "$($Displayname) service is Started." -severity 1 -component "InstallUpdate"
            }
                
        elseif($servicestatus -eq "Running")
            {
                Write-Log -Message "$($Displayname) service is already $($servicestatus)" -severity 1 -component "InstallUpdate"
            }
    }

##################################
##check for Target Release Version
##################################
try
    {
        $ProviderIDs = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts -ErrorAction stop | Select -ExpandProperty Name
        $DMClients = split-path $ProviderIDs -leaf -ErrorAction stop
    }
catch [system.exception]
    {
        Write-Log -Message "DMClient doesn't exist. $($_.exception.message)" -severity 3 -component "InstallUpdate"
    }

foreach($DMClient in $DMClients)
    {
        $ProductVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\providers\$DMClient\default\Device\Update" -Name ProductVersion -ErrorAction SilentlyContinue | select -expandproperty ProductVersion
        $TargetReleaseVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\providers\$DMClient\default\Device\Update" -Name TargetReleaseVersion -ErrorAction SilentlyContinue | select -expandproperty TargetReleaseVersion
        if($ProductVersion -or $TargetReleaseVersion)
            {
                Write-Log -Message "Target release version policy found: $ProductVersion $TargetReleaseVersion" -severity 1 -component "InstallUpdate"
            }
    }

#######################################
##check for Windows Update connectivity
#######################################
Function TestPort {
[cmdletbinding()]
param(
    [parameter(mandatory,valuefrompipeline)]
    [string]$Name,
    [parameter(mandatory)]
    [int[]]$Port
)

    process
    {
        foreach($i in $port)
        {
            try
            {
                $testPort = [System.Net.Sockets.TCPClient]::new()
                $testPort.SendTimeout = 5
                $testPort.Connect($name, $i)
                $result = $testPort.Connected
            }
            catch
            {
                $result = $_.Exception.InnerException.Message
            }
            
            [pscustomobject]@{
                ServerName = $name
                Port = $i
                TestConnection = $result
            }
        }
        
        $testPort.Close()
    }
}
$urls = 
"download.windowsupdate.com",
"download.microsoft.com",
"dl.delivery.mp.microsoft.com",
"sls.update.microsoft.com",
"update.microsoft.com",
"download.microsoft.com",
"catalog.update.microsoft.com",
"dl.delivery.mp.microsoft.com",
"sls.update.microsoft.com"

foreach($Url in $urls)
    {
        $ConnectivityCheck = TestPort -Name $Url -port 443
        $Server = $($ConnectivityCheck).ServerName
        $CStatus = $($ConnectivityCheck).TestConnection
        Write-Log -Message "Connection status to: $Server is $CStatus" -severity 1 -component "InstallUpdate"
    }

####################################################
##Will check for any current blocker for an upgrade
####################################################
Write-Log -Message "Will check for any current blocker for an upgrade" -severity 1 -component "InstallUpdate"
try
    {
        $CO21H2 = Get-ItemPropertyValue -Path $21H2 -Name "RedReason" -ErrorAction Stop
        if($CO21H2 -eq "None")
            {
                Write-Log -Message "No gated blocks found. Good to proceed with Windows 11 upgrade" -severity 1 -component "InstallUpdate"
            }
        else
            {
                Write-Log -Message "Device not ready for upgrade due to $($CO21H2) issue." -severity 2 -component "InstallUpdate"
                $continue = Read-host "Continue?(Y/N)"
                if($continue -eq "N") { Exit }
                    }
    }
catch [system.exception]
    {
        Write-Log -Message "Failed to find the key for Windows 11 CO21H2 due to $($_.exception.message)" -severity 3 -component "InstallUpdate"
        Write-Log -Message "Exiting" -severity 3 -component "InstallUpdate"
        $continue = Read-host "Continue?(Y/N)"
        if($continue -eq "N") { Exit }
    }

####################################################
## check for any previous windows 11 attempts
####################################################
$previousexecutions = Get-ItemPropertyValue -Path "HKLM:\SYSTEM\Setup\MoSetup\Tracking" -Name "InstallAttempts" -ErrorAction SilentlyContinue
Write-Log -Message "Scanning Windows 11 and checking current download state" -severity 1 -component "InstallUpdate"


#Scan and check for download status 
$i = 0
do
  {
    Write-Log -Message "Sleeping 15 seconds..." -severity 1 -component "InstallUpdate"
    sleep 15
    $i++
    $Updates = (Get-WindowsUpdate -title "Windows 11" -ErrorAction SilentlyContinue )[0] | Select-Object -Property Is*,RebootRequired 
    [string]$IsDownloaded = $updates.IsDownloaded
    [string]$IsRestartPending = $updates.RebootRequired

    if($updates)
        {
            if(($IsDownloaded.Trim()) -eq "True" -and (($IsRestartPending.trim()) -eq "True"))
                {
                    Write-Log -Message "Current download state: $($updates.IsDownloaded)" -severity 1 -component "InstallUpdate"
                    Write-Log -Message "Current pending restart state: $($updates.RebootRequired)" -severity 1 -component "InstallUpdate"
        
                    # Conditions to install
                    $ConfirmInstall = "N"
                    $ConfirmReport = "Y"
                }
            elseif(($IsDownloaded.Trim()) -eq "True" -and $($previousexecutions) -ne $Null)
                {
                    Write-Log -Message "Current download state: $($updates.IsDownloaded)" -severity 1 -component "InstallUpdate"
                    Write-Log -Message "Windows 11 installation has been attempted before or currently in progress" -severity 1 -component "InstallUpdate"
                    Write-Log -Message "Previous attempts: $($previousexecutions)" -severity 1 -component "InstallUpdate"
                
                    # Conditions to install
                    $ConfirmInstall = "N"
                    $ConfirmReport = "Y"
                }
            elseif(($IsDownloaded.Trim()) -eq "False" -and ($previousexecutions -eq $null) -and (($IsRestartPending.trim()) -eq "False"))
                {
                    Write-Log -Message "Current download state: $($updates.IsDownloaded)" -severity 1 -component "InstallUpdate"
                
                    # Conditions to install
                    $ConfirmInstall = "Y"
                    $ConfirmReport = "Y"
                }
        }
     else
        {
            Write-Log -Message "Retrying..." -severity 2 -component "InstallUpdate"
        }
    }until(($Updates) -or ($i -eq "10"))       

if($i -eq "10")
    {
        Write-Log -Message "Exceeded scanning attempts" -severity 1 -component "InstallUpdate"
        Write-Log -Message "Will test hardware readiness and retry" -severity 1 -component "InstallUpdate"

        # Testing hardware readiness yet again
        try
            {
                Start-BitsTransfer -Source "https://aka.ms/HWReadinessScript" -Destination "C:\Windows\Temp\HWReadinessScript.ps1" -ErrorAction Stop
                sleep 5
                Write-Log -Message "Downloaded readiness script" -severity 1 -component "InstallUpdate"

                #execute
                $execute = powershell.exe -executionpolicy bypass -file "C:\Windows\Temp\HWReadinessScript.ps1" 
                $output = ($execute | convertfrom-json).logging
                Write-Log -Message "$($output)" -severity 1 -component "InstallUpdate"
                Exit
            }
        catch [system.exception]
            {
                Write-Log -Message "Failed to download/execute readiness script due to $($_.exception.message)" -severity 3 -component "InstallUpdate"
                Exit
            }
    }
else
    {
        Write-Log -Message "Will continue with Windows 11 installation" -severity 1 -component "InstallUpdate"
    }

#$ConfirmInstall = Read-host "Continue to Windows 11 check?(Y/N)"
if($ConfirmInstall -eq "Y")
    {
        ######################
        ##Install for Windows 11
        ######################
        #Search
        $CurrentUpdate = Get-WindowsUpdate -Title "Windows 11"
        $win11 = $CurrentUpdate.Title
        Write-Log -Message "Found Windows 11 update" -severity 1 -component "InstallUpdate"
        if ($win11 -eq "Windows 11")
            {
                Write-Log -Message "Attempting to install: $($Win11)" -severity 1 -component "InstallUpdate"
                try
                    {
                        Write-Log -Message "Triggering installation..." -severity 1 -component "InstallUpdate"
                        Install-WindowsUpdate -Title $Win11 -ScheduleReboot $((Get-Date).AddDays($AddDays)) -Verbose -Confirm:$false -DeploymentAction Installation -ForceInstall | `
                        Out-File -FilePath "C:\windows\Temp\$($env:computername)-WindowsUpdateInstallation.Log" -ErrorAction stop
                        $Status = "Complete" 
                    }
                catch [system.exception]
                    {
                        Write-Log -Message "Failed to invoke update installation due to $($_.exception.message)" -severity 3 -component "InstallUpdate"
                    }
            }

        # Completion Criteria
        if($Status -eq "Complete")
            {
                Write-Log -Message "Finished installing!" -severity 1 -component "InstallUpdate"

                # Initiate Scan
                usoclient.exe startinteractivescan
                Write-Log -Message "Initiated Windows update scan" -severity 1 -component "InstallUpdate"
            }
    }
else
    {
        Write-Log -Message "Skipped Windows 11 install." -severity 2 -component "InstallUpdate"
    }

$ConfirmReport = Read-host "Continue to report to LA?(Y/N)"
if($ConfirmReport -eq "Y")
    {
        Write-Log -Message "Attempting to capture windows update events from event logs" -severity 1 -component "InstallUpdate"

        ################
        ## UPDATE LOG ##
        ################
        #region UpdateLog
        # Get WindowsUpdateClient events
        [array]$UpdateEvents = Get-WinEvent -FilterHashtable @{
            LogName='System'
            ProviderName='Microsoft-Windows-WindowsUpdateClient'
        } -ErrorAction Continue

        If ($UpdateEvents.Count -ge 1)
        {   
            [array]$UpdateEventArray = @()
            # process each event
            foreach ($UpdateEvent in $UpdateEvents)
            {
                # convert to xml
                [xml]$EventXML = $UpdateEvent.ToXml()

                # convert eventdata to hashtable
                $EventData = @{}
                foreach ($item in $EventXML.Event.EventData.Data)
                {
                    $EventData."$($Item.Name)" = $Item.'#text'
                }

                # Extract common entries
                If ($EventData.updateList)
                {
                    $UpdateName = $EventData.updateList
                }
                If ($EventData.updateTitle)
                {
                    $UpdateName = $EventData.updateTitle
                }
                If ($EventData.updateGuid)
                {
                    $UpdateGuid = $EventData.updateGuid.Replace('{','').Replace('}','')
                }
                If ($EventData.errorCode)
                {
                    $ErrorCode = $EventData.errorCode
                }
                If ($ErrorCode)
                {
                    $ErrorDescription = try{([ComponentModel.Win32Exception][int]$ErrorCode).Message}catch{$null}
                }
                If ($EventData.serviceGuid)
                {
                    $ServiceGuid = $EventData.serviceGuid.Replace('{','').Replace('}','')
                }

                # Extract KB number
                If ($UpdateName -match "\(KB")
                {
                    $KB = ($UpdateName.Split() | Where {$_ -match "\(KB"}).Replace("(",'').Replace(")",'').Trim()
                }
                else 
                {
                    $KB = $null    
                }

                # Extract Windows Display version for CUs
                If ($UpdateName -match "\(KB")
                {
                    $SplitArray = $UpdateName.split()
                    $Index = $SplitArray.IndexOf($($SplitArray.Where({$_ -match "version"}))) + 1
                    if ($UpdateName -match "Windows 11" -and $Index -eq 0)
                    {
                        $WindowsDisplayVersion = "21H2"
                    }
                    Elseif ($Index -eq 0)
                    {
                        $WindowsDisplayVersion = $null
                    }
                    else 
                    {
                        $WindowsDisplayVersion = "$($SplitArray[$Index].Trim())"
                    }
                }
                else 
                {
                    $WindowsDisplayVersion = $null 
                }

                # Extract Windows version
                If ($UpdateName -match "Windows 10")
                {
                    $WindowsVersion = "Windows 10"
                }
                ElseIf ($UpdateName -match "Windows 11")
                {
                    $WindowsVersion = "Windows 11"
                }
                else 
                {
                $WindowsVersion = $null 
                }

                # Add the event to a new array
                [array]$UpdateEventArray += [PSCustomObject]@{
                    TimeCreated = Get-Date $UpdateEvent.TimeCreated.ToString() -Format "s"
                    KeyWord1 = $UpdateEvent.KeywordsDisplayNames[0]
                    KeyWord2 = $UpdateEvent.KeywordsDisplayNames[1]
                    EventId = $UpdateEvent.Id
                    ServiceGuid = $ServiceGuid
                    UpdateName = $UpdateName
                    KB = $KB
                    UpdateId = $UpdateGuid
                    ErrorCode = $ErrorCode
                    ErrorDescription = $ErrorDescription
                    RebootRequired = $null
                    WindowsVersion = $WindowsVersion
                    WindowsDisplayVersion = $WindowsDisplayVersion
                    LastCU = $(Get-HotFix -ErrorAction SilentlyContinue | where-object {$_.hotfixid -ne "file 1"} | `
                                Select hotfixid,description,installedby,@{label="InstalledOn";e={[DateTime]::Parse($_.psbase.properties["installedon"].value,`
                                $([System.Globalization.CultureInfo]::GetCultureInfo("en-US")))}} | Where-Object InstalledOn -gt ([DateTime]::Parse('01/01/2016')) `
                                | Sort-Object installedon -Descending | Select-Object -First 1 | select -ExpandProperty HotfixId)
                    Computer = $env:COMPUTERNAME
                    OSBuild = $(Get-WmiObject -Class Win32_OperatingSystem | select -ExpandProperty Version)
                }
                #Remove-Variable ErrorCode -ErrorAction SilentlyContinue
                #Remove-Variable ErrorDescription -ErrorAction SilentlyContinue
            }
        }

        # remove Windows Store updates - they are numerous
        [System.Collections.ArrayList]$UpdateEventArrayList = [array]($UpdateEventArray | where {!$_.UpdateName.StartsWith("9")})

        # create a list of unique updates containing only the most recent entry per update
        [array]$FinalEventArray = @()
        $UniqueUpdateNames = $UpdateEventArrayList.UpdateName | Select -Unique
        foreach ($UniqueUpdateName in $UniqueUpdateNames)
        {
            $FinalEventArray += $UpdateEventArrayList.Where({$_.UpdateName -eq $UniqueUpdateName}) | where{$_.WindowsVersion -eq "Windows 11"} | Sort-Object -Property TimeCreated -Descending | Select -First 1 
        }

        if($FinalEventArray)
            {
                # check whether any updates are pending a reboot
                $RebootStatus = Get-WURebootStatus -Silent
                ($FinalEventArray | where {$_.UpdateId -eq $($FinalEventArray).UpdateId}).RebootRequired = $RebootStatus


                $MasterClass.SU_UpdateLog = $FinalEventArray
                #endregion

                #Filter
                $updatestatus = $MasterClass | select -ExpandProperty SU_UpdateLog | select Computer, UpdateId, UpdateName, Keyword1, Keyword2, RebootRequired, LastCU, OSBuild, EventId, ErrorCode, ErrorDescription, WindowsVersion, TimeCreated 


                $body = $updatestatus | convertto-json

                ############################################
                ##REPORT STATUS TO LOG ANALYTICS WORKSPACE
                ############################################

                $Result = Post-LogAnalyticsData -customerId $WorkspaceID -sharedKey $PrimaryKey -body $body -logType $Category
                If ($Result.GetType().Name -eq "WebResponseObject")
                    {
                        If ($Result.StatusCode -eq 200)
                            {
                                Write-Log -Message "Successfully forwarded status to log analytics" -severity 1 -component "InstallUpdate"
                            }
                        else 
                            {
                                Write-Log -Message "Issue found forwarding status to log analytics due to $($Result.Response)" -severity 2 -component "InstallUpdate"
                            }
                    }
                ElseIf ($Result.GetType().Name -eq "ErrorRecord")
                    {
                        Write-Log -Message "Error forwarding status to log analytics due to $($Result.Exception.Message)" -severity 3 -component "InstallUpdate"
                    }
            }
        else
            {
                Write-Log -Message "Skipped reporting as Windows 11 is not yet detected" -severity 2 -component "InstallUpdate"
                $continue = Read-host "Continue?(Y/N)"
                if($continue -eq "N") { Exit }
            }
        
    }
else
    {
        Write-Log -Message "Skipped reporting" -severity 2 -component "InstallUpdate"
        $continue = Read-host "Continue?(Y/N)"
        if($continue -eq "N") { Exit }
    }

