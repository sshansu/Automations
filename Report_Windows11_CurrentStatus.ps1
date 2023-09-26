#Read-host "Do you want to conteinue"

#################################
##MAIN SCRIPT STARTS
#################################
$ComputerName = $env:computername
$Module = "PSWindowsUpdate"
###
$SAS = "?sp=rw&st=2023-08-10T09:50:17Z&se=2023-12-31T17:50:17Z&spr=https&sv=2022-11-02&sr=c&sig=pGZhejvw3ef1TwguozxOlOX%2B8QTXuE01iyWk%2Bi8iLNM%3D"
$StorageName = "arcadewin11report.blob.core.windows.net"
$Container = "getwinreport"
$FilePath = "C:\Windows\Temp\$($ComputerName)_WinUpdateExport.csv"

#https://arcadewin11report.blob.core.windows.net/getwinreport?sp=rw&st=2023-08-10T09:50:17Z&se=2023-12-31T17:50:17Z&spr=https&sv=2022-11-02&sr=c&sig=pGZhejvw3ef1TwguozxOlOX%2B8QTXuE01iyWk%2Bi8iLNM%3D

###

# Reset current log
get-item "C:\windows\Temp\$($env:computername)-Win11Status.Log" -ea 0 | Remove-Item -Force -ea 0
get-item "C:\windows\Temp\$($env:computername)_WinUpdateExport.csv" -ea 0 | Remove-Item -Force -ea 0

#################################
##REPORTING AND LOGGING FUNCTIONS
#################################

#LogWrite function
Function Write-Log
{

    PARAM(
         [String]$Message,
         [String]$Path = "C:\windows\Temp\$($env:computername)-Win11Status.Log",
         [int]$severity,
         [string]$component
         )
         
         $TimeZoneBias = Get-CimInstance -Query "Select Bias from Win32_TimeZone"
         $Date = Get-Date -Format "HH:mm:ss.fff"
         $Date2 = Get-Date -Format "MM-dd-yyyy"
         $type =1
         
         "<![LOG[$Message]LOG]!><time=$([char]34)$date$($TimeZoneBias.bias)$([char]34) date=$([char]34)$date2$([char]34) component=$([char]34)$component$([char]34) context=$([char]34)$([char]34) type=$([char]34)$severity$([char]34) thread=$([char]34)$([char]34) file=$([char]34)$([char]34)>"| Out-File -FilePath $Path -Append -NoClobber -Encoding default
}

#Upload to Azure
Function UploadLogs-ToAzure
    {
     param($FilePath,$StorageName,$Container,$SAS)
        
        ########################################
        #### START: Upload to Azure Storage Blob
        ########################################
        # source File:
        $Sourcefile = "$FilePath"

        #Get the File-Name without path
        $name = (Get-Item $Sourcefile).Name


        ############## UPDATE URI AND SAS TOKEN BELOW #########################
        $uri = "https://$($StorageName)/$($Container)/$($name)$($SAS)"
        #######################################################################

        #Define required Headers
        $headers = @{
            'x-ms-blob-type' = 'BlockBlob'
        }

        #Upload File...
        try
            {
                Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -InFile $Sourcefile
                write-Log -Message "Status uploaded to storage" -severity 1 -component "File Upload" 
            }
        catch [system.exception]
            {
                write-Log -Message "Status upload failed with $($_.exception.Message)" -severity 3 -component "File Upload"       
            }
        ########################################
        #### END: Upload to Azure Storage Blob
        #########################################>
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

#################
## DEVICE INFO ##
#################
#region DeviceInfo
$Path = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion"
$ProductName = (Get-CimInstance -ClassName Win32_OperatingSystem -Property Caption).Caption.Replace("Microsoft ",'')
$DisplayVersion = (Get-ItemProperty -Path $Path -Name DisplayVersion -ErrorAction SilentlyContinue).DisplayVersion
$CurrentBuild = (Get-ItemProperty -Path $Path -Name CurrentBuild -ErrorAction SilentlyContinue).CurrentBuild
$UBR = (Get-ItemProperty -Path $Path -Name UBR -ErrorAction SilentlyContinue).UBR


####################################################
##Check for current WU WSUS registry key settings
####################################################
#region WU WSUS
$registryPath = "HKLM:\SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU"
$KeyName = "UseWUServer"

Try
    {
        if(Test-Path -Path $registryPath)
            {
                # Get WU Server value
                $checkWUkey = Get-ItemPropertyValue -Path $registryPath -Name $KeyName -ErrorAction Stop
                if($checkWUkey -eq "1")
                    {
                        $UseWUServer = "Yes"
                    }
                else
                    {
                       $UseWUServer = "No"
                    }
        
            } 
        else 
            {
                $UseWUServer = "NA"
            }
    }
catch [system.exception]
    {
        $_.exception.message
    }


##################################
##check for Target Release Version
##################################
#region Target Release Version
try
    {
        $ProviderIDs = Get-ChildItem -Path HKLM:\SOFTWARE\Microsoft\Provisioning\OMADM\Accounts -ErrorAction stop | Select -ExpandProperty Name
        if(!($ProviderIDs)) { $TRV = $Null } else {  $DMClients = split-path $ProviderIDs -leaf -ErrorAction SilentlyContinue }
        foreach($DMClient in $DMClients)
            {
                $ProductVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\providers\$DMClient\default\Device\Update" -Name ProductVersion -ErrorAction SilentlyContinue | select -expandproperty ProductVersion
                $TargetReleaseVersion = Get-ItemProperty -Path "HKLM:\SOFTWARE\Microsoft\PolicyManager\providers\$DMClient\default\Device\Update" -Name TargetReleaseVersion -ErrorAction SilentlyContinue | select -expandproperty TargetReleaseVersion
                if((!($ProductVersion)) -and (!($TargetReleaseVersion)))
                    {
                        $TRV = $Null
                    }
                else
                    {
                        $TRV = "$ProductVersion $TargetReleaseVersion"
                    }
        
            }
    }
catch [System.Exception]
    {
         $_.exception.message
    }
 

#######################################
##check for Windows Update connectivity
#######################################
#region WU Connectivity
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

$hash = @()
foreach($Url in $urls)
    {
        $ConnectivityCheck = TestPort -Name $Url -port 443
        $Server = $($ConnectivityCheck).ServerName
        $CStatus = $($ConnectivityCheck).TestConnection
        $hash += New-Object -TypeName PSCustomObject -Property @{
        Server = $Server
        CStatus = $CStatus
        }
    }
if(($Hash.CStatus) -contains "True")
    {
        $UrlConnection = $True
    }
else
    {
        $UrlConnection = $False
    }


####################################################
#Get download status
####################################################
if($ProductName -match "Windows 10")
    {
        try
            {
                # Get download status
                $Updates = (Get-WindowsUpdate -title "Windows 11" -ErrorAction SilentlyContinue )[0] | Select-Object -Property Is*,RebootRequired 
                [string]$IsDownloaded = $updates.IsDownloaded
                if(!($updates))
                    { 
                        $Win11Downloaded = "Not detected"
                    }
                else
                    { 
                         $Win11Downloaded = $IsDownloaded 
                    }
            }
        catch [system.exception]
            {
                $_.exception.message
            }
        
        ####################################################
        ## MOSetup
        ####################################################
        $MOTracking = "HKLM:\SYSTEM\Setup\MoSetup\Tracking"
        $MOVolatile = "HKLM:\SYSTEM\Setup\MoSetup\Volatile"
      
        # Download Progress?
        $Win11PreDownloadMode = Get-ItemPropertyValue -Path $MOVolatile -Name "PreDownloadMode" -ErrorAction stop
        if(($Win11Downloaded -ne "Not detected") -and !($Win11PreDownloadMode))
            {
                $DownloadStatus = "-1"
            }
        else
            {
                $DownloadStatus = $Win11PreDownloadMode
            }
                    
        $Previousexecution = Get-ItemPropertyValue -Path $MOTracking -Name "InstallAttempts" -ErrorAction stop
        $Win11SetupProgress = Get-ItemPropertyValue -Path $MOVolatile -Name "SetupProgress" -ErrorAction stop

        # ScheduledRebootTime
        $RegScheduledReboot = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\StateVariables -Name ScheduledRebootTime -ErrorAction SilentlyContinue | Select -ExpandProperty ScheduledRebootTime
        If ($RegScheduledReboot)
            {
                $FixRegScheduledReboot = [DateTime]::FromFileTimeUtc($RegScheduledReboot) | Get-Date -format "yyyy-MM-ddTHH:mm:ssZ"
                $ScheduledRebootTime = (Get-Date $FixRegScheduledReboot -ErrorAction Stop).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss")
            }
        else 
            {
                $ScheduledRebootTime = $null
            }

        # PendingRebootStartTime
        $RegPendingRebootTime = Get-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\WindowsUpdate\UX\Settings -Name PendingRebootStartTime -ErrorAction SilentlyContinue | Select -ExpandProperty PendingRebootStartTime
        If ($RegPendingRebootTime)
            {
                $PendingRebootTime = (Get-Date $RegPendingRebootTime).ToLocalTime().ToString("yyyy-MM-dd HH:mm:ss") 
            }
        else 
            {
                $PendingRebootTime = $null
                        
            }



        ####################################################
        ##Will check for any current blocker for an upgrade
        ####################################################
        #region upgrade blockers
        $21H2 = "HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion\AppCompatFlags\TargetVersionUpgradeExperienceIndicators\CO21H2"
        try
            {
                $CO21H2 = Get-ItemPropertyValue -Path $21H2 -Name "RedReason" -ErrorAction Stop
                if($CO21H2 -eq "None")
                    {
                        $GatedBlock = "No gated blocks"
                    }
                else
                    {
                        $GatedBlock = $CO21H2 
                    }
            }
        catch [system.exception]
            {
                $_.exception.message 
                $GatedBlock = "CO21H2 missing"
            }
    }
else
    {
        $GatedBlock = "Not Applicable"
        $Win11Downloaded = "Not Applicable"
        $Win11PreDownloadMode = "Not Applicable"
        $Previousexecution = "Not Applicable"
        $Win11SetupProgress = "Not Applicable"
    }


################
## UPDATE LOG ##
################
#region UpdateLog
Write-Log -Message "Attempting to capture windows update events from event logs" -severity 1 -component "InstallUpdate"

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
            TimeCreated = [datetime]::Parse($(Get-Date $UpdateEvent.TimeCreated.ToString() -Format "s"))
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
            CurrentPatchLevel = "$CurrentBuild.$UBR"
            OS = "$ProductName $DisplayVersion"
            UseWUServer = $UseWUServer
            TargetReleaseVersion = $TRV
            UrlConnection = $UrlConnection
            GatedBlock = $GatedBlock
            Win11PreDownloadMode =  $DownloadStatus
            Win11Downloaded = $Win11Downloaded
            Win11InstallAttempts = $Previousexecution
            SetupProgress = $Win11SetupProgress
            PendingRebootTime =  if(!($PendingRebootTime)){ $null } else { $PendingRebootTime }
            ScheduledRebootTime = if(!($ScheduledRebootTime)){ $null } else { $ScheduledRebootTime }
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
    $FinalEventArray = $UpdateEventArrayList.Where({$_.UpdateName -match "Windows 11"}) | Sort-Object -Property TimeCreated -Descending | Select -First 1
    if(!($FinalEventArray))
        {
            $FinalEventArray = $UpdateEventArrayList.Where({$_.UpdateName -match "Windows 10"}) | Sort-Object -Property TimeCreated -Descending | Select -First 1
        }
}

# check whether any updates are pending a reboot
$RebootStatus = Get-WURebootStatus -Silent
($FinalEventArray | where {$_.UpdateId -eq $($FinalEventArray).UpdateId}).RebootRequired = $RebootStatus

$MasterClass.SU_UpdateLog = $FinalEventArray
#endregion

#Filter
$updatestatus = $MasterClass | select -ExpandProperty SU_UpdateLog | select TimeCreated, Computer, EventId, UpdateId, UpdateName, Keyword1, Keyword2, RebootRequired, LastCU, OSBuild, CurrentPatchLevel, OS, UseWUServer, `
TargetReleaseVersion, UrlConnection, GatedBlock, Win11PreDownloadMode, Win11Downloaded, Win11InstallAttempts, SetupProgress, PendingRebootTime, ScheduledRebootTime, ErrorCode, ErrorDescription

#export
$UpdateStatus | Export-csv -Path $FilePath -Append -NoTypeInformation

############################################
##REPORT STATUS TO LOG ANALYTICS WORKSPACE
############################################

UploadLogs-ToAzure `
        -SAS $SAS `
        -StorageName $StorageName `
        -Container $Container `
        -FilePath $FilePath

Exit 0