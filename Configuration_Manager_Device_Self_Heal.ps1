#####################################################################################################
# ALL THE SCRIPTS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED                   #
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR         #
# FITNESS FOR A PARTICULAR PURPOSE.                                                                 #
#                                                                                                   #
# This script is not supported under any Microsoft standard support program or service.             #
# The script is provided AS IS without warranty of any kind.                                        #
#                                                                                                   #
# Script Name : SelfHeal.PS1                                                           #
# Purpose     : The script is  to discover potential cause of client inactivity                 #
#               and stores results to azure storage.                                                #
# Version     : v1.0                                                                                #
# Created by  : sshansu@microsoft.com									          #
#                                                                                                   #    
#####################################################################################################

[xml]$xml = @"
<sites>
  <default>
    <!--- Site Settings -->
    	<PrimarySiteServer>AZGLGLNEVLA03.Global.batgen.com</PrimarySiteServer>
    	<PrimarySiteURL>https://AZGLGLNEVLA03.Global.batgen.com</PrimarySiteURL>
    	<SCCMEnv>2207</SCCMEnv>
    	<SiteCode>MHN</SiteCode>
	<MP OnPrem="AZGLGLNEVLA03.Global.batgen.com" Internet="BATCLOUDMGNE.CLOUD.BAT.NET/CCM_Proxy_MutualAuth/72057594037928288" />
	<ForNonClients Flag="Yes" LocalClientPath="C:\Windows\CCMSetup" InstallParams="C:\Windows\CCMSetup\ccmsetup.exe CCMHOSTNAME=BATCLOUDMGNE.CLOUD.BAT.NET/CCM_Proxy_MutualAuth/72057594037928288 SMSMP=AZGLGLNEVLA03.Global.batgen.com /mp:BATCLOUDMGNE.CLOUD.BAT.NET/CCM_Proxy_MutualAuth/72057594037928288 SMSSiteCode=BAT /UsePKICert /NoCRLCheck" />
	<Service>
        <Name>BITS</Name>
        <Name>CCMEXEC</Name> 
        <Name>WINMGMT</Name>  
        <Name>WUAUSERV</Name>
        <Name>CryptSvc</Name>
    </Service>
	<Log Size="5" />
	<Inventory Name="Hardware" GUID="{00000000-0000-0000-0000-000000000001}" Days="7" />
	<Inventory Name="Heartbeat" GUID="{00000000-0000-0000-0000-000000000003}" Days="7" />
	<Client Version="5.00.9078.1025" UpgradeCommand="ccmsetup.exe /Autoupgrade" />
	<DC>global.batgen.com</DC> 
	<DeplUniqueID>F793700B</DeplUniqueID>
</default>
</sites>
"@

# Create required folders
$machine = $env:COMPUTERNAME
$parentfolder = "C:\Windows\Temp\ClientHealth"
$checkRem = test-path $parentfolder -ErrorAction SilentlyContinue
If($checkRem -eq 'True')
    {
        get-childitem $parentfolder -ea 0 | Remove-Item -Force
    }
else
    {
        New-Item $parentfolder -ItemType Directory -Force | %{$_.Attributes = "hidden"}
    }

#LogWrite function
Function Write-Log
{

    PARAM(
         [String]$Message,
         [String]$Path = "C:\windows\Temp\ClientHealth\$($env:computername)-RemediationStatus.Log",
         [int]$severity,
         [string]$component
         )
         
         $TimeZoneBias = Get-CimInstance -Query "Select Bias from Win32_TimeZone"
         $Date = Get-Date -Format "HH:mm:ss.fff"
         $Date2 = Get-Date -Format "MM-dd-yyyy"
         $type =1
         
         "<![LOG[$Message]LOG]!><time=$([char]34)$date$($TimeZoneBias.bias)$([char]34) date=$([char]34)$date2$([char]34) component=$([char]34)$component$([char]34) context=$([char]34)$([char]34) type=$([char]34)$severity$([char]34) thread=$([char]34)$([char]34) file=$([char]34)$([char]34)>"| Out-File -FilePath $Path -Append -NoClobber -Encoding default
}

Write-Log -Message " " -severity 1 -component "Initialize Script"
Write-Log -Message "*****************************************" -severity 1 -component "Initialize Script"
Write-Log -Message "Script start time: $(get-date -format g)" -severity 1 -component "Initialize Script"
Write-Log -Message "*****************************************" -severity 1 -component "Initialize Script"
Write-Log -Message " " -severity 1 -component "Initialize Script"

# Main Function
function Get-XMLPrimarySite {
    $obj = $xml.Sites.default.PrimarySiteServer
    Write-Output $obj
}

function Get-XMLSiteCode {
    $obj = $xml.Sites.default.SiteCode
    Write-Output $obj
}

function Get-XMLManagementPoint {
    $obj = $xml.Sites.default.MP
    Write-Output $obj
}

function Get-XMLUpdateDeploymentID {
    $obj = $xml.Sites.default.DeplUniqueID
    Write-Output $obj
}

function Get-XMLClientFlag {
    $obj = $xml.Sites.default.ForNonClients
    Write-Output $obj
}

function Get-Services {
    $obj = $xml.sites.default.Service.Name
    Write-Output $obj
}

Function Get-LogParams {
    $obj = $xml.sites.default.Log
    Write-Output $obj
}

Function Get-InventoryParams {
    $obj = $xml.sites.default.Inventory
    Write-Output $obj
}

Function Get-XMLClientVersion
    {
        $obj = $xml.sites.default.Client.Version
        Write-Output $obj
    }

Function Get-XMLClientUpgradeCmd
    {
        $obj = $xml.sites.default.Client.UpgradeCommand
        Write-Output $obj
    }

Function Get-StateMessageConfig
    {
        $obj = $xml.sites.default.StateMessage
        Write-Output $obj
    }

Function Get-XMLClientRemediate {
        $obj = $Xml.Sites.default.Remediation #| Where-Object {$_.Name -like 'GPUpdate'} | Select-Object -ExpandProperty 'Fix'
        Write-Output $obj
    }

Function Get-DCName {
        $obj = $Xml.Sites.default.DC
        Write-Output $obj
    }

<#
# Reset Script Log

$value = $(Get-LogParams).executions
if($(Get-LogParams).executions -lt 2)
    {
        $newvalue = $Value++
        $Executions = $xml.sites.default.Log.GetAttribute("Executions");
        $Executions = "$newvalue"; $xml.sites.default.log.SetAttribute("Executions", $Executions);
        $xml.Save($XMLFilePath)
    }
else
    {
        # Reset counter
        $Executions = $xml.sites.default.Log.GetAttribute("Executions");
        $Executions = "0"; $xml.sites.default.log.SetAttribute("Executions", $Executions);
        $xml.Save($XMLFilePath)

        # Reset Log
        Remove-Item -Path "C:\windows\temp\$($env:computername)-RemediationStatus.log" -Force
    }
#>

# Host Name - External
Function Get-Hostname {
        $PCName = $env:COMPUTERNAME
        Write-Output $PCName
}
Write-Log -Message "PC Name: $(Get-Hostname)" -severity 1 -component "Get Property"

# PC Type - External
Function Get-PCType 
    {
        $obj = (Get-WmiObject -Class win32_computersystem -ErrorAction SilentlyContinue | Select-Object pcsystemtype).pcsystemtype
        $SystemType = Switch ($obj) {
            1 {"Desktop"}
            2 {"Laptop"}
            3 {"Workstation"}
            4 {"Enterprise Server"}
            5 {"Small Office and Home Office (SOHO) Server"}
            6 {"Appliance PC"}
            7 {"Performance Server"}
            8 {"Maximum"}
            default {"Not a known Product Type"}
               } 
        Write-Output $SystemType
}
Write-Log -Message "System Type: $(Get-PCType)" -severity 1 -component "Get Property"

# Detect Client Domain - External
Function Get-Domain {
    try {
        if ($PowerShellVersion -ge 6) { $obj = (Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain }
        else { $obj = (Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue).Domain }
    }
    catch { $obj = $false }
    finally { Write-Output $obj }
}Write-Log -Message "Client Domain: $(Get-Domain)" -severity 1 -component "Get Property"

 # Active Directory Site - External
 Function Get-ActiveDirectorySite
    {
        try
            {
                $CurrentAdsite = ([System.DirectoryServices.ActiveDirectory.ActiveDirectorySite]::GetComputerSite()).name
                $ads = $CurrentAdsite.split("-") | Select-Object -First 1
                Write-Log -Message "Active Directory Site: $ads" -severity 1 -component "Get Property"
            }
        catch [system.exception]
            {
                Write-Log -Message "Active Directory Site: $($_.exception.Message)" -severity 2 -component "Get Property"
            }
    } Get-ActiveDirectorySite

 # Gather info about the computer - External
    Function Get-Info {
        if ($PowerShellVersion -ge 6) {
            $OS = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue
            $ComputerSystem = Get-CimInstance Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($ComputerSystem.Manufacturer -like 'Lenovo') { $Model = (Get-CimInstance Win32_ComputerSystemProduct -ErrorAction SilentlyContinue).Version }
            else { $Model = $ComputerSystem.Model }
        }
        else {
            $OS = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue
            $ComputerSystem = Get-WmiObject Win32_ComputerSystem -ErrorAction SilentlyContinue
            if ($ComputerSystem.Manufacturer -like 'Lenovo') { $Model = (Get-WmiObject Win32_ComputerSystemProduct -ErrorAction SilentlyContinue).Version }
            else { $Model = $ComputerSystem.Model }
        }

        $obj = New-Object PSObject -Property @{
            Hostname = $ComputerSystem.Name;
            Manufacturer = $ComputerSystem.Manufacturer
            Model = $Model
            Operatingsystem = $OS.Caption;
            Architecture = $OS.OSArchitecture;
            Build = $OS.BuildNumber;
            #InstallDate = Get-SmallDateTime -Date ($OS.ConvertToDateTime($OS.InstallDate))
            LastLoggedOnUser = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\Authentication\LogonUI\' -ErrorAction SilentlyContinue).LastLoggedOnUser;
        }

        $obj = $obj
        Write-Output $obj
    } Write-Log -Message "Device Details: $(Get-Info)" -severity 1 -component "Get Property"

    # Operating System - External
    Function Get-OperatingSystem {
        $OS = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue 


        # Handles different OS languages
        $OSArchitecture = ($OS.OSArchitecture -replace ('([^0-9])(\.*)', '')) + '-Bit'
        switch -Wildcard ($OS.Caption) {
            "*Embedded*" {$OSName = "Windows 7 " + $OSArchitecture}
            "*Windows 7*" {$OSName = "Windows 7 " + $OSArchitecture}
            "*Windows 8.1*" {$OSName = "Windows 8.1 " + $OSArchitecture}
            "*Windows 10*" {$OSName = "Windows 10 " + $OSArchitecture}
            "*Server 2008*" {
                if ($OS.Caption -like "*R2*") { $OSName = "Windows Server 2008 R2 " + $OSArchitecture }
                else { $OSName = "Windows Server 2008 " + $OSArchitecture }
            }
            "*Server 2012*" {
                if ($OS.Caption -like "*R2*") { $OSName = "Windows Server 2012 R2 " + $OSArchitecture }
                else { $OSName = "Windows Server 2012 " + $OSArchitecture }
            }
            "*Server 2016*" { $OSName = "Windows Server 2016 " + $OSArchitecture }
            "*Server 2019*" { $OSName = "Windows Server 2019 " + $OSArchitecture }
        }
        Write-Output $OSName
    }

    # Disk space on PC - External
    Function Get-OSDiskFreeSpace 
        {
            if ($PowerShellVersion -ge 6) { $driveC = Get-CimInstance -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "$env:SystemDrive"} | Select-Object FreeSpace, Size }
            else { $driveC = Get-WmiObject -Class Win32_LogicalDisk | Where-Object {$_.DeviceID -eq "$env:SystemDrive"} | Select-Object FreeSpace, Size }
            $freeSpace = (($driveC.FreeSpace / 1024 / 1024 / 1024))
            Write-Output ([math]::Round($freeSpace,2))
        } Write-Log -Message "Free Disk Space: $(Get-OSDiskFreeSpace) GB" -severity 1 -component "Get Property"

    # Last Boot Time - External
    Function Get-LastBootTime 
        {
            if ($PowerShellVersion -ge 6) { $wmi = Get-CimInstance Win32_OperatingSystem -ErrorAction SilentlyContinue }
            else { $wmi = Get-WmiObject Win32_OperatingSystem -ErrorAction SilentlyContinue }
            $obj = $wmi.ConvertToDateTime($wmi.LastBootUpTime)
            Write-Output $obj
        } Write-Log -Message "Last Boot Date: $(Get-LastBootTime)" -severity 1 -component "Get Property"

# Detect if client exists - External
Function Get-Client
    {
        if(!(get-service -Name CcmExec -ea 0))
            {
                $Clientexist = 'No'
            }
        else
            {
                $Clientexist = 'Yes'
            }
        Write-Output $Clientexist
    }
Write-Log -Message "Is Client: $(Get-Client)" -severity 1 -component "Get Property"

#Check WMI Repository - External
function test-wmirepository 
{
    param(
        [string]$path
        )

if ($path) {
    if (-not(Test-Path $path)) {
    Throw "$path not found"
    }
    else {
    $path
    $exp_verify = "winmgmt /verifyrepository $path"
    }
}

else {
    $exp_verify = "winmgmt /verifyrepository"

}
Invoke-Expression -Command $exp_verify

}

#Call the function to check consistency of repository - External

$check = test-wmirepository
if ($check -eq "WMI repository is consistent")
    {
        $wmi = 'Consistent'
        Write-Log -Message "$check" -severity 1 -component "Get Property"
    }
elseif($check -match "failed")
    {
        $wmi = "failed"
        Write-Log -Message "$check" -severity 3 -component "Get Property"
    }
elseif($check -match "inconsistent") {
        Write-Log -Message "$check" -severity 2 -component "Get Property"
    }

# Get Network Details - External
Function Get-IPAddress 
    {
        $PingSelf = (Test-Connection -ComputerName ($env:COMPUTERNAME) -Count 1 -ErrorAction SilentlyContinue  | Select IPV4Address).IPV4Address
        $IPAddress = ($PingSelf).IPAddressToString
        Write-Output $IPAddress
    }

# Get Network Details - External
Function Get-SubnetMask
    {
        $nic_configuration = gwmi -computer . -class "win32_networkadapterconfiguration" -ErrorAction SilentlyContinue | Where-Object {$_.defaultIPGateway -ne $null}
        $Mask = $nic_configuration.ipsubnet
        $SM = switch ($Mask) {
        '255.255.255.255' {"255.255.255.255"}
        '255.255.255.254' {"255.255.255.254"}
        '255.255.255.252' {"255.255.255.252"}
        '255.255.255.248' {"255.255.255.248"}
        '255.255.255.240' {"255.255.255.240"}
        '255.255.255.224' {"255.255.255.224"}
        '255.255.255.192' {"255.255.255.192"}
        '255.255.255.128' {"255.255.255.128"}
        '255.255.255.0'	{"255.255.255.0"}
        '255.255.254.0'	{"255.255.254.0"}
        '255.255.252.0'	{"255.255.252.0"}
        '255.255.248.0'	{"255.255.248.0"}
        '255.255.240.0'	{"255.255.240.0"}
        '255.255.224.0'	{"255.255.224.0"}
        '255.255.192.0'	{"255.255.192.0"}
        '255.255.128.0'	{"255.255.128.0"}
        '255.255.0.0' {"255.255.0.0"}
        '255.254.0.0' {"255.254.0.0"}
        '255.252.0.0' {"255.252.0.0"}
        '255.248.0.0' {"255.248.0.0"}
        '255.240.0.0' {"255.240.0.0"}
        '255.224.0.0' {"255.224.0.0"}
        '255.192.0.0' {"255.192.0.0"}
        '255.128.0.0' {"255.128.0.0"}
        '255.0.0.0'	{"255.0.0.0"}
        '254.0.0.0'	{"254.0.0.0"}
        '252.0.0.0'	{"252.0.0.0"}
        '248.0.0.0'	{"248.0.0.0"}
        '240.0.0.0'	{"240.0.0.0"}
        '224.0.0.0'	{"224.0.0.0"}
        '192.0.0.0'	{"192.0.0.0"}
        }

        [string]$SubnetMask = $null
        $SubnetMask = $SM -join ","
        Write-Output $SubnetMask
    } Write-Log -Message "IPAddress: $(Get-IPAddress) with subnet mask of $(Get-SubnetMask)" -severity 1 -component "Get Property" 

      
#check if DCOM is enabled - External
Function Get-DCOMHealth
    {
        $dcomvalue = (get-itemproperty -Path HKLM:\SOFTWARE\Microsoft\Ole -Name enabledCOM -ErrorAction SilentlyContinue | Select-Object enableDCOM).enabledcom
        Write-Output $dcomvalue
    } if($(Get-DCOMHealth) -eq "Y")
        {
            Write-Log -Message "DCOM is enabled" -severity 1 -component "Get Property" 
        }
      else
        {
            Write-Log -Message "DCOM is disabled" -severity 2 -component "Get Property" 
        }


# DNS Configuration - External
  Function Test-DNSConfiguration
    {
        Write-Log -Message "Checking if DNS returns same hostname for IP Address: $(Get-IPAddress)" -severity 1 -component "Get Property"
        $IP = Get-IPAddress #(Resolve-DnsName -Name $(Get-Hostname) | Where-Object{$_.ipaddress -like "*.*.*.*"}).ipaddress
        Try
            {
                $InDNS = [System.Net.Dns]::GetHostEntry($ip).Hostname
                $NetbiosInDNS = $InDNS.Split(".") | Select-Object -First 1
                            
                # Compare NetBIOS
                if($NetbiosInDNS -ne $(Get-Hostname))
                    {
                        Write-Log -Message "DNS Check: FAILED. IP Address: $IP has been already assigned to another PC: $NetbiosInDNS. Trying to resolve by registerting with DNS server" -severity 2 -component "Get Property"
                        Write-Log -Message "Performing RegisterDNS command" -severity 1 -component "Get Property"
                        ipconfig /registerdns | out-null
                        Write-Log -Message "Sleeping for 30 seconds" -severity 1 -component "Get Property"
                        sleep -Seconds 30
                    }
                elseif($NetbiosInDNS -eq $(Get-Hostname))
                    {
                        Write-Log -Message "DNS Check: SUCCESS. Valid Host Entry exists in DNS." -severity 1 -component "Get Property"
                    }
            }
        catch [System.Exception]
            {
                If($_.Exception.Message)
                    {
                        Write-Log -Message "IP Address: $IP + $($_.Exception.Message)" -severity 2 -component "Get Property"
                    }
            }
     } Test-DNSConfiguration

#### Remdiations - External
Write-Log -Message "Detecting and Remediating Services" -severity 1 -component "Get Property"
#check for services in StopPending state.
function Resolve-PendingService 
    { 
        $Services = Get-WmiObject -Class win32_service -Filter "state = 'stop pending'" -ErrorAction SilentlyContinue
        if ($Services) 
            { 
                foreach ($service in $Services) 
                    { 
                        try { 
                                Write-Log -Message "'$service' found in 'Stopping' state. Terminating and restarting service." -severity 2 -component "Get Property"
                                Stop-Process -Id $service.processid -Force -PassThru -ErrorAction Stop 
                            } 
                        catch [System.Exception]
                            { 
                                Write-Log -Message "Unexpected Error. Error details: $($_.Exception.Message)" -severity 2 -component "Get Property"
                            }  
                    } 
            } 
        else 
            { 
                Write-Log -Message "There are currently no services with a status of 'Stopping'" -severity 1 -component "Get Property"
            } 
     } Resolve-PendingService

# Remediate external dependencies. Check services and set desired state to Auto and Running.  - External

foreach($service in Get-Services)
{
    #Getting Display names
    $Displayname = (Get-Service -Name $service -ea 0).DisplayName
    If($Displayname -eq $null){$Displayname = $service}

      
    $exist = (get-service -Name $service -ea 0) 
    if($exist)
        {
            #Verify/Remediate service startup type "automatic"
            $servicetype = (Get-WmiObject -Class win32_service -ErrorAction SilentlyContinue | where {$_.name -eq "$service"}).startmode
            if($servicetype -eq "Auto")
                {
                    Write-Log -Message "$($Displayname) service type: $($servicetype)" -severity 1 -component "Get Property"
                }
            else
                {
                    #Change servicetype
                    Write-Log -Message "$($Displayname) service type is set to $($servicetype). Changing to Automatic" -severity 1 -component "Get Property"
                    $settoAuto = Set-Service -Name $service -StartupType Automatic -ErrorAction SilentlyContinue
                }
        
        #Verify/Remediate WMI service status "running"
        $servicestatus = (get-service -Name $service -ea SilentlyContinue | Select-Object status).status
        If($servicestatus -eq "Stopped")
            {
                Write-Log -Message "$($Displayname) service is $servicestatus. Attempting to start the service." -severity 1 -component "Get Property"
                start-Service -Name $service -ErrorAction SilentlyContinue
                $counter=0
                while($servicestatus.Status -ne "Running")
                    {
                        $retryCount++
                        $counter++
                        $servicestatus = Get-Service -Name $service
                        Write-Log -Message "$($Displayname) service is Starting." -severity 1 -component "Get Property"
                        Start-Sleep 2
                        if( $retryCount -gt 1)
                            {
                                break;
                            }
                    }
                    $retryCount=0
                    Write-Log -Message "$($Displayname) service is Started." -severity 1 -component "Get Property"
                    Write-Log -Message " " -severity 1 -component "Get Property"

            }
                
        elseif($servicestatus -eq "Running")
            {
                Write-Log -Message "$($Displayname) service is already $($servicestatus)" -severity 1 -component "Get Property"
                Write-Log -Message " " -severity 1 -component "Get Property"
            }
        
         }   
    
    else
    {
        Write-Log -Message "Warning: $($Service) does not exist" -severity 2 -component "Get Property"
        Write-Log -Message " " -severity 1 -component "Get Property"
    }
}

# Remediate DCOM - External
Function Resolve-DCOM 
    {
        If($(Get-DCOMHealth) -eq "N")
            {
                Write-Log -Message "DCOM is disabled. Enabling DCOM" -severity 2 -component "Get Property"
                Set-ItemProperty -Path HKLM:\SOFTWARE\Microsoft\Ole -Name enableDCOM -Value Y
                    if((Get-Service -Name CcmExec))
                        {
                            Get-Service -Name CcmExec | Restart-Service
                            Write-Log -Message "Restarted SMS Agent Host Service." -severity 1 -component "Get Property"
                        }
            }
    }
Resolve-DCOM

#Salvage WMI Repository if found Inconsistent. - External
function Salvage-wmirepository
    {
        $exp_reset = "winmgmt /salvagerepository"
        Invoke-Expression -Command $exp_reset
    } 

if ($(test-wmirepository) -eq 'WMI repository is consistent')
    {
        Write-Log -Message "WMI is consistent, so rebuild was not performed!" -severity 1 -component "Get Property"
    }

elseif($(test-wmirepository) -like '*Inconsistent*') 
    {
        Write-Log -Message "WARNING!! WMI is inconsistent. Starting repair of WMI Repository. Salvate repository will be executed on the system" -severity 2 -component "Get Property"
        
        # Call the function to reset corrupt repository
        Salvage-wmirepository

        # Wait for 2 mins
        Write-Log -Message "Sleeping for 120 seconds" -severity 1 -component "Get Property"
        sleep -Seconds 120
    }
elseIf($(test-wmirepository) -like '*failed*')
    {
        Write-Log -Message "Skipping WMI check due to Access Denied" -severity 3 -component "Get Property"
    }
    
# Function to install Client - External
Function Install-Client 
    {
        if(($(Get-XMLClientFlag).Flag) -eq 'Yes' -or ($(Get-Client) -eq 'NO'))
            {
                Write-Log -Message "Flagged for Client installation" -severity 2 -component "Get Property" 
                Try
                    {   
                        if((Test-Path $(Get-XMLClientFlag).LocalClientPath) -eq "True")
                            {
                                Write-Log -Message "CCMSetup folder exists locally on %Windir%\CCMSetup" -severity 1 -component "Get Property"
                                $ClientInstall=invoke-wmimethod -path win32_process -name create -argumentlist "$((Get-XMLClientFlag).InstallParams)"
                            }
                        else
                            {
                                Write-Log -Message "Error: CCMSetup folder does not exist on $((Get-XMLClientFlag).LocalClientPath). Exiting Script." -severity 3 -component "Get Property"
                                EXIT
                            }

                    if($ClientInstall.ReturnValue -eq 0) {
                            Write-Log -Message "SCCM Client Install triggered. Check %windir%\CCMSetup\Logs\CCMSetup.log for progress. Exiting Script." -severity 1 -component "Get Property"
                            Wait-Process -Id $ClientInstall.ProcessId
                            sleep -seconds 5
                            $return = 1
                            EXIT
                        }
                    else
                        {
                            Write-Log -Message "SCCM Client installation trigger failed. Exiting Script." -severity 3 -component "Get Property"
                            $return = -1
                            EXIT
                        }
                    }
                catch [system.exception]
                    {
                        Write-Log -Message "Failed to invoke Client installation: $($_.Exception.Message). Exiting Script." -severity 3 -component "Get Property"
                        EXIT
                    }
            }
    }


# Check if Client exists - Internal
if($(Get-Client) -eq "yes")
    {
        # Detect client version
        Function Get-ClientVersion {
                try {
                    if ($PowerShellVersion -ge 6) { $obj = (Get-CimInstance -Namespace root/ccm SMS_Client).ClientVersion }
                    else { $obj = (Get-WmiObject -Namespace root/ccm SMS_Client).ClientVersion }
                }
                catch { $obj = $false }
                finally { Write-Output $obj }
            }
        Write-Log -Message "Client Version: $(Get-ClientVersion)" -severity 1 -component "Get Property"

        #Detect SCCM Client Log path
            Function Get-CCMLogDirectory {
                $obj = (Get-ItemProperty -Path 'HKLM:\SOFTWARE\Microsoft\CCM\Logging\@Global' -ea 0).LogDirectory
                if ($null -eq $obj) { $obj = "$env:SystemDrive\windows\ccm\Logs" }
                Write-Output $obj
            }

        #Detect if client is registered, if not last registration error
        Function Get-ClientRegistration {
        $clientreg = (Get-WmiObject -Class ccm_clientidentificationinformation -Namespace root\ccm -ErrorAction SilentlyContinue).ReservedUInt1
        If($clientreg -eq "2")
            {
                $clientreg = 'Registered'
            }
        elseif($clientreg -eq 0)
            {
                $clientreg = "Deregistered"
            }
        elseif($clientreg -eq 1)
            {
                $clientreg = "Currently Registering with Management Point"
            }
            Write-Output $clientreg
        }
        Write-Log -Message "Registration Status: $(Get-ClientRegistration)" -severity 1 -component "Get Property"
        
        #Detect if client is registered, if not last registration error
        Function Get-ClientRegistrationError {
            If($(Get-ClientRegistration) -eq 'Deregistered')
            {
                $reglog="$(Get-CCMLogDirectory)\ClientIDManagerStartup.log"
                $err1= "0x87d00231"
                $err2= "0x8000000a"
                $err3= "0x8000ffff" 
       
                $stringPresent= Select-String -Path $reglog -Quiet -Pattern $err1
                if($stringPresent -eq "True")
                    {
                        $regerror = $err1
                        Write-Log -Message "Registration Error: $regerror" -severity 3 -component "Get Property"
                    }
   
               $stringPresent= Select-String -Path $reglog -Quiet -Pattern $err2
                if($stringPresent -eq "True")
                    {
                        $regerror = $err2
                        Write-Log -Message "Registration Error: $regerror" -severity 3 -component "Get Property"
                    }
   
               $stringPresent= Select-String -Path $reglog -Quiet -Pattern $err3
                if($stringPresent -eq "True")
                    {
                        $regerror = $err3
                        Write-Log -Message "Registration Error: $regerror" -severity 3 -component "Get Property"
                    }
             }
        
            Write-Output $Regerror
        }

        Get-ClientRegistrationError



        Write-Log -Message "CCM Log Path: $(Get-CCMLogDirectory)" -severity 1 -component "Get Property"

        # Detect Client Cache Location
        Function Get-ClientCache {
            $obj = (gwmi -Class CacheConfig -Namespace root\ccm\softmgmtagent -Property Location).Location
            Write-Output $obj   
        }
        Write-Log -Message "Client Cache Location: $(Get-ClientCache)" -severity 1 -component "Get Property"

        # Detect Client Cache Size Used
        Function Get-CCMCacheConsumption {
        $foldersize = Get-ChildItem $(Get-ClientCache) -recurse | Measure-Object -property length -sum
        $DiskUsed = $([math]::Round(($foldersize.sum / 1GB),2))
        Write-Output $DiskUsed
        }

        # Detect Client Cache Total Size
        Function Get-ClientCacheSize {
            $obj = (New-Object -ComObject UIResource.UIResourceMgr).GetCacheInfo().TotalSize
            $CacheSize = $([math]::Round(($obj/1024),2))
            Write-Output $CacheSize
            }
        Write-Log -Message "Client Cache Disk Consumption: $(Get-CCMCacheConsumption) GB used out of $(Get-ClientCacheSize) GB" -severity 1 -component "Get Property"

        #Detect client location.
        Function Get-ClientInternetLocation
            {
                $location = (Get-WmiObject -Namespace root\ccm -Class clientinfo -ErrorAction SilentlyContinue).InInternet
                if($location -eq $null)
                    {
                        $clientlocation = 'Unknown'
                    }
                else
                    {
                        $clientlocation = $location
                    }
                Write-Output $clientlocation
            }
        Write-Log -Message "Client OnInternet: $(Get-ClientInternetLocation)" -severity 1 -component "Get Property"
                
        #Get Current MP
        function Get-CurrentMP {
            
            If($(Get-ClientInternetLocation) -ne "True")
                {
                    $currentMP = (get-wmiobject -class sms_authority -Namespace root\ccm -ErrorAction SilentlyContinue | Select-Object CurrentManagementPoint).CurrentManagementPoint 
                }
            elseif($(Get-ClientInternetLocation) -eq "True")
                {
                    $currentMP = Get-WmiObject -Class SMS_ActiveMPCandidate -Namespace root\ccm\locationservices | where{$_.type -eq "Internet"} | select -ExpandProperty MP | select -First 1
                }
            elseif($currentMP.Length -eq 0)
                {
                    $currentMP = 'NULL'
                } 
                Write-Output $currentMP
        }
        Write-Log -Message "Current Management Point: $(Get-CurrentMP)" -severity 1 -component "Get Property"

        #Get site code
        Function Get-CurrentSiteCode {
            $site = ($([wmiclass]"root\ccm:sms_client").getassignedsite() | select ssitecode -ErrorAction SilentlyContinue).ssitecode
                if($site -eq $null)
                    {
                        $SITE = 'NULL' 
                    }
                        Write-Output $site
        }
        Write-Log -Message "Current Assigned Site: $(Get-CurrentSiteCode)" -severity 1 -component "Get Property"

        # Get last Client to MP HTTP Error
        Function Get-LastClientMPHResult
            {
                $ParseLog = Get-Content C:\windows\ccm\logs\CCMMessaging.log -ErrorAction SilentlyContinue | Where-Object { $_.Contains("HRESULT =") } | Select-Object -Last 1 | foreach {$_ -csplit 'HRESULT = "' }
                $splitvar = $parselog | foreach {$_ -csplit '";' }
                $LastMPHResult = " $splitvar ".Trim()
                Write-Output $LastMPHResult 
            } 
        Write-Log -Message "Last MP Connection Status code: $(Get-LastClientMPHResult)" -severity 1 -component "Get Property"

        # Telnet Management Point
        Function Get-MPTelnetStatus
            {
                # Telnet MP
                if($currentMP -eq 'NULL')
                        {}
                    elseif($currentMP -notmatch 'CLOUDAPP')
                        {
                            try
                                {
                                    $telnetMP = (New-Object Net.Sockets.TcpClient "$(Get-CurrentMP)",443).Connected
                                        if($telnetMP -eq "true")
                                            {
                                                $ConnectMP = "1"
                                                Write-Log -Message "Telnet MP: $ConnectMP" -severity 1 -component "Get Property"
                                            }
                                }
                            catch
                                {
                                    $ConnectMP = "0"
                                    Write-Log -Message "Telnet MP: $ConnectMP" -severity 2 -component "Get Property"
                                }

                        }
                elseif($currentMP -match 'CLOUDAPP')
                        {
                            try
                                {
                                    $currentMP = $currentMP.Split("/")[2] | select -First 1
                                    $TCPCheck = Test-NetConnection $currentMP -Port 443 -ErrorAction Stop -ErrorVariable err | select -ExpandProperty TcpTestSucceeded
                                    if($TCPCheck -eq "true")
                                            {
                                                $ConnectMP = "1"
                                                Write-Log -Message "Telnet MP: $ConnectMP" -severity 1 -component "Get Property"
                                            }
                                }
                            catch [system.exception]
                                {
                                    if($err.count -ne 0)
                                        {
                                            $ConnectMP = "0"
                                            Write-Log -Message "Telnet MP: $ConnectMP" -severity 2 -component "Get Property"
                                        }
                                }
                        }
            } 
        Get-MPTelnetStatus
        
        # Get HTTP Post status
        Function Get-HTTPPostStatus
            {
                if($currentMP -notmatch 'CLOUDAPP'){
                    try
                        {
                            $POST= [system.net.webrequest]::Create("https://$(Get-CurrentMP)")
                            $RESPONSE = $POST.getresponse() 
                            $StatusCode = [int]$RESPONSE.statuscode
                            $RESPONSE.CLOSE()
                            $httpstate = $StatusCode
                            Write-Log -Message "HTTP Post Status to Management Point: $($httpstate)" -severity 1 -component "Get Property"
                        }
                    catch [system.exception]
                        {
                            Write-Log -Message "HTTP Post Status to Management Point: $($_.exception.message)" -severity 2 -component "Get Property"
                        }
                    }
            }
        Get-HTTPPostStatus 

        # Get Hardware Inventory Report date
        function Get-LastHWInventoryReportDate 
            {
                $LastInventory = '{00000000-0000-0000-0000-000000000001}'
                $CheckInv = Get-WmiObject -Class inventoryactionstatus -Namespace root\ccm\invagt -ErrorAction SilentlyContinue | where{$_.InventoryActionID -eq $LastInventory}
                if($CheckInv)
                    {
                        $GetReportDate = (Get-WmiObject -Class inventoryactionstatus -Namespace root\ccm\invagt -ErrorAction SilentlyContinue | where{$_.InventoryActionID -eq $LastInventory} | `
                        Select-Object LastreportDate).lastreportdate
                        If($GetReportDate -eq $null -or $GetReportDate -like '1970*')
                            {
                                $InventoryConvertedTime = [DateTime] "01/01/1970 12:00 AM"
                            }
                        else{
                                $InventoryConvertedTime= [System.Management.ManagementDateTimeconverter]::ToDateTime($GetReportDate) | Get-Date -Format g
                            }
                                Write-Log -Message "Last Hardware Inventory: $($InventoryConvertedTime)" -severity 1 -component "Get Property"
                    }
                else
                    {
                        $InventoryConvertedTime = [DateTime] "01/01/1970 12:00 AM"
                        Write-Log -Message "Hardware Inventory never ran" -severity 2 -component "Get Property"
                    }
              Write-output $InventoryConvertedTime
            } 
          Get-LastHWInventoryReportDate 

         # Get Hardware Inventory Report date
        function Get-LastSWInventoryReportDate 
            {
                $LastInventory = '{00000000-0000-0000-0000-000000000002}'
                $CheckInv = Get-WmiObject -Class inventoryactionstatus -Namespace root\ccm\invagt -ErrorAction SilentlyContinue | where{$_.InventoryActionID -eq $LastInventory}
                if($CheckInv)
                    {
                        $GetReportDate = (Get-WmiObject -Class inventoryactionstatus -Namespace root\ccm\invagt -ErrorAction SilentlyContinue | where{$_.InventoryActionID -eq $LastInventory} | `
                        Select-Object LastreportDate).lastreportdate
                        If($GetReportDate -eq $null -or $GetReportDate -like '1970*')
                            {
                                $InventoryConvertedTime = [DateTime] "01/01/1970 12:00 AM"
                            }
                        else{
                                $InventoryConvertedTime= [System.Management.ManagementDateTimeconverter]::ToDateTime($GetReportDate) | Get-Date -Format g
                            }
                                Write-Log -Message "Last Software Inventory: $($InventoryConvertedTime)" -severity 1 -component "Get Property"
                    }
                else
                    {
                        Write-Log -Message "Software Inventory never ran" -severity 2 -component "Get Property"
                    }
            Write-output $InventoryConvertedTime
            } 
           Get-LastSWInventoryReportDate 

            # Get Hardware Inventory Report date
        function Get-LastHeartbeatReportDate 
            {
                $LastInventory = '{00000000-0000-0000-0000-000000000003}'
                $CheckInv = Get-WmiObject -Class inventoryactionstatus -Namespace root\ccm\invagt -ErrorAction SilentlyContinue | where{$_.InventoryActionID -eq $LastInventory}
                if($CheckInv)
                    {
                        $GetReportDate = (Get-WmiObject -Class inventoryactionstatus -Namespace root\ccm\invagt -ErrorAction SilentlyContinue | where{$_.InventoryActionID -eq $LastInventory} | `
                        Select-Object LastreportDate).lastreportdate
                        If($GetReportDate -eq $null -or $GetReportDate -like '1970*')
                            {
                                $InventoryConvertedTime = [DateTime] "01/01/1970 12:00 AM"
                            }
                        else{
                                $InventoryConvertedTime= [System.Management.ManagementDateTimeconverter]::ToDateTime($GetReportDate) | Get-Date -Format g
                            }
                                Write-Log -Message "Last HeartBeat Discovery: $($InventoryConvertedTime)" -severity 1 -component "Get Property"
                    }
                else
                    {
                        $InventoryConvertedTime = [DateTime] "01/01/1970 12:00 AM"
                        Write-Log -Message "Last HeartBeat Discovery never ran" -severity 2 -component "Get Property"
                    }
            Write-output $InventoryConvertedTime
            } 
          Get-LastHeartbeatReportDate 

        #Get SUP Source
        function Get-SUPSource {
        $supsource = (Get-ItemProperty -Path HKLM:\software\Policies\Microsoft\Windows\WindowsUpdate -Name wuserver -ea 0 | Select-Object wuserver).wuserver
        Write-output $supsource
        }
        Write-Log -Message "Software Update Server: $(Get-SUPSource)" -severity 1 -component "Get Property"

        #Get the last Scan time
        function Get-LastUpdateScanReportDate {
        $lastscan = (Get-WmiObject -Class ccm_scanupdatesourcehistory -Namespace root\ccm\scanagent -ErrorAction SilentlyContinue | Select-Object LastCompletionTime).LastCompletionTime  
            If($lastscan -eq $null -or $lastscan -like '19700*')
                {
                    $ScanConvertedTime = 'NULL'
                }
            else
                {
                    $ScanConvertedTime= [System.Management.ManagementDateTimeconverter]::ToDateTime($lastscan) | Get-Date -Format g
                }
                    Write-output $ScanConvertedTime
        }
        Write-Log -Message "Last Update Scanning Time: $(Get-LastUpdateScanReportDate )" -severity 1 -component "Get Property"

        # Telnet Software Update Point
        Function Get-SUPTelnetStatus
            {
                $SUP = Get-SUPSource 
                if($SUP -match 'CLOUDAPP')
                    {
                        try
                            {
                                $SUP = $SUP.Split("/")[2] | select -First 1
                                $TCPCheck = Test-NetConnection $SUP -Port 443 -ErrorAction Stop -ErrorVariable err | select -ExpandProperty TcpTestSucceeded
                                if($TCPCheck -eq "true")
                                        {
                                            $telnetSUP = "1"
                                            Write-Log -Message "Telnet SUP: $telnetSUP" -severity 1 -component "Get Property"
                                        }
                            }
                        catch [system.exception]
                            {
                                if($err.count -ne 0)
                                    {
                                        $telnetSUP = "0"
                                        Write-Log -Message "Telnet SUP: $telnetSUP" -severity 2 -component "Get Property"
                                    }
                            }
                    }
                elseif($SUP -notmatch 'CLOUDAPP')
                    {
                        $Url = Get-SUPSource | foreach {$_ -csplit "http://" } | foreach {$_ -csplit ":8530" }
                        if($URL.Length -eq 0)
                            {
                                $SUP = 'NULL'
                            }
                        ELSE
                            {
                                $SUP = " $url ".Trim()
                                try
                                    {
                                        $TCPCheck = (New-Object Net.Sockets.TcpClient $SUP,8530).Connected
                                            if($TCPCheck -eq "true")
                                                {
                                                    $telnetSUP = "1"
                                                    Write-Log -Message "Telnet Software Update Server: $telnetSUP" -severity 1 -component "Get Property"
                                                }
                                    }
                                catch [System.Exception]
                                    {
                                        Write-Log -Message "Telnet Software Update Server: $($_.Exception.Message)" -severity 2 -component "Get Property"
                                    }    
                            }
                    }        
            } 
        Get-SUPTelnetStatus

        # Provisioning Mode
        Function Get-ProvisioningMode 
            {
                $registryPath = 'HKLM:\SOFTWARE\Microsoft\CCM\CcmExec'
                $provisioningMode = (Get-ItemProperty -Path $registryPath -ErrorAction SilentlyContinue).ProvisioningMode
                if ($provisioningMode -eq 'true') { $obj = $true }
                else { $obj = $false }
                Write-Output $obj
            } Write-Log -Message "Provisioning Mode State: $(Get-ProvisioningMode)" -severity 1 -component "Get Property"
        
# Pending Reboot - Internal
function Get-PendingReboot {
        $result = @{
            CBSRebootPending =$false
            WindowsUpdateRebootRequired = $false
            FileRenamePending = $false
            SCCMRebootPending = $false
        }

        #Check CBS Registry
        $key = Get-ChildItem "HKLM:Software\Microsoft\Windows\CurrentVersion\Component Based Servicing\RebootPending" -ErrorAction SilentlyContinue
        if ($null -ne $key) { $result.CBSRebootPending = $true }

        #Check Windows Update
        $key = Get-Item 'HKLM:SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update\RebootRequired' -ErrorAction SilentlyContinue
        if ($null -ne $key) { $result.WindowsUpdateRebootRequired = $true }

        #Check PendingFileRenameOperations
        $prop = Get-ItemProperty 'HKLM:SYSTEM\CurrentControlSet\Control\Session Manager' -Name PendingFileRenameOperations -ErrorAction SilentlyContinue
        if ($null -ne $prop)
        {
            #PendingFileRenameOperations is not *must* to reboot?
            #$result.FileRenamePending = $true
        }

        try
        {
            $util = [wmiclass]'\\.\root\ccm\clientsdk:CCM_ClientUtilities'
            $status = $util.DetermineIfRebootPending()
            if(($null -ne $status) -and $status.RebootPending){ $result.SCCMRebootPending = $true }
        }
        catch{}

        #Return Reboot required
        if ($result.ContainsValue($true)) {
            #$text = 'Pending Reboot: YES'
            $obj = $true
            #$log.PendingReboot = 'Pending Reboot'
        }
        else {
            $obj = $false
            #$log.PendingReboot = 'OK'
        }
        Write-Output $obj
    }
    Write-Log -Message "System Reboot Pending: $(Get-PendingReboot) " -severity 1 -component "Get Property" 

  
# Remediate Provisioning Mode - Internal
Function Resolve-ProvisioningMode
    {
        If($(Get-ProvisioningMode) -eq "True")
            {
                Write-Log -Message "Machine is in Provisioning Mode. Moving out of Provisioning Mode." -severity 2 -component "Get Property"
                Set-ItemProperty -Path hklm:\software\microsoft\ccm\ccmexec -Name provisioningmode -value False
                Set-ItemProperty -Path hklm:\software\microsoft\ccm\ccmexec -Name SYSTEMTASKEXCLUDES -value $NULL
                Get-Service -Name CcmExec | Restart-Service
                Write-Log -Message "Restarted SMS Agent Host Service. Exiting Script" -severity 1 -component "Get Property"
                EXIT
            }
    } Resolve-ProvisioningMode


# Function to trigger full inventory - Internal
Function Invoke-Inventory
    {
        param(
            [Parameter(Mandatory=$true)]$InventoryGUID,
            [Parameter(Mandatory=$true)]$InventoryReport)

        $inventoryType = $((Get-InventoryParams | select name, guid | Where-Object{$_.guid -eq $InventoryGUID}).name)
        try
            {
                if($InventoryReport -eq 'Full')
                    {
                        Get-WmiObject -Class InventoryActionStatus -Namespace Root\CCM\Invagt -ea 0 | where {$_.InventoryActionID -eq "$InventoryGUID"} | Remove-WmiObject
                        Invoke-WmiMethod -Namespace Root\CCM -Class SMS_Client -Name TriggerSchedule -ArgumentList $InventoryGUID -ErrorAction Stop | Out-Null
                        Write-Log -Message "Triggered $($InventoryReport) $($inventoryType) inventory" -severity 1 -component "Get Property"
                    }
                elseif($InventoryReport -eq 'Delta')
                    {
                        Invoke-WmiMethod -Namespace Root\CCM -Class SMS_Client -Name TriggerSchedule -ArgumentList $InventoryGUID -ErrorAction Stop | Out-Null
                        Write-Log -Message "Triggered $($InventoryReport) $($inventoryType) inventory" -severity 1 -component "Get Property"
                    }
            }
        catch [system.exception]
            {
                Write-Log -Message "Failed to perform Full $($inventoryType) Inventory for: $($InventoryGUID) with exception: $($_.Exception.Message)" -severity 3 -component "Get Property"
            }
    }
    
#Check hardware inventory and DDR status - Internal
Function Test-SCCMHardwareInventoryScan 
    {
        Write-Log -Message "Start Test-SCCMHardwareInventoryScan" -severity 1 -component "Get Property"
        $MinDays = (Get-InventoryParams | Where-Object{$_.name -eq 'hardware'} | select days).days

        # Number of days since last hardware inventory
        if (Get-LastHWInventoryReportDate -eq $null){
            Write-Log -Message "Last Hardware Inventory Scan is Null or not run. Initilizing Full Hardware Inventory Scan" -severity 2 -component "Get Property"
            Invoke-Inventory -InventoryGUID '{00000000-0000-0000-0000-000000000001}' -InventoryReport 'Full'
            Write-Log -Message "End Full Test-SCCMHardwareInventoryScan" -severity 1 -component "Get Property"
            }
         else{

            $HWSince = (New-TimeSpan $(Get-LastHWInventoryReportDate) $(get-date -Format g) -ErrorAction SilentlyContinue).Days 
            if ($HWSince -ge $MinDays ) 
                {
                    Write-Log -Message "$($HWSince) days since last Hardware Scan. Initilizing full inventory" -severity 2 -component "Get Property"
                    Invoke-Inventory -InventoryGUID '{00000000-0000-0000-0000-000000000001}' -InventoryReport 'Full'
                    Write-Log -Message "End Test-SCCMHardwareInventoryScan" -severity 1 -component "Get Property"
                }
            else 
                {
                    Invoke-Inventory -InventoryGUID '{00000000-0000-0000-0000-000000000001}' -InventoryReport 'Delta'
                    Write-Log -Message "End Test-SCCMHardwareInventoryScan" -severity 1 -component "Get Property"
                }
          }
        }
     Test-SCCMHardwareInventoryScan

#Check hardware inventory and DDR status - Internal
Function Test-SCCMHeartBeatDiscoveryScan 
    {
        Write-Log -Message "Start Test-SCCMHeartBeatDiscoveryScan" -severity 1 -component "Get Property"
        $MinDays = (Get-InventoryParams | Where-Object{$_.name -eq 'Heartbeat'} | select days).days

        # Number of days since last heartbeat discovery
        if (Get-LastHeartbeatReportDate -eq $null){
            Write-Log -Message "Last Heartbeat Discovery is Null or not run. Initilizing Full Discovery" -severity 2 -component "Get Property"
            Invoke-Inventory -InventoryGUID '{00000000-0000-0000-0000-000000000003}' -InventoryReport 'Full'
            Write-Log -Message "End Full Test-SCCMHeartBeatDiscoveryScan" -severity 1 -component "Get Property"
            }
         else{
                $InvSince = (New-TimeSpan $(Get-LastHeartbeatReportDate) $(get-date -Format g) -ErrorAction SilentlyContinue).Days 
                if ($InvSince -ge $MinDays) 
                    {
                        Write-Log -Message "$($InvSince) days since last HeartBeat Discovery. Initilizing Full Discovery" -severity 2 -component "Get Property"
                        Invoke-Inventory -InventoryGUID '{00000000-0000-0000-0000-000000000003}' -InventoryReport 'Full'
                        Write-Log -Message "End Full Test-SCCMHeartBeatDiscoveryScan" -severity 1 -component "Get Property"
                    }
                else 
                    {
                        Invoke-Inventory -InventoryGUID '{00000000-0000-0000-0000-000000000003}' -InventoryReport 'Delta'
                        Write-Log -Message "End Delta Test-SCCMHeartBeatDiscoveryScan" -severity 1 -component "Get Property"
                    }
             }
         }
     Test-SCCMHeartBeatDiscoveryScan

# Function to test connection to on=prem
Function Check-OnPremConnection {
    $dc = Get-DCName
    $ConnectionOnPrem = Test-NetConnection $dc -WarningAction SilentlyContinue -InformationLevel Quiet
    if($ConnectionOnPrem -eq "True")
        {
            Write-Log -Message "Ping succeeded to $($dc)" -severity 1 -component "Get Property" 
            $InOnprem = "Yes"
        }
    else
        {
            Write-Log -Message "Ping failed to $($dc)" -severity 3 -component "Get Property" 
            $InOnprem = "No"
        }
write-output $InOnprem
}

# Apply Intranet mp
Function Apply-MPURL($Intranet)
    {
        if($Intranet -eq "Yes")
            {
                $SetInstance = Set-WMIInstance -path '\\.\ROOT\ccm:SMS_Authority.Name="SMS:MHN"' -argument @{CurrentManagementPoint="$((Get-XMLManagementPoint).OnPrem)"}
                Write-Log -Message "MP swap completed and changed to $((Get-XMLManagementPoint).OnPrem)." -severity 1 -component "Get Property"
            }
        elseif($Intranet -eq "No")
            {
                $SetInstance = Set-WMIInstance -path '\\.\root\ccm\locationservices:SMS_ActiveMPCandidate' -argument @{MP="$((Get-XMLManagementPoint).Internet)"}
                Write-Log -Message "MP swap completed and changed to $((Get-XMLManagementPoint).Internet)." -severity 1 -component "Get Property" 
            }
        Get-Service -Name CcmExec | Restart-Service
        Write-Log -Message "SMS Agent Host service is restarted. Sleepting 300 seconds. Monitor ClientIdstartupManager.log for client registration progress" -severity 1 -component "Get Property"
        sleep -Seconds 300
           
    }

# Function to fix Site Assignment - Internal
Function Resolve-SiteAssignment
    {
        #Change to MP as defined in Config XML"
        Try
            {
                 if($(Get-CurrentMP) -eq $null -and $(Check-OnPremConnection -eq "Yes"))
                    {
                        Write-Log -Message "Client assigned to Management Point: Null. Will update MP." -severity 2 -component "Get Property"
                        Apply-MPURL -Intranet $(Check-OnPremConnection)
                    }
                elseif($(Get-CurrentMP) -eq $null -and $(Check-OnPremConnection -eq "No"))
                    {
                        Write-Log -Message "Client assigned to Management Point: Null. Will update MP." -severity 2 -component "Get Property"
                        Apply-MPURL -Intranet $(Check-OnPremConnection)
                    }
                elseif(Get-CurrentMP -eq ((Get-XMLManagementPoint).OnPrem) -and $(Check-OnPremConnection -eq "Yes"))
                    {
                        Write-Log -Message "Already set to $((Get-XMLManagementPoint).OnPrem) in WMI. Skipping MP swap." -severity 1 -component "Get Property"
                    }
                elseif(($(Get-CurrentMP) -eq $((Get-XMLManagementPoint).Internet) -and $(Check-OnPremConnection -eq "No")))
                    {
                        Write-Log -Message "Already set to $((Get-XMLManagementPoint).Internet) in WMI. Skipping MP swap." -severity 1 -component "Get Property"
                    }
            }
        catch [system.exception]
            {
                Write-Log -Message "Failed to bind to WMI Class with exception: $($_.Exception.Message)" -severity 3 -component "Get Property"
            }
    } Resolve-SiteAssignment     

# Function to Resync state messages - Internal 
Function Resync-StateMessages
    {
        $SCCMUpdatesStore = New-Object -ComObject Microsoft.CCM.UpdatesStore 
        $SCCMUpdatesStore.RefreshServerComplianceState()
        Write-Log -Message "Resynchronized State Messages" -severity 1 -component "Get Property"
    }

# Function to test Perform Client Upgrade - External
Function Test-ClientVersion
    {
        if($(Get-ClientVersion) -lt $(Get-XMLClientVersion))
            {
                Write-Log -Message "Client version($(Get-ClientVersion)) lesser than Site Version($(Get-XMLClientVersion)). Needs Client Upgrade." -severity 2 -component "Get Property"
                Invoke-Command -ScriptBlock { $(Get-XMLClientUpgradeCmd)}
                Write-Log -Message "Triggered Client Upgrade. Review CCMSetup.log from %Windir%\CCMSetup\Logs for progress. Exiting Script" -severity 2 -component "Get Property"
                EXIT
            }
        elseif($(Get-ClientVersion) -eq $(Get-XMLClientVersion))
            {
                Write-Log -Message "Client version($(Get-ClientVersion)) matches Site Version($(Get-XMLClientVersion)). No Client Upgrade needed." -severity 1 -component "Get Property"
            }
        elseif($(Get-ClientVersion) -gt $(Get-XMLClientVersion))
            {
                Write-Log -Message "Client version($(Get-ClientVersion)) higher than Site Version($(Get-XMLClientVersion))." -severity 2 -component "Get Property"
            }
    } Test-ClientVersion


# Fix Client Registration Issue
    
#Detect if client is registered, if not last registration error - Internal
Function Fix-ClientRegistrationError 
    {
        If($(Get-ClientRegistration) -eq 'Deregistered')
        {
            $reglog="$(Get-CCMLogDirectory)\ClientIDManagerStartup.log"
            $error = "0x87d00231", "0x8000000a", "0x8000ffff" 
            foreach ($err in $error)
                {
                    $result = Get-Content $reglog | Select-String $err -quiet -casesensitive
                    if ($result -eq "True")
                        {
                                Write-Log -Message "Registration Error: $regerror. Will attempt to fix. Invoking client repair." -severity 3 -component "Get Property"
                                Repair-Client
                        }
                    else
                        {
                            # Repair anyway
                            Write-Log -Message "Not a transient error however will attempt to fix. Invoking client repair." -severity 2 -component "Get Property"
                            Repair-Client
                        }
                }
        }
    } Fix-ClientRegistrationError

# Repair Client - Internal
Function Repair-Client
    {
        Write-Log -Message "Initializing Client Repair" -severity 1 -component "Get Property"

        # Stop SMS Agent Host
        Get-service -Name CcmExec | Stop-Service
        Sleep -Seconds 30
        Write-Log -Message "Stopped SMS Agent Host service. Sleeping for 30 seconds." -severity 1 -component "Get Property"

        # Delete SMS Key
        Get-childItem Cert:\LocalMachine\SMS\* | Remove-Item -Recurse -Force
        Write-Log -Message "Deleted SMS Certificates" -severity 1 -component "Get Property"

        # Delete RSA Key
        Get-ChildItem "C:\ProgramData\Microsoft\Crypto\RSA\MachineKeys\19c5*" | Move-Item -Destination "C:\Windows\Temp\" -Force
        Write-Log -Message "Deleted RSA Machine keys" -severity 1 -component "Get Property"

        # Delete SMSCFG.ini
        Get-Item -path C:\Windows\SMSCfg.ini | Remove-Item -Force
        Write-Log -Message "Deleted SMSCFG.ini file from %windir%" -severity 1 -component "Get Property"

        # GPUpdate
        Write-Log -Message "Performing Group Policy Update" -severity 1 -component "Get Property"
        Invoke-Command -ScriptBlock {"cmd.exe & gpupdate /force"}
        sleep -Seconds 30
        $GPEvent = (Get-EventLog -LogName System | where{$_.source -eq "Microsoft-Windows-GroupPolicy" -and $_.InstanceId -eq '1502'} | Sort-Object time -Descending | Select-Object -first 1).message
        Write-Log -Message "$($GPEvent)" -severity 1 -component "Get Property"

        # Repair Client
        Get-Service -Name CcmExec | start-Service
        Write-Log -Message "Started SMS Agent Host service. Sleeping for 30 seconds." -severity 1 -component "Get Property"
        #Sleep -Seconds 30

        # Monitor Registration
        $regstat1 = (Get-WmiObject -Class CCM_ClientIdentificationInformation -Namespace Root\CCM).ReservedUInt1
        if($regstat1 -ne "2")
            {
                do
                    {
                        $regstarttime = Get-Date -Format HH:mm
                        $check = ($(Get-ClientRegistration)) 
                
                        if($check -ne 'Registered')
                            {
                                Write-Log -Message "Client is registering" -severity 1 -component "Get Property"
                                Sleep -Seconds 10
                                if((New-TimeSpan $regstarttime (get-date -Format HH:mm) -ErrorAction SilentlyContinue).minutes -ge "5")
                                    {
                                        $expired1 = -1
                                        break;
                                    }
                                else
                                    {
                                        $expired1 = 1
                                    }
                            }
                    } until ($(Get-ClientRegistration) -eq "Registered")
            }
        else
            {
                Write-Log -Message "Break" -severity 1 -component "Get Property"
            }
        if($expired1 -eq 1)
            {
                Write-Log -Message "Client is registered. Exiting Script." -severity 1 -component "Get Property"
                EXIT
            }
        elseif($expired1 -eq -1)
            {
                Write-Log -Message "Client registration attempt has timedout. Will attempt a repair." -severity 2 -component "Get Property"
                $repair1 = [wmiclass]"\\.\root\ccm:sms_client"
                if($repair1)
                    {
                        $repair1 = $repair1.RepairClient()
                        Write-Log -Message "Client Repair triggered. Check CCMSetup.log from %windir%\CCMSetup\Logs for progress. Exiting Script." -severity 2 -component "Get Property"
                        EXIT
                    }
                else
                    {
                        Write-Log -Message "Failed! Could not bind WMI class SMS_client. Exiting Script." -severity 2 -component "Get Property"
                        EXIT
                    }
            }
    }


# Check Service Data and take appropriate actions

$TopQueue = Get-ChildItem -Path C:\Windows\CCM\ServiceData\Messaging\OutgoingQueues -File -Recurse -Filter *.msg -ErrorAction SilentlyContinue | Where-Object {$_.Length -gt 100KB} | Select-Object Name,Directory
if($topqueue)
    {
        $dirs = $($TopQueue.directory).fullname
        foreach($queue in $TopQueue)
            {
                Write-Log -Message "$($queue.name) from $($queue.Directory) exceeding 100KB size" -severity 1 -component "Get Property"
            }
        Write-Log -Message "Clearing the files, will get recreated upon service restart" -severity 1 -component "Get Property"

        #stop CCMEXEC
        try 
           {
                Get-Service -Name CcmExec | Stop-Service
                sleep -Seconds 5
                foreach($dir in $dirs)
                    {
                        get-childItem -Path $dir -Filter *.msg -ErrorAction SilentlyContinue | Where-Object {$_.Length -gt 100KB} | Remove-Item -Force
                    }
                sleep -Seconds 5
                Get-Service -Name CcmExec | Start-Service
           }
        catch [System.Exception]
            {
                Write-Log -Message "Failed to stop CCMEXEC service" -severity 3 -component "Get Property"
            }
        Write-Log -Message "Cleared files" -severity 1 -component "Get Property"
    }
else
    {
        Write-Log -Message "Service Data files found below 100KB" -severity 1 -component "Get Property"
    }


############################
## Updates Remediation space
############################

# Common function to invoke Updates Deployment Evaluation Cycle
Function Invoke-UpdatesDeployment 
    {
        $WMIConnection  = [WMICLASS]"root\CCM:SMS_Client"
        $MethodParameters = $WMIConnection.psbase.GetMethodParameters("TriggerSchedule")
        $MethodParameters.sScheduleID = "{00000000-0000-0000-0000-000000000108}"

        if($WMIConnection) 
            {
                $WMIConnection.psbase.InvokeMethod("TriggerSchedule",$MethodParameters,$Null)
                Write-Log -Message "Invoked Updates Deployment Evaluation Cycle" -severity 1 -component "Get Property"
            }
        else
            {
                Write-Log -Message "Error, could not bind WMI class SMS_client" -severity 3 -component "Get Property"
            }
    } 

# Force Install Updates from Software Center

Function Force-InstallUpdates
    {
        # Get missing updates list from root\CCM\ClientSDK 
        $MissingUpdates = Get-WmiObject -Class CCM_SoftwareUpdate -Filter ComplianceState=0 -Namespace root\CCM\ClientSDK 

        # Get the missing updates (ComplianceState=0) and turn it into an array of WMI objects 
        $MissingUpdatesReformatted = @($MissingUpdates | ForEach-Object {if($_.ComplianceState -eq 0){[WMI]$_.__PATH}}) 
 
        # InstallUpdates missing updates 
        $InstallReturn = Invoke-WmiMethod -Class CCM_SoftwareUpdatesManager -Name InstallUpdates -ArgumentList (,$MissingUpdatesReformatted) -Namespace root\ccm\clientsdk 
    }

# Unspecified Error
Function Resolve-UnspecifiedError 
    {
        # -2147467259
        Write-Log -Message "Attempting to remediate Unspecified Error" -severity 1 -component "Get Property"
        $windir = 'C:\Windows\system32\GroupPolicy\Machine'
        $RegpolPath= test-path $windir\Registry.pol
        if($RegpolPath -eq "True")
            {
                Remove-Item $RegpolPath -Force -ea 0
                Write-Log -Message "Registry.pol deleted from $windir. Invoking Updates Deployment Evaluation cycle" -severity 1 -component "Get Property"

                # Invoke Updates Deployment Evaluation Cycle
                Invoke-UpdatesDeployment 
	        }
        else
            {
                Write-Log -Message "Can't find Registry.pol in $windir. Attempting to invoke Updates Deployment Evaluation cycle" -severity 2 -component "Get Property"

                # Invoke Updates Deployment Evaluation Cycle
                Invoke-UpdatesDeployment 
            }
    }

# Updates Handler Cancelled
Function Resolve-UpdatesHandlerCancelled 
    {
        # -2016410012
        Write-Log -Message "Attempting to remediate Updates Handler Cancelled Error" -severity 1 -component "Get Property"

        #restart ccmexec service
        Write-Log -Message "Restarting SMS w Host Service" -severity 1 -component "Get Property"
        get-service -name ccmexec | restart-service

        Write-Log -Message "Sleeping for 30 seconds" -severity 1 -component "Get Property"
        sleep -seconds 30

        #Restart windows update service
        Write-Log -Message "Restarting Windows Update Service" -severity 1 -component "Get Property"
        get-service -name wuauserv | restart-service

        #wait out for 2 minutes
        Write-Log -Message "Sleeping for 120 seconds" -severity 1 -component "Get Property"
        sleep -seconds 120
        
        # Invoke Updates Deployment Evaluation Cycle
        Invoke-UpdatesDeployment 
    }

# Fix License Terms
Function Resolve-LicenseTerms
    {
        # -2145124301
        $WMIConnection  = [WMICLASS]"\\.\root\CCM:SMS_Client"
        $MethodParameters = $WMIConnection.psbase.GetMethodParameters("TriggerSchedule")
        $MethodParameters.sScheduleID = "{00000000-0000-0000-0000-000000000113}"
        if($WMIConnection) 
            {
                $WMIConnection.psbase.InvokeMethod("TriggerSchedule",$MethodParameters,$Null)
                Write-Log -Message "Successfully performed forced online scan" -severity 1 -component "Get Property"
            }
        else
            {
               Write-Log -Message "Failed to perform online scan" -severity 3 -component "Get Property"
            }

        Write-Log -Message "Sleeping for 180 Seconds" -severity 1 -component "Get Property"
        sleep -Seconds 180

        # Invoke Updates Deployment Evaluation Cycle
        Invoke-UpdatesDeployment  
    }

# Not Enough Storage to perform operation
Function Resolve-MemoryLeak
    {
        # -2147024882
        Try
            {
                get-service -Name wuauserv | Stop-Service -Force

                $ReturnObj = invoke-wmimethod -path win32_process -name create -argumentlist "cmd /c Sc config wuauserv type= own"
                    if( $ReturnObj.ReturnValue -eq 0)
                        {
                           Write-Log -Message "Moved WUAUServ to its own SVCHost." -severity 1 -component "Get Property"
                        }
                     else
                        {
                           Write-Log -Message "Failed to move WUAUServ to its own SVCHost." -severity 2 -component "Get Property"
                        }

                get-service -Name wuauserv | Start-Service
                Write-Log -Message "Restarted Windows Update Service" -severity 1 -component "Get Property"
                
                # Invoke Updates Deployment Evaluation Cycle
                Invoke-UpdatesDeployment
            }
        catch [system.exception]
            {
                 Write-Log -Message "Failed to move WUAUServ to its own SVCHost with exception: $($_.Exception.Message)" -severity 3 -component "Get Property"
            }
    }

# Group Policy Conflict 
Function Resolve-GPOConflict
    {
        # -2016409966
        Write-Log -Message "Overriding Windows Update Group Policy detected on the system. Remove any WU GPOs applied at Domain level." -severity 2 -component "Get Property"
    }


# Software Updates Detected actionable
Function Resolve-SUDetectedActionable
    {
        # -2016410008
        get-service -Name wuauserv | Stop-Service
        sleep -Seconds 2
        Rename-Item -Path C:\windows\SoftwareDistribution SoftwareDistribution.old
        sleep -Seconds 2
        get-service -Name wuauserv | Start-Service

        Write-Log -Message "Software Distribution Folder has been reset" -severity 1 -component "Get Property"

        #wait out for 2 minutes
        Write-Log -Message "Sleeping for 2 minutes" -severity 1 -component "Get Property"
        sleep -seconds 120
        
        # Get missing updates list from root\CCM\ClientSDK
        Write-Log -Message "Triggered updates installation pending in Software Center." -severity 1 -component "Get Property"
        Force-InstallUpdates

        #wait out for 2 minutes
        Write-Log -Message "Sleeping for 2 minutes" -severity 1 -component "Get Property"
        sleep -seconds 120

        # Perform Online WSUS Scan and Invoke Updates Deployment Evaluation Cycle
        Resolve-LicenseTerms
    }

# Component Store has been Corrupted
Function Resolve-ComponentStoreCorruption
    {
        # -2147010798
        $CBSLog = "C:\temp\CBS1.log" #"C:\Windows\Logs\CBS\CBS.log"
        $err = "[HRESULT = 0x80073712 - ERROR_SXS_COMPONENT_STORE_CORRUPT]"
        $stringPresent = Select-String -Path $CBSLog -Quiet -Pattern $err
        if($stringPresent -eq "True")
                {
                    Write-Log -Message "Component Store is Corrupt: $err" -severity 3 -component "Get Property"
                    Write-Log -Message "System requires OS Repair" -severity 2 -component "Get Property"
                }
    }  

# Updates installed but Configuration failed
Function Resolve-UpdatesConfigPostInstall
    {
         # -2146498555
        $CBSLog = "C:\Windows\Logs\CBS\CBS.log"
        $err = "[HRESULT = 0x800f0805 - CBS_E_INVALID_PACKAGE]"
        $stringPresent = Select-String -Path $CBSLog -Quiet -Pattern $err
        if($stringPresent -eq "True")
                {
                    Write-Log -Message "CBS Invalid Update Package detected: $err" -severity 3 -component "Get Property"
                    Write-Log -Message "System requires OS Repair" -severity 2 -component "Get Property"
                }

    }

# "There is no route or network connectivity to the endpoint" and "Same as HTTP status 401 - the requested resource requires user authentication."
Function Resolve-NoNetworkRoute
    {
         # -2145123272 and -2145107945
        
    # Create Reg file for import

    $content = 'Windows Registry Editor Version 5.00

                [HKEY_USERS\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections]
                "DefaultConnectionSettings"=hex:46,00,00,00,09,00,00,00,01,00,00,00,00,00,00,\
                  00,00,00,00,00,00,00,00,00,01,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
                  00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00
                "SavedLegacySettings"=hex:46,00,00,00,0a,00,00,00,09,00,00,00,00,00,00,00,00,\
                  00,00,00,00,00,00,00,01,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,00,\
                  00,00,00,00,00,00,00,00,00,00,00,00,00,00
                '
    
    try 
            {
                add-content "C:\Windows\temp\IEConnection.reg" $content
                Write-Log -Message "Wrote reg file to C:\Windows\Temp\IEConnection.reg" -severity 1 -component "Get Property"
            }
    catch [system.exception]
            {
                Write-Log -Message "Failed to export reg file" -severity 3 -component "Get Property"
            }
    
        # Disable "Automatically detect proxy settings" 
        $checkPSDrive = (Get-psdrive -name HKU -ea 0).name
        
        if($checkPSDrive) 
            {
                Write-Log -Message "PS Drive Exists" -severity 1 -component "Get Property"
            }
        else
            {
                New-PSDrive HKU -Root HKEY_Users -PSProvider Registry 
                Write-Log -Message "New PS Drive created to query HKEY CURRENT USER" -severity 1 -component "Get Property"
            }


        # Check whether IE Connections Key exist and take action 
        $key = 'HKU:\.DEFAULT\Software\Microsoft\Windows\CurrentVersion\Internet Settings\Connections'
        Get-ItemProperty -Path $key -Name DefaultConnectionSettings -ErrorVariable err -ea 0
        if($Err.count -eq 0)
            {
                Write-Log -Message "The Key $($key) exists. Will modify binary value to '01'" -severity 1 -component "Get Property"
                $data = (Get-ItemProperty -Path $key -Name DefaultConnectionSettings -ErrorAction SilentlyContinue).DefaultConnectionSettings
                $data[8] = 01
                Set-ItemProperty -Path $key -Name DefaultConnectionSettings -Value $data
                Write-Log -Message "Binary value updated" -severity 1 -component "Get Property"
            }
        else
            {
                Write-Log -Message "The Key $($key) does not exist. Will import REG file" -severity 2 -component "Get Property"
                $invokescript=invoke-wmimethod -path win32_process -name create -argumentlist "C:\windows\regedit.exe /s C:\Windows\Temp\IEConnection.reg"            
                if( $invokescript.ReturnValue -eq 0)
                    {
                        Write-Log -Message "Registry key imported" -severity 1 -component "Get Property"
                    }

                else
                    {
                        Write-Log -Message "Registry key import failed" -severity 3 -component "Get Property"
                    } 
            }


        #Evaluate Software Updates
        $WMIConnection  = [WMICLASS]"\\.\root\CCM:SMS_Client"
        $MethodParameters = $WMIConnection.psbase.GetMethodParameters("TriggerSchedule")
        $MethodParameters.sScheduleID = "{00000000-0000-0000-0000-000000000108}"

        if($WMIConnection) 
            {
                $WMIConnection.psbase.InvokeMethod("TriggerSchedule",$MethodParameters,$Null)
                Write-Log -Message "Triggered software updates deployment evaluation" -severity 1 -component "Get Property"
            }

            else

            {}

        #wait out for 2 minutes
        sleep -seconds 120

        # Resync State Messagews
        $SCCMUpdatesStore = New-Object -ComObject Microsoft.CCM.UpdatesStore
        $SCCMUpdatesStore.RefreshServerComplianceState()
        Write-Log -Message "Resynchronized state messages" -severity 1 -component "Get Property"
    }


### Remediate Patches and invoke appropriate function. 

Function Resolve-NonCompliance
    {
        #$Error = Get-content C:\RemediationNoDelete\scanerror.txt 

        #Check for non-compliance.
        $query = "topicid like '%$(Get-XMLUpdateDeploymentID)%'"
        $result = Get-WmiObject -class ccm_statemsg -Namespace root\ccm\statemsg -ComputerName localhost -Filter $query | where{$_.topictype -eq "301"} | Select-Object UserParameters,topictype,stateid
        $Error = $result.UserParameters | Select-String -Pattern "-2"

        Write-Log -Message "Software Updates error detected on the PC " -severity 1 -component "Get Property"

        $ExecuteFunction = switch ($Error) {
        '-2147467259' {"$(Resolve-UnspecifiedError)"}
        '-2016410012' {"$(Resolve-UpdatesHandlerCancelled)"}
        '-2145124301' {"$(Resolve-LicenseTerms)"}
        '-2147024882' {"$(Resolve-MemoryLeak)"}
        '-2016409966' {"$(Resolve-GPOConflict)"}
        '-2016410008' {"$(Resolve-SUDetectedActionable)"}
        '-2147010798' {"$(Resolve-ComponentStoreCorruption)"}
        '-2146498555' {"$(Resolve-UpdatesConfigPostInstall)"}
        '-2145123272' {"$(Resolve-NoNetworkRoute)"}  # newly added
        '-2145107945' {"$(Resolve-NoNetworkRoute)"}  # newly added
        } 

        Write-Log -Message "Invoked function to resolve $($error)" -severity 1 -component "Get Property" 
    }

Resolve-NonCompliance

    }
else
    {
        Write-Log -Message "Skipped ConfigMgr specific checks as this is an unmanaged device. Will install client." -severity 2 -component "Get Property"
        Install-Client
    }

#Upload to Azure
Function UploadLogs-ToAzure
    {
        # Export Reg Hive
        $checkreg = Test-path "HKLM:\SOFTWARE\Microsoft\CCMSetup" -ErrorAction SilentlyContinue
        if($checkreg -eq "True")
            {
                # Export CCMSetup Reg
                reg export 'HKLM\SOFTWARE\Microsoft\CCMSetup' "$parentfolder\CCMSetup.reg" | Out-Null
                Write-Log -Message "CCMSetup Reg Hive exported" -severity 1 -component "Copy logs"
            }
        else
            {
                Write-Log -Message "CCMSetup Reg Hive does not exist" -severity 1 -component "Copy logs"
            }

        # Copy logs
        $logs = switch (Get-Client) 
            {
                'No' {"C:\Windows\ccmsetup\logs\ccmsetup*.lo*","C:\Windows\ccmsetup\logs\client.msi*.lo*"}
                'Yes' {"C:\Windows\CCM\Logs\CCMMessaging*.lo*","C:\Windows\CCM\Logs\ClientIDManagerStartup*.lo*","C:\Windows\CCM\Logs\CCMExec*.lo*","C:\Windows\CCM\Logs\LocationServices*.lo*","C:\Windows\CCM\Logs\DataTransferService*.lo*",
                       "C:\Windows\CCM\Logs\ClientLocation*.lo*", "C:\Windows\CCM\Logs\CertificateMaintenance*.lo*", "C:\Windows\ccmsetup\logs\ccmsetup*.lo*", "C:\Windows\ccmsetup\logs\client.msi*.lo*", "C:\Windows\ccmsetup\logs\PolicyAgent*.lo*", "C:\Windows\CCM\Logs\PolicyAgent*.lo*"}
            }

        $dst_dir = "$parentfolder\"

        # Copy each file unconditionally (regardless of whether or not the file is there
        try
            {
                Copy-Item -Path $logs -Recurse -destination $dst_dir -ea SilentlyContinue
                Write-Log -Message "Copied Logs" -severity 1 -component "Copy logs"
            }
        catch [system.exception]
            {
                Write-Log -Message "Failed to copy logs. $($_.exception.message)" -severity 3 -component "Copy logs"
            }

        $ZIPFile = @{
          Path= $parentfolder
          CompressionLevel = "Fastest"
          DestinationPath = "C:\windows\Temp\$($machine)-Remediation_V2.zip"
          }
          Compress-Archive @ZIPFile -Update


        ########################################
        #### START: Upload to Azure Storage Blob
        ########################################
        #Our source File:
        $file = "C:\windows\Temp\$($machine)-Remediation_V2.zip"

        #Get the File-Name without path
        $name = (Get-Item $file).Name



        ############## UPDATE URI AND SAS TOKEN BELOW #########################
        # EXAMPLE: "https://emsintune.blob.core.windows.net/reports/$($name)?sv=2019-12-12&ss=bfqt&srt=sco&sp=rwdlacupx&se=2020-10-05T12:23:32Z&st=2020-10-05T04:23:32Z&spr=https&sig=DfSM%2BldHRm5aVX8E5LPwmoYgniAbhSGv%2FKYjf3mdOJI%3D"
        $uri = "https://storglnesccmlogsprod01.blob.core.windows.net/sccmclienthealth/$($name)?sp=rw&st=2023-05-25T09:38:31Z&se=2024-05-25T17:38:31Z&spr=https&sv=2022-11-02&sr=c&sig=bA0VJI8sWNdgida9yphEgTX9d4UysuBXv83mpPsCfu4%3D"
        #######################################################################

        #Define required Headers
        $headers = @{
            'x-ms-blob-type' = 'BlockBlob'
        }

        #Upload File...
        try
            {
                Invoke-RestMethod -Uri $uri -Method Put -Headers $headers -InFile $file
                write-Log -Message "Zip uploaded" -severity 1 -component "Zip Upload" 
            }
        catch [system.exception]
            {
                write-Log -Message "Zip upload failed with $($_.exception.Message)" -severity 3 -component "Zip Upload"       
            }
        ########################################
        #### END: Upload to Azure Storage Blob
        #########################################>
    }


UploadLogs-ToAzure

Exit 0
