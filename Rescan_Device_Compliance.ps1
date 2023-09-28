<##########################################################################################################################################################################
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for 
loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if 
Microsoft has been advised of the possibility of such damages

Pre-requisite
Ensure we execute the script on a client machine 60 minutes after manually fixing the custom compliant setting on the machine. 

How does the script work?
The script is intended to be executed on machine that’s non-compliant due to a specific setting within the compliance policy. We assume that the custom compliance script as part of your 
compliance policy has already been executed on the machine and the resultant JSON output is applied on the device marking the machine non-compliant. Below are the actions the PowerShell 
script will perform to force IME service to re-trigger the custom compliance script.

1. Deletes the LastExecution key from "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Execution"
2. Restarts IME Service. 
3. Waits for Agent Executor to re-run the Custom Compliance Script.
4. Verifies the status in registry “HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Reports" and prints in the log. 
5. Performs Sync by invoking “PushLaunch” scheduled task from \Microsoft\Windows\EnterpriseMgmt\<YOUR DMCLIENT ID>\. 
6. Log is generated on C:\Windows\Temp\RescanCompliance.log, mentioned in Line 28 in the above script. 
###########################################################################################################################################################################>

sleep 10 
# Define variables
$ScriptID = "" # Specify Script ID from Intune -- https://endpoint.microsoft.com/#view/Microsoft_Intune_DeviceSettings/DevicesComplianceMenu/~/customComplianceScripts
$Regpath = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Execution"
$RegPathReport = "HKLM:\SOFTWARE\Microsoft\IntuneManagementExtension\SideCarPolicies\Scripts\Reports"
$key = "LastExecution" 
$Currentuser = (Get-WmiObject -Class Win32_Process -Filter 'Name="explorer.exe"').GetOwner().User | select -first 1
$path = "C:\ProgramData\Microsoft\IntuneManagementExtension\Logs\AgentExecutor.log" 
$Searchstring = "$($ScriptID)"

#LogWrite function
Function Write-Log
    {
	    PARAM(
		    [String]$Message,
		    [String]$Path = "C:\Windows\Temp\ReScanCompliance.Log",
		    [int]$severity,
		    [string]$component
	    )

	    $TimeZoneBias = Get-CimInstance -Query "Select Bias from Win32_TimeZone"
	    $Date = Get-Date -Format "HH:mm:ss.fff"
	    $Date2 = Get-Date -Format "MM-dd-yyyy"
	    $type =1

	    "<![LOG[$Message]LOG]!><time=$([char]34)$date$($TimeZoneBias.bias)$([char]34) date=$([char]34)$date2$([char]34) component=$([char]34)$component$([char]34) context=$([char]34)$([char]34) type=$([char]34)$severity$([char]34) thread=$([char]34)$([char]34) file=$([char]34)$([char]34)>"| Out-File -FilePath $Path -Append -NoClobber -Encoding default
    }
Write-Log -Message "Current User: $Currentuser" -severity 1 -component "RescanCompliance"


# STEP 1 Function to find registry key
Function Get-CustomScriptRegPath(){
    
    param($searchPath,$Regkey)

Get-ChildItem $Regkey -Recurse -ErrorAction SilentlyContinue | 
   % { 
      if((get-itemproperty -Path $_.PsPath) -match $searchPath)
      { 
         $result = $_.PsPath
      } 
   } 
   [string]$Path = $result.Split("::") | select -Skip 1
   $result = $path.Replace(" HKEY_LOCAL_MACHINE","HKLM:")
   write-output $result
  }

# Proceed
Try
    {
        $FullPath = Get-CustomScriptRegPath -Regkey $Regpath -searchPath $ScriptID
        Write-Log -Message "Scriptid: Found!. Registry key: $FullPath" -severity 1 -component "RescanCompliance"
    }
catch [system.exception]
    {
        Write-Log -Message "Scriptid: $ScriptID not found!" -severity 3 -component "RescanCompliance"
        Exit
    }

# STEP 2 Delete Registry value
Try
    {
        Get-Item -Path $FullPath | Remove-ItemProperty -Name $key -Force -ErrorAction Stop
        Write-Log -Message "Registry key: $Key deleted" -severity 1 -component "RescanCompliance"
    }
catch [system.exception]
    {
        Write-Log -Message "Failed to delete registry key due to $($_.exception.message)" -severity 3 -component "RescanCompliance"
        Exit
    }

# STEP 3 Restart IME Service
Try
    {
        Get-Service -Name IntuneManagementExtension | Restart-Service -Force -ErrorAction Stop
        Write-Log -Message "Restarted Intune Management Extension Service" -severity 1 -component "RescanCompliance"
        Write-Log -Message "Waiting for AgentExecutor to initiate custom compliance script" -severity 1 -component "RescanCompliance"
        Write-Log -Message "Sleeping 300 seconds" -severity 1 -component "RescanCompliance"
        sleep -Seconds 300
        do
            {
                sleep 10
                [array]$StringExist = (select-string -path $path -pattern $Searchstring -allmatches | select -last 1).tostring()
                
                # Script initiate date and time
                $b = ($StringExist.Split('<') | select -last 1).tostring().trim()
                $c = (($b.Split(' ') | select -first 1).tostring().trim().split('='))
                $d = ($c | select -last 1).tostring().trim()
                $ScriptRuntime = $d -replace '"', "" | get-date -Format g
                $timediff = (New-TimeSpan $ScriptRuntime (get-date -Format g)).minutes
                if($timediff -le "60")
                    {
                        Write-Log -Message "AgentExecutor finished execution of custom compliance script" -severity 1 -component "RescanCompliance"
                        $proceed = $true
                    }
            }until($proceed -eq $true)
    }
catch [system.exception]
    {
        Write-Log -Message "Failed to restart Intune Management Extension Service" -severity 3 -component "RescanCompliance"
        Exit
    }

Write-Log -Message "Sleeping 60 seconds" -severity 1 -component "RescanCompliance"
sleep -Seconds 60
Write-Log -Message "Looking for status from registry" -severity 1 -component "RescanCompliance"

# Read results from registry
$ReportingPath = Get-CustomScriptRegPath -Regkey $RegPathReport -searchPath $ScriptID
$results = Get-ItemPropertyValue -Path $ReportingPath -Name Result | ConvertFrom-Json | select ErrorCode, PreRemediationDetectScriptOutput
Write-Log -Message "Custom Compliance script finished with exit code: $($results.ErrorCode) with output: $($results.PreRemediationDetectScriptOutput)"  -severity 1 -component "RescanCompliance"
Write-Log -Message "Sleeping 120 seconds" -severity 1 -component "RescanCompliance"
sleep -Seconds 120
Write-Log -Message "Will start initiating sync for refreshing compliance" -severity 1 -component "RescanCompliance"


# STEP 4 Trigger scheduled task. Sync initiates 
Try
    {
        Get-ScheduledTask | ? {$_.TaskName -eq ‘PushLaunch’} | Start-ScheduledTask
        $GPEvent =  Get-WinEvent -LogName "Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider/Admin" -MaxEvents 10 -FilterXPath "*[System[Provider[@Name='Microsoft-Windows-DeviceManagement-Enterprise-Diagnostics-Provider']]]" `
        | where{$_.id -eq '206'} | select -First 1 | select -ExpandProperty Message
        Write-Log -Message "Policy sync initiated" -severity 1 -component "RescanCompliance"
        Write-Log -Message "$GPEvent" -severity 1 -component "RescanCompliance"
    }
catch [system.exception]
    {
        Write-Log -Message "Failed to perform sync." -severity 3 -component "RescanCompliance"
        Exit
    }


