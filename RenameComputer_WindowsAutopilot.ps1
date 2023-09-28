<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever 
(including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or 
inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages

The script will be used as a Win32 app during Autopilot "Device Setup" phase. The script invokes the runbook to generate a computer name and then renders the same name from the 
storage account table and applies it. Creates a log in "C:\Users\Public\RenameDevice_RB.Log"
#>



#LogWrite function
Function Write-Log
    {
        PARAM(
                [String]$Message,
                [String]$Path = "C:\Users\Public\RenameDevice_RB.Log",
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
#Invoke-Item "C:\Windows\Temp\RenameDevice.Log"
Write-Log -Message "Initiated..." -severity 1 -component "Initialize Script"
Write-Log -Message "Current machine name: $($env:COMPUTERNAME)" -severity 1 -component "Prereq"  

#Variables
$RunbookURL = "https://4dae5f91-adfe-4f5f-aba9-81b72b940e39.webhook.sea.azure-automation.net/webhooks?token=%2biNBudhomo5sNwpDISU0PejjbdyniT3tAqyXGQKrEok%3d"  # ----> SPECIFY WEBHOOK URL TO INVOKE RUNBOOK
$StorageAccount = "cloudrep"   # ----> SPECIFY STORAGE ACCOUNT NAME
$AZTableName = "devicename"    # ----> SPECIFY STORAGE TABLE NAME
$AZTableSasReadToken = "?sv=2021-12-02&ss=bfqt&srt=o&sp=rtfx&se=2023-09-30T11:42:54Z&st=2023-04-03T03:42:54Z&spr=https&sig=ad%2FwO6hifp%2BcGHAKQ6CGP"  # ----> SPECIFY SAS TOKEN
$AZTableUri = "https://$StorageAccount.table.core.windows.net/$AZTableName$AZTableSasReadToken"
$domaincontroller =  "XS-DC01" # ----> SPECIFY DOMAIN CONTROLLER NAME

# Prereq - Check if in domain
$ComputerInfo = Get-ComputerInfo
$InDomain = ($ComputerInfo).CsPartOfDomain

##########################################
If($InDomain -eq "True")
    {
        Write-Log -Message "Machine joined to domain: $(($ComputerInfo).CsDomain)" -severity 1 -component "Prereq" 
    }
else
    {
        Write-Log -Message "Machine not joined to domain. Exiting" -severity 3 -component "Prereq" 
        Exit
    }
##########################################

# Check if DC can be reached
##########################################
try
    {
        $result = Test-ComputerSecureChannel -Server ($domaincontroller).Trim() 
        if($result -eq "True")
            {
                Write-Log -Message "Successful connection to domain controller: $($domaincontroller)" -severity 1 -component "Prereq"
            }
    }
catch [System.Exception]
    {
        Write-Log -Message "ERROR: Could not connect to domain controller $($domaincontroller) with error $($_.exception.message). Exiting" -severity 3 -component "Prereq"
        Exit
    }
##########################################

#Invoke Runbook Function
##########################################
Function Invoke-Runbook 
    {
         PARAM(
                [String]$URI
              )

        try 
            {
                $result = Invoke-WebRequest -Uri $uri -Method Post -UseBasicParsing
                Write-Log -Message "Invoked Runbook using Webhook URL: $RunbookURL" -severity 1 -component "InvokeRunbook" 
            }
        catch [system.exception]
            {
                Write-Log -Message "ERROR: Could not invoke runbook with error $($_.exception.message). Exiting" -severity 3 -component "InvokeRunbook"
                Exit
            }
    }
##########################################

#Function to Get machine name
##########################################
Function Get-MachineName
    {
        PARAM (
                [String]$TableURI
              )

        # Generate header
        $GMTTime = (Get-Date).ToUniversalTime().toString('R')
        $header = @{
            'x-ms-date' = $GMTTime;
            Accept = 'application/json;odata=nometadata'
        }

        try
            {
                # Poll AZ Table 
                $finalResult = Invoke-WebRequest -Uri $TableURI -Headers $header -UseBasicParsing
                $finalResult = $finalResult.Content | ConvertFrom-Json
                $newpcname = $finalResult.value.rowkey

 

                Write-Log -Message "New name retrieved from AZTable: $newpcname" -severity 1 -component "QueryTable" 
                return $newpcname
            }
        catch [system.exception]
            {
                Write-Log -Message "ERROR: Could not query table: $($AZTableName) with error $($_.exception.message). Exiting" -severity 3 -component "QueryTable"
                Exit
            }

    }
##########################################

# Function Rename PC
##########################################
Function RenamePC
    {
        PARAM (
                [String]$oldname,
                [String]$newname
              )

        try
            {
                Rename-Computer -ComputerName $oldname -NewName $newname -ErrorAction Stop -ErrorVariable err
                Write-Log -Message "Renamed computer. Restart PC for changes to take effect" -severity 1 -component "RenamePC" 
                Copy-Item -Path "C:\Users\Public\RenameDevice_RB.Log" -Destination "C:\Users\Public\RenameDevice_RB_copy.Log"
                Remove-item "C:\Users\Public\RenameDevice_RB.Log" -Force
            }
        catch [system.exception]
            {
                if($err.count -ne 0)
                    {
                        Write-Log -Message "ERROR: Could not rename computer with error '$($_.exception.message)'. Exiting" -severity 3 -component "RenamePC"
                        Copy-Item -Path "C:\Users\Public\RenameDevice_RB.Log" -Destination "C:\Users\Public\RenameDevice_RB_copy.log"
                        Remove-item "C:\Users\Public\RenameDevice_RB.Log" -Force
                        Exit
                    }
            }
    }
##########################################

# Step 1 - Invoke Runbook
Invoke-Runbook -URI $RunbookURL

# Step 2 - Generate Random Sleep
$rndm = get-random -Minimum 30 -Maximum 35
Write-Log -Message "Sleeping for $rndm seconds" -severity 1 -component "InvokeRunbook" 
sleep -Seconds $rndm

# Step 3 - Get Machine name from AZTable
$newpcname = Get-MachineName -TableURI $AZTableUri

# Step 4 - Rename PC
RenamePC -oldname $($env:COMPUTERNAME) -newname $newpcname

Exit 0 


