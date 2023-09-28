
#####################################################################################################
# ALL THE SCRIPTS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED                   #
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR         #
# FITNESS FOR A PARTICULAR PURPOSE.                                                                 #
#                                                                                                   #
# This script is not supported under any Microsoft standard support program or service.             #
# The script is provided AS IS without warranty of any kind.                                        #
#                                                                                                   #
# Script Name : RenamePC.PS1                                                                        #
# Purpose     : The script is used to derive machine name from csv file stored in container         #
# Version     : v1.0                                                                                #
#####################################################################################################

cls

#Clear previosly stored variables
$vars = (Get-variable | Select-Object name).name
foreach($var in $vars)
    {
        Try
            {
                Clear-Variable -Name $var -Force -ErrorAction SilentlyContinue
            }
        catch
            {}
    }

# Define Variables
$root = "C:\Windows\Temp"
$storageAccName = "cloudrep" # ----> SPECIFY STORAGE ACCOUNT NAME
$container = "devicerename" # ----> SPECIFY STORAGE CONTAINER NAME
$sas = "?sv=2021-12-02&ss=bfqt&srt=o&sp=rtfx&se=2023-09-30T11:42:54Z&st=2023-04-03T03:42:54Z&spr=https&sig=ad%2FwO6hifp%2BcGHAKQ6CG"  # ----> SPECIFY SAS TOKEN     
$destination = $root + "\" + $container 
$blob = "SerialNo.csv" # ----> SPECIFY CSV FILE NAME CONTAINING SERIAL NUMBERS
$domaincontroller = "xs-dc01" # ----> SPECIFY DOMAIN CONTROLLER NAME

#LogWrite function
Function Write-Log
{

    PARAM(
         [String]$Message,
         [String]$Path = "$root\RenamePC.log",
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
Write-Log -Message "Destination folder: $destination" -severity 1 -component "Read Variables"
Write-Log -Message "Storage Account: $storageAccName" -severity 1 -component "Read Variables"
Write-Log -Message "Container: $container " -severity 1 -component "Read Variables"

#########################
##### Test Folder
#########################
# Check if  folder exists, if not create, if yes, clear existing folders and files
Function Test-DestinationFolder
    {
         param
            (
                [Parameter(Mandatory)]
                [string] $folder
            )

        $testpath = test-path $folder
        If(($testpath -eq 'True'))
            {
                Write-Log -Message "Folder exists. Clearing existing files and folders" -severity 1 -component "Test-Folder"
                Remove-Item $folder -Force
            }
        else
            {
                Write-Log -Message "Created $container folder" -severity 1 -component "Test-Folder"
                New-Item $folder -ItemType Directory -Force | Out-Null
            }
    }

#create folder
Test-DestinationFolder -folder $destination

################################
##### Function to Download blobs
################################
Function Get-AzureBlobFromAPI {
    param(
        [Parameter(Mandatory)]
        [string] $StorageAccountName,
        [Parameter(Mandatory)]
        [string] $Container,
        [Parameter(Mandatory)]
        [string] $Blob,
        [Parameter(Mandatory)]
        [string] $SASToken,
        [Parameter(Mandatory)]
        [string] $File
    )

    # documentation: https://docs.microsoft.com/en-us/azure/storage/common/storage-dotnet-shared-access-signature-part-1
    Invoke-WebRequest -Uri "https://$storageAccName.blob.core.windows.net/$Container/$($Blob)$($SAS)" -OutFile $File

}

#########################
##### Rename PC
#########################
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
            }
        catch [system.exception]
            {
                if($err.count -ne 0)
                    {
                        Write-Log -Message "ERROR: Could not rename computer with error '$($_.exception.message)'. Exiting" -severity 3 -component "RenamePC"
                        Copy-Item -Path "C:\Windows\Temp\RenameDevice_RB.Log" -Destination "C:\Windows\Temp\RenameDevice_RB_copy.Log"
                        Remove-item "C:\Windows\Temp\RenameDevice_RB.Log" -Force
                        Exit
                    }
            }
    }

#############################
##### Invoke download of blob
#############################
sleep 1
try
    {
        Write-Log -Message "Downloading $($blob)..." -severity 1 -component "Downloadfiles"
        Get-AzureBlobFromAPI -StorageAccountName $storageAccName -Container $container -Blob $($blob) -SASToken $sas -File $($destination + "\" + $($blob))
    }
catch [system.exception]
{
    Write-Log -Message "ERROR: Could not download blob: $($blob). $($_.exception.message)" -severity 3 -component "Downloadfiles"
}

Write-Log -Message "Download of blob content completed." -severity 1 -component "Downloadfiles"

####################
#Fetch serial number
####################
$serial = Get-WmiObject win32_bios | select -ExpandProperty serialnumber

################################
# Prereq - Check if in domain
################################
$ComputerInfo = Get-ComputerInfo
$InDomain = ($ComputerInfo).CsPartOfDomain
If($InDomain -eq "True")
    {
        Write-Log -Message "Machine joined to domain: $(($ComputerInfo).CsDomain)" -severity 1 -component "Prereq" 
    }
else
    {
        Write-Log -Message "Machine not joined to domain. Exiting" -severity 3 -component "Prereq" 
        Exit
    }

# Check if DC can be reached
try
    {
        $result = Test-ComputerSecureChannel -Server $domaincontroller 
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

#####################################
# Step 1 - Get Machine name from CSV
#####################################
$NewName = Import-Csv $destination\$blob | where{$_.serial -eq $serial} | select -ExpandProperty Name
Write-Log -Message "New name derived from csv: $NewName" -severity 3 -component "RenamePC" 

# Step 2 - Rename PC
RenamePC -oldname $($env:COMPUTERNAME) -newname $NewName

Exit 1000

#delete folder
Test-DestinationFolder -folder $destination 
