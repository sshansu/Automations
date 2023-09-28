#######################################################################################################
# ALL THE SCRIPTS PROVIDED "AS IS" WITHOUT WARRANTY OF ANY KIND, EITHER EXPRESSED                     #
# OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR           #
# FITNESS FOR A PARTICULAR PURPOSE.                                                                   #
#                                                                                                     #
# This script is not supported under any Microsoft standard support program or service.               #
# The script is provided AS IS without warranty of any kind.                                          #
#                                                                                                     #
# Script Name : MergeReport.PS1                                                                       #
# Purpose     : The script is used to Merge the reports stored in storage account                     #
#               Before executing this script, we'll have to execute Report_Windows11_CurrentStatus.ps1 #
# Version     : v1.0                                                                                  #
# Created by  : sshansu@microsoft.com                                                                 #
#######################################################################################################

# Define Variables
$root = "C:\Temp\Windows11"
$sourcefolder = "$root\zip"   ##### <----- DEFINE YOUR PATH HERE
$Extpath = "$sourcefolder\zipextract"
$storageAccName = "arcadewin11report"  # STORAGE ACCOUNT NAME
$container = "getwinreport"  # CONTAINER NAME
$sas = "?sp=rw&st=2023-08-10T09:50:17Z&se=2023-12-31T17:50:17Z&spr=https&sv=2022-11-02&sr=c&sig=pGZhejvw3ef1"      # SAS TOKEN
$downloadLocation = $Extpath 
$destination = $downloadLocation + "\" + $container 

#LogWrite function
Function Write-Log
{

    PARAM(
         [String]$Message,
         [String]$Path = "$root\ExtractFolders.log",
         [int]$severity,
         [string]$component
         )
         
         $TimeZoneBias = Get-CimInstance -Query "Select Bias from Win32_TimeZone"
         $Date = Get-Date -Format "HH:mm:ss.fff"
         $Date2 = Get-Date -Format "MM-dd-yyyy"
         $type =1
         
         "<![LOG[$Message]LOG]!><time=$([char]34)$date$($TimeZoneBias.bias)$([char]34) date=$([char]34)$date2$([char]34) component=$([char]34)$component$([char]34) context=$([char]34)$([char]34) type=$([char]34)$severity$([char]34) thread=$([char]34)$([char]34) file=$([char]34)$([char]34)>"| Out-File -FilePath $Path -Append -NoClobber -Encoding default
}

# Clear existing Log if exceeding 5 Mb
$logname = "ExtractFolders.log"
function Delete-log
    {
        $checklogsize = [math]::Round(((Get-childitem $sourcefolder -Filter $logname -ErrorAction SilentlyContinue).Length/1024)) 
        if($checklogsize -ge "5000")
            {
               write-Host "Deleting log" 
               Get-childitem $sourcefolder -Filter $logname | Remove-item -Force -ea 0
            }
        else{}
    }
Delete-Log

Write-Log -Message " " -severity 1 -component "Initialize Script"
Write-Log -Message "*****************************************" -severity 1 -component "Initialize Script"
Write-Log -Message "Script start time: $(get-date -format g)" -severity 1 -component "Initialize Script"
Write-Log -Message "*****************************************" -severity 1 -component "Initialize Script"
Write-Log -Message "Source folder: $sourcefolder" -severity 1 -component "Read Variables"
Write-Log -Message "Storage Account: $storageAccName" -severity 1 -component "Read Variables"
Write-Log -Message "Container: $container " -severity 1 -component "Read Variables"
Write-Log -Message "Destination folder: $destination" -severity 1 -component "Read Variables"


############################
##### Get blobs from storage
############################
Function Get-blobs
    {
        param(
        [Parameter(Mandatory)]
        [string] $StorageAccountName,
        [Parameter(Mandatory)]
        [string] $Container,
        [Parameter(Mandatory)]
        [string] $ResourceGroup 
    )

        Connect-AzAccount | Out-Null
        
        # Get-AzLocation | Select-Object -Property Location
        # $Location = 'centralindia'

        #$ResourceGroup = 'SystemCenter'
        #$storagename = 'runbookblobs'
        #$ContainerName = 'clienthealth'

        $StorageAccount = Get-AzStorageAccount -ResourceGroupName $ResourceGroup -Name $StorageAccountName
        $Context = $StorageAccount.Context

        $blobs = Get-AzStorageBlob -Container $Container -Context $Context | Select-Object -Property Name -ExpandProperty Name
        Write-Output $blobs
    }

#########################
##### Test Extract Folder
#########################
# Check if extract folder exists, if not create, if yes, clear existing folders and files
Function Test-ExtractFolder
    {
        $testpath = test-path $Extpath
        If($testpath -eq 'True')
            {
                Write-Log -Message "Extract folder exists. Clearing existing files and folders" -severity 1 -component "Test-ExtractFolder"
                get-childitem $destination -ea 0 | Remove-Item -Recurse -Force
            }
        else
            {
                Write-Log -Message "Extract folder does not exist. Creating folder." -severity 1 -component "Test-ExtractFolder"
                New-Item $destination -ItemType Directory -Force
            }
    }Test-ExtractFolder

#########################
##### Download blobs
#########################
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
    Invoke-WebRequest -Uri "https://$StorageAccountName.blob.core.windows.net/$Container/$($Blob)$($SASToken)" -OutFile $File
}

$DeviceNames = Get-blobs -ResourceGroup "SpaceNetEnv" -StorageAccountName "arcadewin11report" -Container "getwinreport" 
$blobNames = @($DeviceNames)
Write-Log -Message "Initiating download of blobs from container" -severity 1 -component "Downloadfiles"
foreach($blob in $blobNames)
    {
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
    }

Write-Log -Message "Download of blob content completed." -severity 1 -component "Downloadfiles"

#################
##### Extract ZIP
#################
Function Extract-files 
    {
        $countzip = (Get-ChildItem -Path $destination -Filter *.zip).count
        Write-Log -Message "$($countzip) ZIP files to extract" -severity 1 -component "Extract-files"
        Write-Log -Message "Extracting files..." -severity 1 -component "Extract-files"
        try
            {
                $count = 0
                $getfiles = Get-ChildItem -Path $destination -Filter *.zip 
                foreach($zip in $getfiles)
                    {
                        $count++
                        $per = $count/$countzip*100
                        for ($i = 1; $i -le 100; $i++ )
                            {
                                Write-Progress -Activity "Search in Progress" -Status "$i% Complete:" -PercentComplete $i -ParentId 1;
                            }
                        Expand-Archive -Path $zip.FullName -DestinationPath $destination\$($zip.basename) -Force
                        Write-Progress -Activity "Extracting files and folders..." -Status "Progress: $([math]::Round($per))%" -PercentComplete ($per) -ID 1
                    }
                
                #| ForEach-Object {Expand-Archive -Path $zip.FullName -DestinationPath $Extpath\$_ -Force}
                Write-Log -Message "Extracted files" -severity 1 -component "Extract-files"
                
            }
        catch [System.Exception]
            {
                Write-Log -Message "Failed to extracted files with error: $($_.Exception.Message)" -severity 3 -component "Extract-files"   
            }
    }Extract-files

################
##### Merge CSV
################
Function Merge-CSV
    {
        $countcsv = (Get-ChildItem -Path $destination -Recurse -Filter *.csv).count
        Write-Log -Message "$($countcsv) CSV files to merge" -severity 1 -component "Merge-CSV"
        Write-Log -Message "Merging files..." -severity 1 -component "Merge-CSV"
        try
            {
                Get-ChildItem -Path $destination -Recurse -Filter *.csv | Select-Object -ExpandProperty FullName | Import-Csv | Export-Csv $sourcefolder\Merged-$(Get-Date -Format "MM-dd-yyyy_hh-mm-ss").csv -NoTypeInformation -Append
                Write-Log -Message "Merged Files." -severity 1 -component "Merge-CSV"
            }
        catch [System.Exception]
            {
                Write-Log -Message "Failed to merge CSV files with error: $($_.Exception.Message)" -severity 3 -component "Merge-CSV"  
            }
    }Merge-CSV
