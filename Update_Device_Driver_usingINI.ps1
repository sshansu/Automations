#LogWrite function
Function Write-Log
{

    PARAM(
         [String]$Message,
         [String]$Path = "C:\windows\Temp\$($env:computername)-DriverUpdate.Log",
         [int]$severity,
         [string]$component
         )
         
         $TimeZoneBias = Get-CimInstance -Query "Select Bias from Win32_TimeZone"
         $Date = Get-Date -Format "HH:mm:ss.fff"
         $Date2 = Get-Date -Format "MM-dd-yyyy"
         $type =1
         
         "<![LOG[$Message]LOG]!><time=$([char]34)$date$($TimeZoneBias.bias)$([char]34) date=$([char]34)$date2$([char]34) component=$([char]34)$component$([char]34) context=$([char]34)$([char]34) type=$([char]34)$severity$([char]34) thread=$([char]34)$([char]34) file=$([char]34)$([char]34)>"| Out-File -FilePath $Path -Append -NoClobber -Encoding default
}

# Read XML File
$XMLFilePath = "C:\Temp\Drivers-Update\Config.xml"
[xml]$xml = get-content $XMLFilePath

function Get-ServerShare {
    $obj = $xml.CentralSettings.ServerShare
    Write-Output $obj
}

function Get-DriverOption {
    $obj = $xml.CentralSettings.DriverOption
    Write-Output $obj
}

function Get-DriverOutputPath {
    $obj = $xml.CentralSettings.DriverOutputPath
    Write-Output $obj
}

# Define Variables
$serverpath = Get-ServerShare
$option = Get-DriverOption
$DriverOutputPath = Get-DriverOutputPath
$DeviceModel = Get-DeviceModel

# Define driver based on driver option from above variable
$DrivertoUpdate = Switch ($option)
      {
       1 { "Network" }
       2 { "Audio" }
       3 { "Chipset" }
       4 { "Graphics" }
       5 { "Other" }
       6 { "Storage" }
      }

Write-Log -Message " " -severity 1 -component "Initialize Script"
Write-Log -Message "Driver location: $serverpath"  -severity 1 -component "GetParams"
Write-Log -Message "Driver to update: $DrivertoUpdate"  -severity 1 -component "GetParams"
Write-Log -Message "Driver output path: $DriverOutputPath"  -severity 1 -component "GetParams"
Write-Log -Message "Device model: $DeviceModel"  -severity 1 -component "GetParams"

# Get device model 
Function Get-DeviceModel{
        $obj = Get-CimInstance -ClassName Win32_ComputerSystem | select -ExpandProperty Model
        Write-Output $obj
    }

# Invoke pnputil 
Function Update_Driver{
    PARAM(
            [String]$sharepath,
            [String]$Driver
         ) 
    
    Write-Log -Message "Sleeping for 10 seconds."  -severity 1 -component "SearchDriver"
    sleep 10
    Write-Log -Message "Searching for driver repository for current model on server share."  -severity 1 -component "SearchDriver"
    $subfolder = get-childitem -Path $sharepath -Recurse -Filter $DeviceModel -Directory -ErrorAction SilentlyContinue
    if($subfolder)
        {
            Write-Log -Message "Found driver folder for this specific model. Will continue..."  -severity 1 -component "SearchDriver"
        }
    else
        {
            Write-Log -Message "Did not find any driver repository for this model. Exiting"  -severity 2 -component "SearchDriver"
            Exit
        }

    $Path = Join-path $sharepath -ChildPath $subfolder
    $1stLevelSF = (Get-ChildItem -path $Path -Directory).FullName
    $2ndLevelSF = (Get-ChildItem -path $1stLevelSF -Directory).FullName
    $driverpath = Join-path $2ndLevelSF -ChildPath $Driver
    $InfWCPath = Join-Path $driverpath -ChildPath "\*.inf"
    Write-Log -Message "Driver path: $InfWCPath"  -severity 1 -component "SearchDriver"

    $argument = "/c C:\windows\system32\pnputil /add-driver `"$InfWCPath`" /subdirs /install /reboot >> $($DriverOutputPath)"
    
    #Test connectivity to network share
    try
        {
            Resolve-Path $Path -ErrorAction Stop | out-Null
            Write-Log -Message "Successfully resolved server share."  -severity 1 -component "UpdateDriver"
        }
    catch 
        {
            Write-Log -Message "Error! $($_.exception.message)"  -severity 3 -component "UpdateDriver"
            Write-Log -Message "Exit" -severity 1 -component "UpdateDriver"
            Exit
        }
    
    # driver update
    try
        {
            Write-Log -Message "Sleeping for 10 seconds."  -severity 1 -component "UpdateDriver"
            sleep 10
            Write-Log -Message "Attempting to update driver..."  -severity 1 -component "UpdateDriver"
            Write-Log -Message "Executing command: $argument"  -severity 1 -component "UpdateDriver"
            Start-Process "cmd.exe" -ArgumentList $argument -WindowStyle Hidden -ErrorAction Stop
            Write-Log -Message "Driver install invoked!" -severity 1 -component "UpdateDriver"
        }
    catch [system.exception]
        {
            Write-Log -Message "ERROR: Could not invoke driver install due to: $($_.exception.message). Exiting" -severity 3 -component "UpdateDriver"
            Exit
        }  

} 

#invoke driver update
Update_Driver -sharepath $serverpath -Driver $DrivertoUpdate
Write-Log -Message "End" -severity 1 -component "End"