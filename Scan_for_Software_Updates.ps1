<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>

#LogWrite function
Function Write-Log
{

    PARAM(
         [String]$Message,
         [String]$Path = "C:\Temp\SoftwareUpdate.Log",
         [int]$severity,
         [string]$component
         )
         
         $TimeZoneBias = Get-CimInstance -Query "Select Bias from Win32_TimeZone"
         $Date = Get-Date -Format "HH:mm:ss.fff"
         $Date2 = Get-Date -Format "MM-dd-yyyy"
         $type =1
         
         "<![LOG[$Message]LOG]!><time=$([char]34)$date$($TimeZoneBias.bias)$([char]34) date=$([char]34)$date2$([char]34) component=$([char]34)$component$([char]34) context=$([char]34)$([char]34) type=$([char]34)$severity$([char]34) thread=$([char]34)$([char]34) file=$([char]34)$([char]34)>"| Out-File -FilePath $Path -Append -NoClobber -Encoding default
}

$argument = "/c C:\windows\system32\USOClient.exe StartInteractiveScan"

# update
    try
        {
            Write-Log -Message "Sleeping for 10 seconds."  -severity 1 -component "UpdateScan"
            sleep 10
            Write-Log -Message "Attempting to initiate update scan..."  -severity 1 -component "UpdateScan"
            Write-Log -Message "Executing command: $argument"  -severity 1 -component "UpdateScan"
            Start-Process "cmd.exe" -ArgumentList $argument -WindowStyle Hidden -ErrorAction Stop
            Write-Log -Message "Update scan invoked!" -severity 1 -component "UpdateScan"
        }
    catch [system.exception]
        {
            Write-Log -Message "ERROR: Could not invoke update scan due to: $($_.exception.message). Exiting" -severity 3 -component "UpdateScan"
            Exit
        } 
Exit 0