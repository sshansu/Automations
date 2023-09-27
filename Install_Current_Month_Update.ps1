<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>

# Define variables
$CabPath = "C:\Windows\Temp\CurrentUpdates"
$URL = "https://catalog.s.download.windowsupdate.com/d/msdownload/update/software/updt/2023/07/windows10.0-kb5028244-x64_c9831d703373ce46e2e86c0849e1f131de9b854d.msu"  # ---> Replace with download path of current month update in CAB format
$UpdateFile =  Split-Path $downloadURL -Leaf
$destination = "$CabPath\$filename"
$InstallLog = "$CabPath\UpdateInstall.log"
$PathExist = test-path $CabPath
If($PathExist -eq 'True')
    {
        get-childitem $CabPath -ea 0 | Remove-Item -Force
    }
else
    {
        New-Item $CabPath -ItemType Directory -Force | %{$_.Attributes = "hidden"}
    }


Function Install-Current {
param($DownloadURL, $File, $Log, $Path)

    # Step 1 Download Update
    try
        {
            Write-Log -Message "Started download of cumulative update" -severity 1 -component "InstallUpdate"
            Start-BitsTransfer -Source $downloadURL -Destination $File -ErrorAction Stop
            sleep 5
            Write-Log -Message "Cumulative update downloaded" -severity 1 -component "InstallUpdate"
        }
    catch [exception.message]
        {
            Write-Log -Message "Failed to download current month update due to $($_.exception.message)" -severity 3 -component "InstallUpdate"
        }

    # Step 2 Expand Update
    try
        {
            start-process -FilePath "cmd" -ArgumentList "/c expand -f:* `"$File`" `"$Path`"" -WindowStyle Hidden -ErrorAction Stop
            Write-Log -Message "Expanded cumulative update" -severity 1 -component "InstallUpdate"
        }
    catch [exception.message]
        {
            Write-Log -Message "Failed to expand msu due to $($_.exception.message)" -severity 3 -component "InstallUpdate"
        }

    # Step 3 Apply Update
    try
        {
            $cabfiles = Get-ChildItem $CabPath -Filter "*.cab" -Recurse -Exclude "WSUSSCAN.cab"
            foreach($file in $cabfiles)
                {
                    sleep 5
                    start-process -FilePath "cmd" -ArgumentList "/c dism.exe /online /add-package /packagepath:`"$($file.FullName)`" /quiet /norestart /logpath:`"$Log`"" -WindowStyle Hidden -ErrorAction Stop
                    Write-Log -Message "Applied $($file.Name)" -severity 1 -component "InstallUpdate"
                }
        }
    catch [exception.message]
        {
            Write-Log -Message "Failed to apply update due to $($_.exception.message)" -severity 3 -component "InstallUpdate"
        }

    }

Install-Current -DownloadURL $URL -File $UpdateFile -Path $CabPath -Log $InstallLog

