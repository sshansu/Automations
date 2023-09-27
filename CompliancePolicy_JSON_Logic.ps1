$App = "Google Chrome"
$installedApp = Get-ItemProperty HKLM:\Software\Wow6432Node\Microsoft\Windows\CurrentVersion\Uninstall\* | `
Select-Object DisplayName, DisplayVersion, Publisher | where{$_.DisplayName -eq $App}
If($installedApp)
    {
        $hash = @{ AppName = $installedApp.DisplayName; Version = $installedApp.DisplayVersion; Publisher = $installedApp.Publisher; AppPresent = $true}
        return $hash | ConvertTo-Json -Compress
    }
else
    {
        $hash = @{ AppName = $App; Version = $null; Publisher = $null; AppPresent = $false}
        return $hash | ConvertTo-Json -Compress
    }