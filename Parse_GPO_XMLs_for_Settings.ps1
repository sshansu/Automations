<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>


$FileExport = "" # Path where csv will be dumped
$Root = ""  # Path containing all GPOs in XML format

#registry
$table0 = @()
$files = Get-ChildItem $Root -Filter *.xml
foreach ($file in $files)
    {
        [xml]$xmldata2 = Get-Content -Path $file.fullname
        $policyname = $xmldata2.gpo.Name
        $regvalue = $xmldata2.GPO.Computer.ExtensionData.extension.RegistrySettings.registry.Properties
        
        Foreach($value in $regvalue)
            {
                $table0 += New-Object -TypeName PSCustomObject -Property @{
                FileName=$file.Name
                Policy=$policyname
                Hive=$value.hive
                Key=$value.key
                Name=$value.Name
                Type=$value.Type
                Value=$value.Value
                }
        $table0 | select FileName,Policy,Hive,Key,Name,Type,Value | export-csv -path "$FileExport\RegistryPolicy_Computer.csv" -NoTypeInformation 
        }
    }
Write-host "Dumped Registry settings" -ForegroundColor Green

#environmentvariable
$table2 = @()
$files = Get-ChildItem $Root -Filter *.xml #| select -First 1
foreach ($file in $files)
    {
        [xml]$xmldata2 = Get-Content -Path $file.fullname
        $policyname = $xmldata2.gpo.Name
        $regvalue = $xmldata2.GPO.Computer.ExtensionData.extension.EnvironmentVariables.EnvironmentVariable.Properties | select name, value

        Foreach($value in $regvalue)
            {
                $table2 += New-Object -TypeName PSCustomObject -Property @{
                FileName=$file.Name
                Policy=$policyname
                Name=$value.name
                Value=$value.value
                }
                $table2 | export-csv -path "$FileExport\Environmentvariable_Computer.csv" -NoTypeInformation 
            }
    }
Write-host "Dumped Environment variable settings" -ForegroundColor Green


#Filesettings
$table1 = @()
$files = Get-ChildItem $Root -Filter *.xml #| select -First 1
foreach ($file in $files)
    {
        [xml]$xmldata2 = Get-Content -Path $file.fullname
        $policyname = $xmldata2.gpo.Name
        $regvalue = $xmldata2.GPO.Computer.ExtensionData.extension.FilesSettings.File.Properties | select fromPath, targetPath

        Foreach($value in $regvalue)
            {
                $table1 += New-Object -TypeName PSCustomObject -Property @{
                FileName=$file.Name
                Policy=$policyname
                fromPath=$regvalue.fromPath
                targetPath=$regvalue.targetPath
                }
                $table1 | export-csv -path "$FileExport\FileSettings_Devices.csv" -NoTypeInformation
            }
    }
Write-host "Dumped File settings" -ForegroundColor Green

#PowerOptions
$table1 = @()
$files = Get-ChildItem $Root -Filter *.xml
foreach ($file in $files)
    {
        [xml]$xmldata2 = Get-Content -Path $file.fullname
        $policyname = $xmldata2.gpo.Name
        $regvalue = $xmldata2.GPO.Computer.ExtensionData.extension.PowerOptions.GlobalPowerOptionsV2.Properties

        Foreach($value in $regvalue)
            {
                $table1 += New-Object -TypeName PSCustomObject -Property @{
                FileName=$file.Name
                Policy=$policyname
                lidCloseAC=$value.lidCloseAC
                hibernateAC=$value.hibernateAC
                pbActionAC=$value.pbActionAC
                strtMenuActionAC=$value.strtMenuActionAC
                displayOffAC=$value.displayOffAC
                critBatActionAC=$value.critBatActionAC
                lowBatteryLvlAC=$value.lowBatteryLvlAC
            }
                $table1 | export-csv -path "$FileExport\PowerOptions_Devices.csv" -NoTypeInformation
            }
    }
Write-host "Dumped Power Options settings" -ForegroundColor Green

#PublicKeySettings
$table1 = @()
$files = Get-ChildItem $Root -Filter *.xml
foreach ($file in $files)
    {
        [xml]$xmldata2 = Get-Content -Path $file.fullname
        $policyname = $xmldata2.gpo.Name
        $regvalue1 = $xmldata2.GPO.Computer.ExtensionData.extension.EFSSettings
        $regvalue2 = $xmldata2.GPO.Computer.ExtensionData.extension.RootCertificateSettings
        
        if(($regvalue1 -ne $Null) -or ($regvalue2 -ne $Null))
            {
                $table1 += New-Object -TypeName PSCustomObject -Property @{
                FileName=$file.Name
                Policy=$policyname
                AllowEFS=$regvalue1.AllowEFS
                Options=$regvalue1.Options
                CacheTimeout=$regvalue1.CacheTimeout
                KeyLen=$regvalue1.KeyLen
                AllowNewCAs=$regvalue2.AllowNewCAs
                TrustThirdPartyCAs=$regvalue2.TrustThirdPartyCAs
                RequireUPNNamingConstraints=$regvalue2.RequireUPNNamingConstraints
                }
                $table1 | export-csv -path "$FileExport\PublicKeySettings_Device.csv" -NoTypeInformation
            }

    }
Write-host "Dumped Public Key Settings" -ForegroundColor Green

#ShortCutSettings
$table1 = @()
$files = Get-ChildItem $Root -Filter *.xml
foreach ($file in $files)
    {
        [xml]$xmldata2 = Get-Content -Path $file.fullname
        $policyname = $xmldata2.gpo.Name
        $regvalue1 = $xmldata2.GPO.Computer.ExtensionData.extension.ShortcutSettings.Shortcut.Properties
        
        Foreach($value in $regvalue1)
            {
                $table1 += New-Object -TypeName PSCustomObject -Property @{
                FileName=$file.Name
                Policy=$policyname
                targetPath=$value.targetPath
                iconPath=$value.iconPath
                shortcutPath=$value.shortcutPath
                }
                $table1 | export-csv -path "$FileExport\ShortCuts_Device.csv" -NoTypeInformation
            }
    }
Write-host "Dumped ShortCut Settings" -ForegroundColor Green

#WlanPolicies 
$table1 = @()
$files = Get-ChildItem $Root -Filter *.xml
foreach ($file in $files)
    {
        [xml]$xmldata2 = Get-Content -Path $file.fullname
        $policyname = $xmldata2.gpo.Name
        $regvalue1 = $xmldata2.GPO.Computer.ExtensionData.extension.WLanSvcSetting.WlanPolicies
        
        Foreach($value in $regvalue1)
            {
                $table1 += New-Object -TypeName PSCustomObject -Property @{
                FileName=$file.Name
                Policy=$policyname
                Name=$value.Name
                description=$value.description
                policyType=$value.policyType
                }
                $table1 | export-csv -path "$FileExport\WlanPolicies_Device.csv" -NoTypeInformation
            }
    }
Write-host "Dumped WlanPolicies Settings" -ForegroundColor Green

#Firewall
$table1 = @()
$files = Get-ChildItem $Root -Filter *.xml
foreach ($file in $files)
    {
        [xml]$xmldata2 = Get-Content -Path $file.fullname
        $policyname = $xmldata2.gpo.Name
        $rules = "InboundFirewallRules"#, "OutboundFirewallRules"
        Foreach($rule in $rules)
            {
                $regvalue1 = $xmldata2.GPO.Computer.ExtensionData.extension.$rule
                Foreach($value in $regvalue1)
                    {
                        $table1 += New-Object -TypeName PSCustomObject -Property @{
                        FileName=$file.Name
                        Policy=$policyname
                        Rule=$rule
                        Version=$value.Version
                        Action=$value.Action
                        Name=$value.Name
                        Dir=$value.Dir
                        App=$value.App
                        Active=$value.Active
                        }
                        $table1 | export-csv -path "$FileExport\Firewall_Device.csv" -NoTypeInformation
                    }
            }
    }
Write-host "Dumped Firewall Settings" -ForegroundColor Green


#TYPES
$table10 = @()
$files = Get-ChildItem $Root -Filter *.xml
foreach ($file in $files)
    { 
        [xml]$xmldata2 = Get-Content -Path $file.fullname
        $data = $xmldata2.GPO.Computer.ExtensionData.extension
    
        $policyname = $xmldata2.gpo.Name
        Foreach($value in $data)
            {
                $table10 += New-Object -TypeName PSCustomObject -Property @{
                FileName=$file.Name
                Policy=$policyname
                Type=$value.type
                }
                $table10 | export-csv -path "$FileExport\Types1.csv" -NoTypeInformation
            }
    }
       # $data.substring(3) | out-file "$FileExport\Types.csv" -ErrorAction SilentlyContinue -Append 
Write-host "Dumped All GPO Types" -ForegroundColor Green


