<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>

$LocalAdminName = "SpaceNetAdmin"
$Pwd = "in clear text"
$DNSServerIP = "192.168.0.100"
$Gateway = "192.168.0.1"

Invoke-Command -ScriptBlock {(net user /add "$($LocalAdminName)" "$($Pwd)"), (net localgroup administrators "$($LocalAdminName)" /add)} | out-null
sleep 5
$wmi = Get-WmiObject win32_networkadapterconfiguration | where{$_.DHCPEnabled -eq 'True' -and $_.IPAddress -ne $Null}
$wmi.SetDNSServerSearchOrder($DNSServerIP)
$wmi.SetGateways($Gateway, 1)
sleep 5
Invoke-Command -ScriptBlock {(ipconfig /registerdns)} | out-null