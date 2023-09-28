<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever 
(including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out 
of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages

Use this script as a requirement rule to delay the installation of a Win32 Application, either during Windows Autopilot process or in full blown OS.

Currently this script delays the execution of Win32 app by 60 minutes. You can reduce or bump it up on line 24.
#>

Function GetRegDate ($path, $key){
    function GVl ($ar){
        return [uint32]('0x'+(($ar|ForEach-Object ToString X2) -join ''))
    }
    $ar=Get-ItemPropertyValue $path $key
    [array]::reverse($ar)
    $time = New-Object DateTime (GVl $ar[14..15]),(GVl $ar[12..13]),(GVl $ar[8..9]),(GVl $ar[6..7]),(GVl $ar[4..5]),(GVl $ar[2..3]),(GVl $ar[0..1])
    return $time
}
$AppInstallDelay = New-TimeSpan -Days 0 -Hours 0 -Minutes 60 ##--> DEFINE TIME IN MINUTES TO APPLY A DELAY IN EXECUTION

$RegKey = (@(Get-ChildItem "HKLM:\SOFTWARE\Microsoft\Enrollments" -recurse | Where-Object {$_.PSChildName -like 'DeviceEnroller'}))
$RegPath = $($RegKey.name).TrimStart("HKEY_LOCAL_MACHINE")
$RegDate = GetRegDate HKLM:\$RegPath "FirstScheduleTimestamp"
$DeviceEnrolmentDate = Get-Date $RegDate
If ((Get-Date) -ge ($DeviceEnrolmentDate + $AppInstallDelay)) {
    $InstallApp = $True
}
Else {
    $InstallApp = $False
}
$InstallApp 

