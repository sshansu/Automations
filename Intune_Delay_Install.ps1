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