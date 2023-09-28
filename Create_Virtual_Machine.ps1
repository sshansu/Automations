<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for 
loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if 
Microsoft has been advised of the possibility of such damages
#>

#$Admincred = Get-Credential -UserName "GlobalAdminAccount" -Message "Enter Password"
$subcriptionID =""
$resourceGroup = ""
$location = "eastus2"
$vmNames = Read-host "Enter VM Names"
$vmSize = "Standard_D4lds_v5" #"Standard_D2S_V3"#
$publisher = "MicrosoftWindowsDesktop"
$offer = "windows-10"
$sku = "win10-21h2-ent-g2"
$version = "latest"
$scriptpath = "<Local Path>\DisableNLA.ps1"
$cmdID = "DisableNLA"
$ExtName = "AADLoginForWindows"
$ExtPublisher = "Microsoft.Azure.ActiveDirectory"
$ExtType = "AADLoginForWindows"
$ExtTypeVersion = "1.0"
$option = "1" #Read-host "Which portion of script you want to run?(1, 2, 3)"
$Admin1 = "SpaceNetAdmin"
$Admin2 = "ArcAdmin"
$value = 1

$LocalAdmin = switch($value)
    {
        1{"$($Admin1)"}
        2{"$($Admin2)"}
    }

# connecting to Azure
write-host "Connecting to Azure" -ForegroundColor DarkYellow
$admincred = Connect-AzAccount -Subscription $subcriptionID

# Get existing context
$currentAzContext = Get-AzContext

# Your subscription. This command gets your current subscription
$subscriptionID=$currentAzContext.Subscription.Id

Write-host "$subscriptionID"

write-host "Accepting local admin password for the VM" -ForegroundColor DarkYellow
$cred = Get-Credential -UserName $LocalAdmin -Message "Enter new local admin password"

foreach($vmName in $vmNames)
    {
        $option = "1"
        Write-host ""
        Write-host "Working on $vmName"
        If($option -eq 1)
            {
                Write-host "Creating VM..." -ForegroundColor Yellow
                Write-host ""
                

                # Network pieces
                $subnetConfig = New-AzVirtualNetworkSubnetConfig -Name "$vmName-Subnet" -AddressPrefix 192.168.1.0/24
                Write-host "Setting Subnet configuration" -ForegroundColor Cyan

                $vnet = New-AzVirtualNetwork -ResourceGroupName $resourceGroup -Location $location -Name "$vmName-vNET" -AddressPrefix 192.168.0.0/16 -Subnet $subnetConfig
                Write-host "Setting Virtual Network" -ForegroundColor Cyan

                $pip = New-AzPublicIpAddress -ResourceGroupName $resourceGroup -Location $location -Name "$vmName-publicdns$(Get-Random)" -AllocationMethod Static -IdleTimeoutInMinutes 4
                Write-host "Setting Public IP configuration" -ForegroundColor Cyan

                $nsgRuleRDP = New-AzNetworkSecurityRuleConfig -Name myNetworkSecurityGroupRuleRDP -Protocol Tcp -Direction Inbound -Priority 1000 -SourceAddressPrefix * -SourcePortRange * `
                    -DestinationAddressPrefix * -DestinationPortRange 3389 -Access Deny
                Write-host "Setting Network Security Rule configuration" -ForegroundColor Cyan

                $nsg = New-AzNetworkSecurityGroup -ResourceGroupName $resourceGroup -Location $location -Name "$vmName-NSG" -SecurityRules $nsgRuleRDP
                Write-host "Setting Network Security Group configuration" -ForegroundColor Cyan

                $nic = New-AzNetworkInterface -Name "$vmName-Nic" -ResourceGroupName $resourceGroup -Location $location -SubnetId $vnet.Subnets[0].Id -PublicIpAddressId $pip.Id -NetworkSecurityGroupId $nsg.Id
                Write-host "Setting Network interface" -ForegroundColor Cyan

                $vm  =  New-AzVMConfig  -VMName  $vmName  -VMSize  $vmSize 
                Write-host "Setting Size config" -ForegroundColor Cyan

                $vm  =  Set-AzVMOperatingSystem -VM  $vm  -Windows -ComputerName  $vmName -Credential  $cred  -ProvisionVMAgent -EnableAutoUpdate 
                Write-host "Setting OS VM configuration" -ForegroundColor Cyan

                $vm = Add-AzVMNetworkInterface  -VM  $vm  -Id  $NIC.Id 
                Write-host "Adding Network interface" -ForegroundColor Cyan

                $vm  =  Set-AzVMSourceImage  -VM  $vm  -PublisherName  $publisher  -Offer  $offer  -Skus  $sku  -Version  $version 
                Write-host "Setting OS image" -ForegroundColor Cyan

                $vm = Set-AzVMOSDisk  -VM  $vm  -StorageAccountType  "StandardSSD_LRS" -CreateOption  "FromImage" 
                Write-host "Setting OS disk" -ForegroundColor Cyan

                $confirm = "Y" #Read-host "Enable TPM?"
                    if($confirm -eq "Y")
                        {
                            $vm = Set-AzVMSecurityProfile  -VM  $vm  -SecurityType  "TrustedLaunch" 
                            Write-host "Setting security profile" -ForegroundColor Cyan
               
                            $vm = Set-AzVmUefi  -VM  $vm  -EnableVtpm  $true  -EnableSecureBoot  $true 
                            Write-host "Setting vTPM" -ForegroundColor Cyan
                        }
                
                Write-host ""
                Write-host "Creating virtual machine..." -ForegroundColor Yellow
                New-AzVM  -ResourceGroupName  $resourceGroup  -Location  $location  -VM  $vm
                
                Write-host "VM Created!" -ForegroundColor Green
                $continue = "Y" #Read-host "Continue to invoke remote script?(Y/N)"
                if($continue -eq "Y")
                    {
                        $option = 2
                    }
            }
        If($option -eq 2) 
            {
                try
                    {
                        Write-host ""
                        # invoke script to disable NLA
                        write-host "Invoking script to disable NLA"
                        $runcommand = Invoke-AzVMRunCommand -VMName $vmName -ResourceGroupName $resourceGroup -ScriptPath $scriptpath -CommandId $cmdID
                        Write-host "$($runcommand.Value.message)" -ForegroundColor cyan
                        #Restart PC
                        write-host "Restarting PC..."
                        $restartpc = Restart-AzVM -Name $vmName -ResourceGroupName $resourceGroup
                        Write-host "Restart VM: $($restartpc.Status)" -ForegroundColor Green

                        $continue = "Y" #Read-host "Continue to add Azure AD VM Extention?(Y/N)"
                        if($continue -eq "Y")
                            {
                                $option = 3
                            }
                    }
                catch
                    {
                        Write-host "Failed due to $($_.exception.message)"
                    }
            }

        If($option -eq 3) 
            {
                try
                    {
                        Write-host ""
                        #Set VM extension
                        write-host "Setting VM Extension for Azure AD User login"
                        Set-AzVMExtension -ResourceGroupName $resourceGroup -VMName $vmName -Name $ExtName -Publisher $ExtPublisher -ExtensionType $ExtType -TypeHandlerVersion $ExtTypeVersion
                        Write-host "VM Extension set" -ForegroundColor Green
                    }
                catch
                    {
                        Write-host "Failed due to $($_.exception.message)"
                    }
            }
    }
