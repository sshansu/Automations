<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>

#Initialize Variables
#$global:authToken = $null
$global:TenantID = "c6ad27e8-880a-4114-9e21-4b9ae776b0ad"
$global:ClientID = "f611de58-d43c-4c0a-a1a3-d5c217f978b6"
$global:ClientSecret = "ltG8Q~eqEzQX_4Rey_ZvLRaHPDg9ljA~HpAKObg8"

####################################################
Function Get-AuthToken {
	<#
	.SYNOPSIS
	This function is used to get an auth_token for the Microsoft Graph API
	.DESCRIPTION
	The function authenticates with the Graph API Interface with client credentials to get an access_token for working with the REST API
	.EXAMPLE
	Get-AuthToken -TenantID "0000-0000-0000" -ClientID "0000-0000-0000" -ClientSecret "sw4t3ajHTwaregfasdgAWREGawrgfasdgAWREGw4t24r"
	Authenticates you with the Graph API interface and creates the AuthHeader to use when invoking REST Requests
	.NOTES
	NAME: Get-AuthToken
	#>
	param(
		[Parameter(Mandatory=$true)]
		$TenantID,
		[Parameter(Mandatory=$true)]
		$ClientID,
		[Parameter(Mandatory=$true)]
		$ClientSecret
	)
	try{
		# Define parameters for Microsoft Graph access token retrieval
		$resource = "https://graph.microsoft.com"
		$authority = "https://login.microsoftonline.com/$TenantID"
		$tokenEndpointUri = "$authority/oauth2/token"

		# Get the access token using grant type client_credentials for Application Permissions
		$content = "grant_type=client_credentials&client_id=$ClientID&client_secret=$ClientSecret&resource=$resource"
		$response = Invoke-RestMethod -Uri $tokenEndpointUri -Body $content -Method Post -UseBasicParsing
		Write-Host "Got new Access Token!" -ForegroundColor Green
		# If the accesstoken is valid then create the authentication header
		if($response.access_token){
		# Creating header for Authorization token
		$authHeader = @{
			'Content-Type'='application/json'
			'Authorization'="Bearer " + $response.access_token
			'ExpiresOn'=$response.expires_on
			}
		return $authHeader
		}
		else{
			Write-Error "Authorization Access Token is null, check that the client_id and client_secret is correct..."
			break
		}
	}
	catch{
		#FatalWebError -Exeption $_.Exception -Function "Get-AuthToken"
	}
}
####################################################
####################################################
Function Validate-AuthToken{
	# Checking if authToken exists before running authentication
	if($global:authToken){
		# Setting DateTime to Universal time to work in all timezones
		#$DateTime = (Get-Date).ToUniversalTime()
		$CurrentTimeUnix = $((get-date ([DateTime]::UtcNow) -UFormat +%s)).split((Get-Culture).NumberFormat.NumberDecimalSeparator)[0]
		# If the authToken exists checking when it expires
		#$TokenExpires = ($authToken.ExpiresOn.datetime - $DateTime).Minutes
		$TokenExpires = [MATH]::floor(([int]$authToken.ExpiresOn - [int]$CurrentTimeUnix) / 60)
		if($TokenExpires -le 0){
			write-host "Authentication Token expired" $TokenExpires "minutes ago" -ForegroundColor Yellow
			$global:authToken = Get-AuthToken -TenantID $global:TenantID -ClientID $global:ClientID -ClientSecret $global:ClientSecret
		}
	}
	# Authentication doesn't exist, calling Get-AuthToken function
	else {
		# Getting the authorization token
		$global:authToken = Get-AuthToken -TenantID $global:TenantID -ClientID $global:ClientID -ClientSecret $global:ClientSecret
	}
}
####################################################

Validate-AuthToken

# Render Group ID
Function Get-GroupID(){

[cmdletbinding()]
Param(
        [Parameter(Mandatory = $true)]
        $GroupName
    )

    try
        {
         
            $uri = "https://graph.microsoft.com/beta/groups?`$filter=displayName eq '$($GroupName)'&`$select=id,displayName"
            $result = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
            $Value = $result.value
        }
    catch
        {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        }
    write-output $Value

}

# Query Configuration Profiles
Function Get-DeviceConfigurationPolicy(){

    <#
.SYNOPSIS
This function is used to get device configuration policies from the Graph API REST interface
.DESCRIPTION
The function connects to the Graph API Interface and gets any device configuration policies
.EXAMPLE
Get-DeviceConfigurationPolicy
Returns any device configuration policies configured in Intune
.NOTES
NAME: Get-DeviceConfigurationPolicy
#>

[cmdletbinding()]
Param(
        [Parameter(Mandatory = $true)]
        [ValidateSet("All","Specific")]
        $Query,
     
        [Parameter(Mandatory = $false)]
        $PolicyName,

        [Parameter(Mandatory = $True)]
        [ValidateSet("SettingsCatalog","Others")]
        $PolicyType
    )

    # Define Graph API Resource
    $GraphResource = Switch ($PolicyType) {
    "SettingsCatalog" {"deviceManagement/configurationPolicies";$RenderSelect = "name"}
    "Others" {"deviceManagement/deviceConfigurations";$RenderSelect = "displayName"}
    }    
    #Write-host "$GraphResource"

    try
        {
         
            $uri = "https://graph.microsoft.com/Beta/$GraphResource"
            $result = Invoke-RestMethod -Uri $uri -Headers $authToken -Method Get
            
            # Switch
            $Values = Switch ("$Query") {
            "All" {$result.value | select $RenderSelect, id}
            "Specific" {$result.value | select $RenderSelect, id  | Where{ ($_.$($RenderSelect)).contains("$PolicyName")}}
            } 
        }
    catch
        {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        }
    write-output $values
}

# Assign Configuration Profiles
Function Assign-DeviceConfigurationPolicy(){

[cmdletbinding()]
Param(
     [Parameter(Mandatory = $true)]
     [ValidateSet("All","Specific")]
     $Assign,
     
     [Parameter(Mandatory = $False)]
     $PolicyName,

     [Parameter(Mandatory = $True)]
     [ValidateSet("SettingsCatalog","Others")]
     $PolicyType,

     [Parameter(Mandatory = $False)]
     $Group
 )

    #write-host "$Assign"
    #Write-host "$PolicyName"
    #Write-host "$PolicyType"

    # Begin assignment
    try
        {   
            if($Assign -eq "All")
                {
                    $Policies = Get-DeviceConfigurationPolicy -Query All -PolicyType $PolicyType
                }
            elseif($Assign -eq "Specific")
                {
                    $Policies = Get-DeviceConfigurationPolicy -Query Specific -PolicyName $PolicyName -PolicyType $PolicyType
                }
            #Write-host $Policies

            # Define Graph API Resource
            $GraphResource = Switch ($PolicyType) {
            "SettingsCatalog" {"deviceManagement/configurationPolicies"}
            "Others" {"deviceManagement/deviceConfigurations/"}
            }
            #Write-host "$GraphResource"

            # Get Group ID
            $GroupID = Get-GroupID -GroupName $Group | select -ExpandProperty id

            #Prepare JSON Body for assignment
            $params = @{
	        assignments = @(
		        @{
			        target = @{
				        "@odata.type" = "#microsoft.graph.groupAssignmentTarget"
				        groupId = "$($GroupId)"
			        }
		        }
	        )
            }
            $JSONBody = $params | ConvertTo-Json -Depth 10

            foreach($policy in $Policies)
                {
                    try
                        {
                            # Begin Assignment
                            if($PolicyType -eq "SettingsCatalog")
                                {
                                    $uri = "https://graph.microsoft.com/beta/$($GraphResource)" + "('$($Policy.id)')/assign"
                                    $PolicyName = $policy.name
                                }
                            elseif($PolicyType -eq "Others")
                                {
                                    $uri = "https://graph.microsoft.com/beta/$($GraphResource)$($Policy.id)/assign"
                                    $PolicyName = $policy.displayName
                                }
                            #write-host $uri

                            #sleep 30
                            $output = Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method POST -Body $JSONBody
                            Write-Host "Assigned $($PolicyName) to $Group" -ForegroundColor Cyan
                        }
                    catch
                        {
                            Write-Host "Failed to assign $($policy.displayName) due to $($_.exception.message)" -ForegroundColor Red
                            $ex = $_.Exception
                            $errorResponse = $ex.Response.GetResponseStream()
                            $reader = New-Object System.IO.StreamReader($errorResponse)
                            $reader.BaseStream.Position = 0
                            $reader.DiscardBufferedData()
                            $responseBody = $reader.ReadToEnd();
                            Write-Host "Response content:`n$responseBody" -f Red
                            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
                            write-host
                            break
                        }
                }
        }
    catch
        {
            $ex = $_.Exception
            $errorResponse = $ex.Response.GetResponseStream()
            $reader = New-Object System.IO.StreamReader($errorResponse)
            $reader.BaseStream.Position = 0
            $reader.DiscardBufferedData()
            $responseBody = $reader.ReadToEnd();
            Write-Host "Response content:`n$responseBody" -f Red
            Write-Error "Request to $Uri failed with HTTP Status $($ex.Response.StatusCode) $($ex.Response.StatusDescription)"
            write-host
            break
        }
}

Assign-DeviceConfigurationPolicy -Assign Specific -PolicyName "Domain Join" -PolicyType Others -Group "Licensed Users"

    