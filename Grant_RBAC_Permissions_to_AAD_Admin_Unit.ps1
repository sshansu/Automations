<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages

This script is to automate RBAC Role assignment of HelpDesk Administrator and User Administrator to Azure AD Administrative Unit.

#>

Param (
	[string]$AU,
	[string]$IntuneGroup,
	[string]$IntuneGroup_Helpdesk,
    [string]$IntuneGroup_UserAdmin,
    [string]$RoleDefinition
)

<# Login to Azure AD PowerShell With Admin Account
$connectionName="AzureRunAsConnection" 
$servicePrincipalConnection = Get-AutomationConnection -Name $connectionName         

# Connect to Azure
$connectState = Connect-AzureAD -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint
#$connectState = Connect-AzAccount -TenantId $servicePrincipalConnection.TenantId -ApplicationId $servicePrincipalConnection.ApplicationId -CertificateThumbprint $servicePrincipalConnection.CertificateThumbprint
if ($connectState) {
      "Connected."
  } else {
      "Doesn't seem to be connected."
  }
#>

# Define graph variables
$global:authToken = $null
$global:TenantID = "d948da51-c23f-4c15-89e5-b2dde3add88d"
$global:ClientID = "bde5156f-9cc0-43de-b310-1f2d580810ae"
$global:ClientSecret = "u-F8Q~F6cOehRYEDt9VqDXqLhFvxRelO03CMcdqv"

<# Group variables
$AU = "0125"
$IntuneGroup =  "Intune - 0125"
$IntuneGroup_Helpdesk = "Intune - RLGroup - ITAdmins"
$IntuneGroup_UserAdmin = "Intune - RLGroup - ITAdmins 6310"
$RoleDefinition = "Custom_ITAdmin_All-Read"
#>

# connect to graph
Function Get-AuthToken {
	<#
	.SYNOPSIS
	This function is used to get an auth_token for the Microsoft Graph API
	.DESCRIPTION
	The function authenticates with the Graph API Interface with client credentials to get an access_token for working with the REST API
	.EXAMPLE
	Get-AuthToken -TenantID "0000-0000-0000" -ClientID "0000-0000-0000" -ClientSecret ""
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
		Write-Host "Got new Access Token!" 
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
			write-output "Authentication Token expired" $TokenExpires "minutes ago"
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

#Get Token
Validate-AuthToken
Write-output "Got new access token!"

Write-output ""
Write-output "AU             = $AU" 
Write-output "IntuneGroup    = $IntuneGroup"
Write-output "IntuneGroup_HD = $IntuneGroup_Helpdesk"
Write-output "IntuneGroup_UD = $IntuneGroup_UserAdmin"
Write-output ""

Write-output "Region Adding AAD Roles"
sleep 5

#region Add Intune - SchoolID group to AU
Write-output "Add Intune - SchoolID group to $($AU)"
$AUURI = "https://graph.microsoft.com/v1.0/directory/administrativeUnits?`$filter=displayName eq $($AU)"
$GroupURI = "https://graph.microsoft.com/v1.0/groups?`$filter=displayName eq $($IntuneGroup)"
$AUID = Invoke-RestMethod -Uri $AUURI -Headers $global:authToken -Method get | select -ExpandProperty value | select -ExpandProperty id
$GroupID = Invoke-RestMethod -Uri $GroupURI -Headers $global:authToken -Method get | select -ExpandProperty value | select -ExpandProperty id
$CheckMember = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$AUID/members"

# Check member
$MemberPresent = Invoke-RestMethod -Uri $URI2 -Headers $global:authToken -Method Get | select -ExpandProperty value | select -ExpandProperty id
if($MemberPresent -contains $GroupID)
    {
        Write-Output "Group $($IntuneGroup) already added!"
    }
else
    {
        $URI = "https://graph.microsoft.com/v1.0/directory/administrativeUnits/$AUID/members/`$ref"
$jsonParams = @"
{
    "@odata.id":"https://graph.microsoft.com/v1.0/groups/$GroupID"
}
"@ 
        
Invoke-RestMethod -Uri $URI -Headers $global:authToken -Method Post -Body $jsonParams -ErrorAction Stop -ErrorVariable err0

write-output "Added Intune group to Azure Administrative unit: $Au"
Write-output ""
sleep 2

if($err0.count -ne 0)
	{
		Write-Output "A conflicting object with one or more of the specified property values is present in the directory."
		Write-output ""
		#Write-output $_.exception.message
	}
}


#region Assigning roles

#region Assign Helpdesk Administrator at Directory Level using Add-AzureADDirectoryRoleMember cmdlet"

Write-Output "Region Assign Helpdesk Administrator at Directory Level using Graph"
$adminUser_HD = Get-AzureADGroup -Filter "DisplayName eq '$IntuneGroup_Helpdesk'"
$role_HD = Get-AzureADDirectoryRole | Where-Object -Property DisplayName -EQ -Value "Helpdesk Administrator"
$roleMember_HD = New-Object -TypeName Microsoft.Open.MSGraph.Model.MsRoleMemberInfo
$roleMember_HD.Id = $adminUser_HD.ObjectId
$uri_HD = "https://graph.microsoft.com/v1.0/directoryRoles/roleTemplateId=$($role_HD.ObjectId)/members/`$ref"

# JSON request
$jsonParams = @"
{
    "@odata.id": "https://graph.microsoft.com/v1.0/directoryObjects/$($roleMember_HD.Id)"
}
"@  

try
    {
        Validate-AuthToken
        Invoke-RestMethod -Uri $uri_HD -Headers $global:authToken -Method Post -Body $jsonParams -ErrorAction Stop -ErrorVariable err1
        Write-Output "Granted '$IntuneGroup_Helpdesk' Helpdesk Administrator Role" 
        Write-Output ""
        Sleep 2
    }
catch
    {
        if($err1.count -ne 0)
            {
                Write-Output "One or more added object references already exist for the following modified properties: 'members'."
                Write-Output ""
                #Write-output $_.exception.message
            }
    }
#endregion

#region Assign User Administrator at Application Level using Add-AzureADMSScopedRoleMembership cmdlet"
Write-Output "Region Assign User Administrator at Application Level using Graph"
$adminUser_UD = Get-AzureADGroup -Filter "DisplayName eq '$IntuneGroup_UserAdmin'"
$role_UD = Get-AzureADDirectoryRole | Where-Object -Property DisplayName -EQ -Value "User Administrator"
$adminUnitObj_UD = Get-AzureADMSAdministrativeUnit -Filter "displayname eq '$AU'"
$roleMember_UD = New-Object -TypeName Microsoft.Open.MSGraph.Model.MsRoleMemberInfo
$roleMember_UD.Id = $adminUser_UD.ObjectId
$uri_UD = "https://graph.microsoft.com/v1.0/roleManagement/directory/roleAssignments"

# JSON request
$jsonParams1 = @"
{
    "@odata.type": "#microsoft.graph.unifiedRoleAssignment",
    "principalId": "$($adminUser_UD.ObjectId)",
    "roleDefinitionId": "$($role_UD.ObjectId)",
    "directoryScopeId": "/administrativeUnits/$($adminUnitObj_UD.Id)"
}
"@  

try
    {
        Validate-AuthToken
        Invoke-RestMethod -Uri $uri_UD -Headers $global:authToken -Method Post -Body $jsonParams1 -ErrorAction Stop -ErrorVariable err2 | Out-Null
        Write-Output "Granted '$IntuneGroup_UserAdmin' User Administrator Role"
        Write-Output ""
        Sleep 2
    }
catch
    {
        if($err2.count -ne 0)
            {
                Write-Output "One or more added object references already exist for the following modified properties: 'members'."
                Write-Output ""
                #Write-output $_.exception.message
            }
    }

#endregion


# Assign Scopes
$adminUser_UD = Get-AzureADGroup -Filter "DisplayName eq '$IntuneGroup_UserAdmin'"

#region Adding group Intune - $SchoolID to Scopetag - 2 roles
#Write-host "Region Adding group Intune - $SchoolID to Scopetag - 2 roles" -ForegroundColor Yellow
write-output "Region Adding group Intune - $SchoolID to Scopetag - 2 roles"
$RoleDefinitions = "Custom_ITAdmin_All-Read","Custom_ITAdmin"

foreach ($RoleDefinition in $RoleDefinitions) {

    #Write-host "Processing $($RoleDefinition)" -ForegroundColor Yellow
    write-output "Processing $($RoleDefinition)"

    # Get custom intune role
    Validate-AuthToken
    $Url1 = "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions/?`$select=displayName,id"
    $a = Invoke-RestMethod -Uri $Url1 -Headers $global:authToken -Method Get
    $IntuneCustomRole = $a.value | where{$_.displayName -eq "$RoleDefinition"} | select id, displayName

    # Get scope tags
    Validate-AuthToken
    $url2 = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/?`$select=displayName,id"
    $b = Invoke-RestMethod -Uri $Url2 -Headers $global:authToken -Method Get
    $Scopetags = $b.value 

    $(if($RoleDefinition -match "Read")
        {
        #user All-Read for the ScopeTag
$jsonParams = @"
{
     "roleDefinition@odata.bind": "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions('$($IntuneCustomRole.id)')",
     "roleScopeTags@odata.bind": ["https://graph.microsoft.com/beta/deviceManagement/roleScopeTags('$($Scopetags | where{$_.displayName -eq 'All-Read'}| select id -ExpandProperty id)')"],
     "description": "",
     "displayName": "$($AU)",
     "resourceScopes": [
    "$($ScopeGroup.ObjectId)" 
  ],
     "scopeMembers": [
    "$($ScopeGroup.ObjectId)" 
  ],
     "members": [
     "$($adminUser_UD.ObjectId)"
     ],
     "scopeType": "resourceScope"
   }
"@

           
        } else {
        #user schoolid/AU for the ScopeTag
 
$jsonParams = @"
{
     "roleDefinition@odata.bind": "https://graph.microsoft.com/beta/deviceManagement/roleDefinitions('$($IntuneCustomRole.id)')",
     "roleScopeTags@odata.bind": ["https://graph.microsoft.com/beta/deviceManagement/roleScopeTags('$($Scopetags | where{$_.displayName -eq "$($AU)"}| select id -ExpandProperty id)')"],
     "description": "",
     "displayName": "$($AU)",
     "resourceScopes": [
    "$($ScopeGroup.ObjectId)" 
  ],
     "scopeMembers": [
    "$($ScopeGroup.ObjectId)" 
  ],
     "members": [
     "$($adminUser_UD.ObjectId)"
     ],
     "scopeType": "resourceScope"
   }
"@       
        
        })

    # Assign Intune Custom Role
    try
        {
            $uri = "https://graph.microsoft.com/beta/deviceManagement/roleAssignments"
            $Result = Invoke-RestMethod -Uri $uri -Headers $global:authToken -Method Post -Body $jsonParams -ErrorAction Stop -ErrorVariable err3
            #Write-host "Assigned Custom Intune Role Definition: '$RoleDefinition' to '$IntuneGroup_UserAdmin' group " -ForegroundColor Cyan
            write-output "Assigned Custom Intune Role Definition: '$RoleDefinition' to '$IntuneGroup_UserAdmin' group "
            #Write-host ""
            write-output ""
            Sleep 2
        }
    catch
        {
            if($err3.count -ne 0)
                {
                    #Write-Output "One or more added object references already exist for the following modified properties: 'members'."
                    #Write-host ""
                    write-output ""
                    Write-output $_.exception.message
                }
        }
}
#endregion
#endregion

