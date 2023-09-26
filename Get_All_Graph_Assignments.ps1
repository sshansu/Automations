<#
This sample script is not supported under any Microsoft standard support program or service.
The sample script is provided AS IS without warranty of any kind.
Microsoft further disclaims all implied warranties including, without limitation, any implied warranties of merchantability or of fitness for a particular purpose.
The entire risk arising out of the use or performance of the sample scripts and documentation remains with you.
In no event shall Microsoft, its authors, or anyone else involved in the creation, production, or delivery of the scripts be liable for any damages whatsoever (including, #without limitation, damages for loss of business profits, business interruption, loss of business information, or other pecuniary loss) arising out of the use of or inability to use the sample scripts or documentation, even if Microsoft has been advised of the possibility of such damages
#>

$ExecutionTime = Get-Date
$StartTime = Get-Date $ExecutionTime -Format dd-MM-yyyy-HH-mm-ss

#Initialize Variables
#$global:authToken = $null
$global:TenantID = "d948da51-c23f-4c15-89e5-b2dde3add88d"
$global:ClientID = "5b392c21-9fff-4f7d-8bec-c160dbe8402f"
$global:ClientSecret = "dr-8Q~MKUZBYK4dm_c5BLNxMaAapQjqVfD-ZsaBi"
$LogFile = "C:\Windows\Temp\graph.log"

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

# $global:authToken

$GrpID = "2c5f17f5-7857-4c94-8845-fc4d4d7ed188" #Read-host "Enter Group ID"
$Exportpath = "C:\Temp\Assignments7.csv"

# Function to read Device Configuration Assignments
Function Get-DeviceConfigurationAssignments() {
    Param
        (
            $GroupID
        )

        $DCURL = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$select=displayName,id"
        $Policies = @()
        #$count=0
        do {
            Validate-AuthToken
            #$count++
            #write-host "Page:$count + $DCURL"
            #write-host ""
	        $QueryResult = Invoke-RestMethod -Uri $DCURL -Headers $global:authToken -Method Get
	        $Policies += $QueryResult.value
	        $DCURL = $QueryResult.'@odata.nextLink'
        } while ($DCURL -ne $null)
        
        $count = 0
        $dump = @()
        Foreach($policyid in $Policies.id)
            {
                $DCURL = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$policyid/assignments"
                $PoliciesAssignment = @()
                do {
                    Validate-AuthToken
                    #$page++
                    #write-host "Page:$page + $DCURL"
                    #write-host ""
	                $QueryResult = Invoke-RestMethod -Uri $DCURL -Headers $global:authToken -Method Get
	                $PoliciesAssignment += $QueryResult.value.target.groupId
	                $DCURL = $QueryResult.'@odata.nextLink'
                } while ($DCURL -ne $null)
                if($PoliciesAssignment -eq $GrpID)
                    {
                        $count++
                        $dump += $Policies | Where-Object{$_.id -eq $policyid} | select @{n="Type";e={'DeviceConfiguration'}},Id,displayName
                    }
            }
    $count
    $dump | Export-Csv -Path $Exportpath -Append -NoTypeInformation
}
$DeviceConfigCount = Get-DeviceConfigurationAssignments -GroupID $GrpID
write-host "Device Configuration Assignments: $DeviceConfigCount" -ForegroundColor Cyan

# Function to read Compliance Policy Assignments
Function Get-CompliancePolicyAssignments() {
    Param
        (
            $GroupID
        )

        $ComplianceURL = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies?`$select=displayName,id"
        $Policies = @()
        do {
            Validate-AuthToken
            $QueryResult = Invoke-RestMethod -Uri $ComplianceURL -Headers $global:authToken -Method Get
	        $Policies += $QueryResult.value
	        $ComplianceURL = $QueryResult.'@odata.nextLink'
        } while ($ComplianceURL -ne $null)
        
        $count = 0
        $dump = @()
        Foreach($policyid in $Policies.id)
            {
                $ComplianceURL = "https://graph.microsoft.com/beta/deviceManagement/deviceCompliancePolicies/$($policyid)?`$expand=assignments"
                $PoliciesAssignment = @()
                do {
                    Validate-AuthToken
                    $QueryResult = Invoke-RestMethod -Uri $ComplianceURL -Headers $global:authToken -Method Get
	                $PoliciesAssignment += $QueryResult.assignments.target.groupId
	                $ComplianceURL = $QueryResult.'@odata.nextLink'
                } while ($ComplianceURL -ne $null)
                if($PoliciesAssignment -eq $GrpID)
                    {
                        $count++
                        $dump += $Policies | Where-Object{$_.id -eq $policyid} | select @{n="Type";e={'CompliancePolicy'}},Id,displayName
                    }
            }
        $count
        $dump | Export-Csv -Path $Exportpath -Append -NoTypeInformation 
    }
$CompliancePolicyCount = Get-CompliancePolicyAssignments -GroupID $GrpID
write-host "Device Compliance Assignments: $CompliancePolicyCount" -ForegroundColor Cyan

# Function to read Application Assignments
Function Get-ApplicationAssignments() {
    Param
        (
            $GroupID
        )

        $AppURI = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps?`$filter=isAssigned eq true&`$select=id,displayName,isAssigned"
        $apps = @()
        do {
            Validate-AuthToken
            $QueryResult = Invoke-RestMethod -Uri $AppURI -Headers $global:authToken -Method Get
	        $apps += $QueryResult.Value
	        $AppURI = $QueryResult.'@odata.nextLink'
        } while ($AppURI-ne $null)
        
        $count=0
        $dump = @()
        Foreach($appid in $apps.id)
            {
                #$select=displayName,isAssigned&`
                $AppAsstURI = "https://graph.microsoft.com/beta/deviceAppManagement/mobileApps/$($appid)/?`$expand=assignments"
                $assignments = @()
                do {
                    Validate-AuthToken
                    $QueryResult = Invoke-RestMethod -Uri $AppAsstURI -Headers $global:authToken -Method Get
	                $assignments += $QueryResult.assignments.target.groupId
	                $AppAsstURI = $QueryResult.'@odata.nextLink'
                } while ($AppAsstURI -ne $null)
                if($assignments -eq $GrpID)
                    {
                        $count++
                        $dump += $apps | Where-Object{$_.id -eq $appid} | select @{n="Type";e={'Application'}},Id,displayName
                    }
            }
        $count
        $dump | Export-Csv -Path $Exportpath -Append -NoTypeInformation 
}
$AppCount = Get-ApplicationAssignments -GroupID $GrpID
write-host "Application Assignments: $AppCount" -ForegroundColor Cyan

# Function to read App Protection Assignments - iOS
Function Get-ApplicationAssignments_iOS() {
    Param
        (
            $GroupID
        )

        $AppProtURL = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies?`$select=displayName,id"
        $Policies = @()
        do {
            Validate-AuthToken
            $QueryResult = Invoke-RestMethod -Uri $AppProtURL -Headers $global:authToken -Method Get
	        $Policies += $QueryResult.value
	        $AppProtURL = $QueryResult.'@odata.nextLink'
        } while ($AppProtURL -ne $null)
        
        $iosPolicies = $Policies | where{($_.'@odata.type' -match 'iosManaged')}
        $count = 0
        $dump = @()
        Foreach($policyid in $iosPolicies.id)
            {
                
                $MAM_AssignmentURL = "https://graph.microsoft.com/beta/deviceAppManagement/iosManagedAppProtections('$($policyid)')?`$expand=apps,assignments"
                $MAMAssignment = @()
                do {
                    Validate-AuthToken
                    $QueryResult = Invoke-RestMethod -Uri $MAM_AssignmentURL -Headers $global:authToken -Method Get
	                $MAMAssignment += $QueryResult.assignments.target.groupid
	                $MAM_AssignmentURL = $QueryResult.'@odata.nextLink'
                } while ($MAM_AssignmentURL -ne $null)
                if($MAMAssignment -eq $GrpID)
                    {
                        $count++
                        $dump += $iosPolicies | Where-Object{$_.id -eq $policyid} | select @{n="Type";e={'AppProtection_iOS'}},Id,displayName
                    }
            }
        $count
        $dump | Export-Csv -Path $Exportpath -Append -NoTypeInformation
}
$AppProtectioniOSCount = Get-ApplicationAssignments_iOS -GroupID $GrpID
write-host "App Protection Policy for iOS Assignments: $AppProtectioniOSCount" -ForegroundColor Cyan

# Function to read App Protection Assignments - Android
Function Get-ApplicationAssignments_Android() {
    Param
        (
            $GroupID
        )

        $AppProtURL = "https://graph.microsoft.com/beta/deviceAppManagement/managedAppPolicies?`$select=displayName,id"
        $Policies = @()
        do {
            Validate-AuthToken
            $QueryResult = Invoke-RestMethod -Uri $AppProtURL -Headers $global:authToken -Method Get
	        $Policies += $QueryResult.value
	        $AppProtURL = $QueryResult.'@odata.nextLink'
        } while ($AppProtURL -ne $null)
        
        $AndroidPolicies = $Policies | where{($_.'@odata.type' -match 'androidManaged')}
        $count = 0
        $dump = @()
        Foreach($policyid in $AndroidPolicies.id)
            {
                
                $MAM_AssignmentURL = "https://graph.microsoft.com/beta/deviceAppManagement/androidManagedAppProtections('$($policyid)')?`$expand=apps,assignments"
                $MAMAssignment = @()
                do {
                    Validate-AuthToken
                    $QueryResult = Invoke-RestMethod -Uri $MAM_AssignmentURL -Headers $global:authToken -Method Get
	                $MAMAssignment += $QueryResult.assignments.target.groupid
	                $MAM_AssignmentURL = $QueryResult.'@odata.nextLink'
                } while ($MAM_AssignmentURL -ne $null)
                if($MAMAssignment -eq $GrpID)
                    {
                        $count++
                        $dump += $AndroidPolicies | Where-Object{$_.id -eq $policyid} | select @{n="Type";e={'AppProtection_Android'}},Id,displayName
                    }
            }
        $count
        $dump | Export-Csv -Path $Exportpath -Append -NoTypeInformation
}
$AppProtectionAndroidCount = Get-ApplicationAssignments_Android -GroupID $GrpID
write-host "App Protection Policy for Android Assignments: $AppProtectionAndroidCount" -ForegroundColor Cyan

# Function to read Scripts Assignments
Function Get-ScriptAssignments() {
    Param
        (
            $GroupID
        )
    
    $scriptURI = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts?`$select=displayName,id"
    $Scripts = @()
    $count=0
    do {
        Validate-AuthToken
        $QueryResult = Invoke-RestMethod -Uri $scriptURI -Headers $global:authToken -Method Get
	    $Scripts += $QueryResult.value
	    $scriptURI = $QueryResult.'@odata.nextLink'
    } while ($scriptURI -ne $null)
    
    $count=0
    $dump = @()
    Foreach($Scriptid in $Scripts.id)
            {
                $scriptURI = "https://graph.microsoft.com/beta/deviceManagement/deviceManagementScripts/$($scriptid)?`$expand=assignments"
                $ScriptAssignment = @()
                do {
                    Validate-AuthToken
                    $QueryResult = Invoke-RestMethod -Uri $scriptURI -Headers $global:authToken -Method Get
	                $ScriptAssignment += $QueryResult.assignments.target.groupId
	                $scriptURI = $QueryResult.'@odata.nextLink'
                } while ($scriptURI -ne $null)
                if($ScriptAssignment -eq $GrpID)
                    {
                        $count++
                        $dump += $Scripts | Where-Object{$_.id -eq $Scriptid} | select @{n="Type";e={'Scripts'}},Id,displayName
                    }
            }
        $count
        $dump | Export-Csv -Path $Exportpath -Append -NoTypeInformation
}
$ScriptCount = Get-ScriptAssignments -GroupID $GrpID
write-host "Script Assignments: $ScriptCount" -ForegroundColor Cyan

# Function to read Proactive Remediation Assignments
Function Get-ProactiveRemediationAssignments() {
    Param
        (
            $GroupID
        )
        
        $eauri = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts?`$select=displayName,id"
        $PRScripts = @()
        do {
            Validate-AuthToken
            $QueryResult = Invoke-RestMethod -Uri $eauri -Headers $global:authToken -Method Get
	        $PRScripts += $QueryResult.value
	        $eauri = $QueryResult.'@odata.nextLink'
        } while ($eauri -ne $null)
        
        $count=0
        $dump = @()
        Foreach($PRScriptID in $PRScripts.id)
            {
                $scriptURI = "https://graph.microsoft.com/beta/deviceManagement/deviceHealthScripts/$($PRScriptID)?`$expand=assignments"
                $PRScriptAssignment = @()
                $count=0
                do {
                    Validate-AuthToken
                    $QueryResult = Invoke-RestMethod -Uri $scriptURI -Headers $global:authToken -Method Get
	                $PRScriptAssignment += $QueryResult.assignments.target.groupId
	                $scriptURI = $QueryResult.'@odata.nextLink'
                } while ($scriptURI -ne $null)
                if($PRScriptAssignment -eq $GrpID)
                    {
                        $count++
                        $dump += $PRScripts | Where-Object{$_.id -eq $PRScriptID} | select @{n="Type";e={'ProactiveRemediation'}},Id,displayName
                    }
            }
        $count
        $dump | Export-Csv -Path $Exportpath -Append -NoTypeInformation 
}
$ProactiveRemediationCount = Get-ProactiveRemediationAssignments -GroupID $GrpID   
write-host "Proactive Remediation Assignments: $ProactiveRemediationCount" -ForegroundColor Cyan
        
# Function to read Scope Tag Assignments
Function Get-ScopeTagsAssignments() {
    Param
        (
            $GroupID
        )
        
        $STURI = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags?`$select=displayName,id"
        $tags = @()
        do {
            Validate-AuthToken
            $QueryResult = Invoke-RestMethod -Uri $STURI -Headers $global:authToken -Method Get
	        $tags += $QueryResult.value
	        $STURI = $QueryResult.'@odata.nextLink'
        } while ($STURI -ne $null)
        
        $count=0
        $dump = @()
        Foreach($tagId in $tags.id)
            { 
                $STURI = "https://graph.microsoft.com/beta/deviceManagement/roleScopeTags/$($tagId)/assignments"
                $TagAssignment = @()
                do {
                    Validate-AuthToken
                    $QueryResult = Invoke-RestMethod -Uri $STURI -Headers $global:authToken -Method Get
	                $TagAssignment += $QueryResult.value.target.groupId
	                $STURI = $QueryResult.'@odata.nextLink'
                } while ($STURI -ne $null)
                if($TagAssignment -eq $GrpID)
                    {
                        $count++
                        $dump += $tags | Where-Object{$_.id -eq $tagId} | select @{n="Type";e={'ScopeTags'}},Id,displayName
                    }
            }
        $count
        $dump | Export-Csv -Path $Exportpath -Append -NoTypeInformation 
}
$ScopeTagCount = Get-ScopeTagsAssignments -GroupID $GrpID
write-host "Scope tags Assignments: $ScopeTagCount" -ForegroundColor Cyan

# Function to read Update Policy Assignments
Function Get-UpdateRingAssignments() {
    Param
        (
            $GroupID
        )

        $RingURI = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations?`$filter=isof('microsoft.graph.windowsUpdateForBusinessConfiguration')&`$select=displayName,id"
        $URPolicies = @()
        do {
            Validate-AuthToken
            $QueryResult = Invoke-RestMethod -Uri $RingURI -Headers $global:authToken -Method Get
	        $URPolicies += $QueryResult.value
	        $RingURI = $QueryResult.'@odata.nextLink'
        } while ($RingURI -ne $null)
        
        $count=0
        $dump = @()
        Foreach($URPolicyID in $URPolicies.id)
            {
                $RingURI = "https://graph.microsoft.com/beta/deviceManagement/deviceConfigurations/$($URPolicyID)?`$expand=assignments"
                $URAssignment = @()
                do {
                    Validate-AuthToken
                    $QueryResult = Invoke-RestMethod -Uri $RingURI -Headers $global:authToken -Method Get
	                $URAssignment += $QueryResult1.assignments.target.groupid
	                $RingURI = $QueryResult.'@odata.nextLink'
                } while ($RingURI -ne $null)
                if($URAssignment -eq $GrpID)
                    {
                        $count++
                        $dump += $URPolicies | Where-Object{$_.id -eq $URPolicyID} | select @{n="Type";e={'UpdateRingPolicy'}},Id,displayName
                    }
            }
        $count
        $dump | Export-Csv -Path $Exportpath -Append -NoTypeInformation
}
$UpdateRingCount = Get-UpdateRingAssignments -GroupID $GrpID
write-host "Update Ring Policy Assignments: $UpdateRingCount" -ForegroundColor Cyan

# Function to read Update Policy Assignments
Function Get-FeatureUpdateAssignments() {
    Param
        (
            $GroupID
        )

        $RingURI = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles?`$select=displayName,id"
        $FUPolicies = @()
        do {
            Validate-AuthToken
            $QueryResult = Invoke-RestMethod -Uri $RingURI -Headers $global:authToken -Method Get
	        $FUPolicies += $QueryResult.value
	        $RingURI = $QueryResult.'@odata.nextLink'
        } while ($RingURI -ne $null)
       
        $count=0
        $dump = @()
        Foreach($FUPolicyID in $FUPolicies.id)
            {
                $RingURI = "https://graph.microsoft.com/beta/deviceManagement/windowsFeatureUpdateProfiles/$($FUPolicyID)?`$expand=assignments"
                $FUAssignment = @()
                do {
                    Validate-AuthToken
                    $QueryResult = Invoke-RestMethod -Uri $RingURI -Headers $global:authToken -Method Get
	                $FUAssignment += $QueryResult.assignments.target.groupid
	                $RingURI = $QueryResult.'@odata.nextLink'
                } while ($RingURI -ne $null)
                if($FUAssignment -eq $GrpID)
                    {
                        $count++
                        $dump += $FUPolicies | Where-Object{$_.id -eq $FUPolicyID} | select @{n="Type";e={'FeatureUpdatePolicy'}},Id,displayName
                    }
            }
        $count
        $dump | Export-Csv -Path $Exportpath -Append -NoTypeInformation
}
$FeatureUpdateCount = Get-FeatureUpdateAssignments -GroupID $GrpID
write-host "Feature Update Policy Assignments: $FeatureUpdateCount" -ForegroundColor Cyan


