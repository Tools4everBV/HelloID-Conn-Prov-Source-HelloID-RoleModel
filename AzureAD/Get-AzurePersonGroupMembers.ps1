<#
.SYNOPSIS

.DESCRIPTION

.NOTES
    Author: Ramon Schouten
    Editor: Jeroen Smit
    Created At: 2023-04-17
    Last Edit: 2024-03-25
    Version 1.0 (RS) - initial release (inclduing status active for the employee and support for no startdate per employee)
    Version 1.1 (JS) - added reporting for persons with no correlation attribute, persons with no account or accounts with no permissions
    Version 1.2 (RH) - added nesting support
    Version 1.2.1 (JS) - fix column 'Status' is removed from export 'entilements.csv'
    Version 1.2.2 (JS) - fix: calculate dummy permission even if person has no other permissions
#>
# Specify whether to output the logging
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Azure AD Graph API, specify the tenant id, app id & secret
$AADtenantID = "<AZURE_TENANT_ID>"
$AADAppId = "<AZURE_APP_ID>"
$AADAppSecret = "<AZURE_APP_SECRET>"

# Toggle to include nested groupmemberships (up to a maximum of 1 layer deep)
$includeNestedGroupMemberships = $true # or $false

# Toggle to add dummy group to result for each person
$addDummyGroup = $true # or $false

# Replace path with your path for vault.json, Evaluation.csv and entitlements.csv.
# Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments
$exportPath = "C:\HelloID\RoleminingEntraID\"

# Optionally, specifiy the parameters below when you want to check the groups against an evaluation report
# The location of the Evaluation Report Csv (needs to be manually exported from a HelloID Provisioning evaluation).
$evaluationReportCsv = $exportPath + "EvaluationReport.csv"
# The name of the system on which to check the permissions in the evaluation (Required when using the evaluation report)
$evaluationSystemName = "Microsoft Azure AD"
# The name of the permission type on which to check the permissions in the evaluation (Required when using the entitlements report) (Default for Azure AD is: Group Membership)
$evaluationPermissionTypeName = "Group Membership"

# Optionally, specifiy the parameters below when you want to check the groups against a granted entitlements report
# The location of the Granted Entitlements Csv (needs to be manually exported from a HelloID Provisioning Granted Entitlements).
$grantedEntitlementsCsv = $exportPath + "Entitlements.csv"
# The name of the system on which to check the permissions in the granted entitlements (Required when using the entitlements report)
$entitlementsSystemName = "Microsoft Entra ID"
# The name(s) of the permission type on which to check the permissions in the granted entitlements (Required when using the entitlements report) (Default for Azure AD is: Group Membership)
$entitlementsPermissionTypeNames = @("Permission - Security Group", "Permission - M365 Group")

# The attribute used to correlate a person to an account
$personCorrelationAttribute = "externalId" # or e.g. "externalId"
$userCorrelationAttribute = "employeeId" # or e.g. "userAttributes.EmployeeID"

# The location of the Vault export in JSON format (needs to be manually exported from a HelloID Provisioning snapshot).
$vaultJson = $exportPath + "vault.json"
# Specify the Person fields from the HelloID Vault export to include in the report (These have to match the exact name from he Vault.json export) - Must always contains personCorrelationAttribute!
$personPropertiesToInclude = @($personCorrelationAttribute, "source.displayname")
# Specify the Contracts fields from the HelloID Vault export to include in the report (These have to match the exact name from he Vault.json export)
$contractPropertiesToInclude = @("costCenter.externalId", "Costcenter.name")

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#region functions
function Write-Information {
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$Message
    )
    
    if ($portalBaseUrl -eq $null) {
        # Use the standard Write-Information
        Write-Host $Message
       
    }
    else {
        # Use HelloID logging
        Hid-Write-Status -Message $Message -Event "Information"
    }
}

function New-AuthorizationHeaders {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [parameter(Mandatory)]
        [string]
        $TenantId,

        [parameter(Mandatory)]
        [string]
        $ClientId,

        [parameter(Mandatory)]
        [string]
        $ClientSecret
    )
    try {
        Write-Verbose "Creating Access Token"
        $baseUri = "https://login.microsoftonline.com/"
        $authUri = $baseUri + "$TenantId/oauth2/token"
    
        $body = @{
            grant_type    = "client_credentials"
            client_id     = "$ClientId"
            client_secret = "$ClientSecret"
            resource      = "https://graph.microsoft.com"
        }
    
        $Response = Invoke-RestMethod -Method POST -Uri $authUri -Body $body -ContentType 'application/x-www-form-urlencoded'
        $accessToken = $Response.access_token
    
        #Add the authorization header to the request
        Write-Verbose 'Adding Authorization headers'

        $headers = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $headers.Add('Authorization', "Bearer $accesstoken")
        $headers.Add('Accept', 'application/json')
        $headers.Add('Content-Type', 'application/json')
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        $headers.Add('ConsistencyLevel', 'eventual')

        Write-Output $headers  
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Resolve-HTTPError {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $httpErrorObj = [PSCustomObject]@{
            FullyQualifiedErrorId = $ErrorObject.FullyQualifiedErrorId
            MyCommand             = $ErrorObject.InvocationInfo.MyCommand
            RequestUri            = $ErrorObject.TargetObject.RequestUri
            ScriptStackTrace      = $ErrorObject.ScriptStackTrace
            ErrorMessage          = ''
        }
        if ($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') {
            $httpErrorObj.ErrorMessage = $ErrorObject.ErrorDetails.Message
        }
        elseif ($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException') {
            $httpErrorObj.ErrorMessage = [System.IO.StreamReader]::new($ErrorObject.Exception.Response.GetResponseStream()).ReadToEnd()
        }
        Write-Output $httpErrorObj
    }
}

function Resolve-MicrosoftGraphAPIErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        try {
            $errorObjectConverted = $ErrorObject | ConvertFrom-Json -ErrorAction Stop

            if ($null -ne $errorObjectConverted.error_description) {
                $errorMessage = $errorObjectConverted.error_description
            }
            elseif ($null -ne $errorObjectConverted.error) {
                if ($null -ne $errorObjectConverted.error.message) {
                    $errorMessage = $errorObjectConverted.error.message
                    if ($null -ne $errorObjectConverted.error.code) { 
                        $errorMessage = $errorMessage + " Error code: $($errorObjectConverted.error.code)"
                    }
                }
                else {
                    $errorMessage = $errorObjectConverted.error
                }
            }
            else {
                $errorMessage = $ErrorObject
            }
        }
        catch {
            $errorMessage = $ErrorObject
        }

        Write-Output $errorMessage
    }
}

function Get-ErrorMessage {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory,
            ValueFromPipeline
        )]
        [object]$ErrorObject
    )
    process {
        $errorMessage = [PSCustomObject]@{
            VerboseErrorMessage = $null
            AuditErrorMessage   = $null
        }

        if ( $($ErrorObject.Exception.GetType().FullName -eq 'Microsoft.PowerShell.Commands.HttpResponseException') -or $($ErrorObject.Exception.GetType().FullName -eq 'System.Net.WebException')) {
            $httpErrorObject = Resolve-HTTPError -Error $ErrorObject

            $errorMessage.VerboseErrorMessage = $httpErrorObject.ErrorMessage

            $errorMessage.AuditErrorMessage = Resolve-MicrosoftGraphAPIErrorMessage -ErrorObject $httpErrorObject.ErrorMessage
        }

        # If error message empty, fall back on $ex.Exception.Message
        if ([String]::IsNullOrEmpty($errorMessage.VerboseErrorMessage)) {
            $errorMessage.VerboseErrorMessage = $ErrorObject.Exception.Message
        }
        if ([String]::IsNullOrEmpty($errorMessage.AuditErrorMessage)) {
            $errorMessage.AuditErrorMessage = $ErrorObject.Exception.Message
        }

        Write-Output $errorMessage
    }
}
#endregion functions

function Invoke-TransformMembershipsToMemberOf {
    param(
        [parameter(Mandatory = $true)]$GroupsWithMembers,
        [parameter(Mandatory = $true)][ref]$usersWithMemberOf
    )

    try {
        Write-Information "Transforming group memberships to users with memberOf..." -InformationAction Continue

        foreach ($record in $GroupsWithMembers) {   
            if ($record.users.'@odata.type' -eq '#microsoft.graph.user') {
                foreach ($user in $record.users) {
                    $userWithMemberOf = [PSCustomObject]@{
                        userGuid    = $user.id
                        memberOf    = $record.Id
                        isNested    = $false
                        parentGroup = $null
                    }
                    [void]$usersWithMemberOf.Value.Add($userWithMemberOf)
                }
            }
        }

        if ($includeNestedGroupMemberships -eq $true) {
            $usersWithMemberOfGrouped = $usersWithMemberOf.Value | Group-Object -Property memberOf -AsString -AsHashTable
            foreach ($record in $GroupsWithMembers) {
                if ($record.groups.'@odata.type' -eq '#microsoft.graph.group') {
                    foreach ($groupGuid in $record.groups) {
                        foreach ($userGuid in $usersWithMemberOfGrouped[$groupGuid.id].userGuid) {
                            $userWithMemberOf = [PSCustomObject]@{
                                userGuid    = $userGuid
                                memberOf    = $record.Id
                                isNested    = $true
                                parentGroup = $groupsWithMembersHashTable[$groupGuid.id].Name
                            }
                            [void]$usersWithMemberOf.Value.Add($userWithMemberOf)
                        }
                    }
                }                
            }
        }
    }
    catch {
        $usersWithMemberOf.Value = $null
        Write-Error $_.Exception
    }
}

function Expand-Persons {
    param(
        [parameter(Mandatory = $true)]$Persons,
        [parameter(Mandatory = $true)][ref]$ExpandedPersons
    )

    try {
        Write-Information "Expanding persons with contracts..." -InformationAction Continue

        foreach ($person in $persons) {
            if ($null -eq $person.PrimaryContract.EndDate) {
                $endDate = Get-Date -Date "2199-01-01 00:00:00"
                $endDate = $endDate.AddDays(1).AddSeconds(-1)
            }
            else {
                $endDate = [DateTime]$person.PrimaryContract.EndDate
            }

            if ($null -eq $person.PrimaryContract.startDate) {
                Write-Warning "$($person.displayName) has no start date on primary contract with externalId [$($person.PrimaryContract.ExternalId)]"
                continue
            }
            else {
                $startDate = [DateTime]$person.PrimaryContract.startDate
            }

            $record = [PSCustomObject]@{
                source                = $person.Source.DisplayName
                externalId            = $person.ExternalId
                displayName           = $person.DisplayName
                contractExternalId    = $person.PrimaryContract.ExternalId
                departmentId          = $person.PrimaryContract.Department.ExternalId
                departmentCode        = $person.PrimaryContract.Department.Code
                departmentDescription = $person.PrimaryContract.Department.DisplayName
                titleId               = $person.PrimaryContract.Title.ExternalId
                titleCode             = $person.PrimaryContract.Title.Code
                titleDescription      = $person.PrimaryContract.Title.Name
                contractIsPrimary     = $true
                startDate             = $startDate
                endDate               = $endDate
            }

            if ($personPropertiesToInclude) {
                foreach ($personPropertyToInclude in $personPropertiesToInclude) {
                    $personProperty = '$person' + ".$personPropertyToInclude"
                    $personPropertyValue = ($personProperty | Invoke-Expression) 
                    $record | Add-Member -MemberType NoteProperty -Name $personPropertyToInclude.replace(".", "") -Value $personPropertyValue -Force
                }
            }
            if ($contractPropertiesToInclude) {
                foreach ($contractPropertyToInclude in $contractPropertiesToInclude) {
                    $contractProperty = '$person.PrimaryContract' + ".$contractPropertyToInclude"
                    $contractPropertyValue = ($contractProperty | Invoke-Expression) 
                    $record | Add-Member -MemberType NoteProperty -Name $contractPropertyToInclude.replace(".", "") -Value $contractPropertyValue -Force
                }
            }

            [void]$ExpandedPersons.Value.Add($record)

            foreach ($contract in $person.Contracts) {
                if ($contract.ExternalId -eq $person.PrimaryContract.ExternalId) { continue; }

                if ($null -eq $contract.EndDate) {
                    $endDate = Get-Date -Date "2199-01-01 00:00:00"
                    $endDate = $endDate.AddDays(1).AddSeconds(-1)
                }
                else {
                    $endDate = [DateTime]$contract.EndDate
                }

                if ($null -eq $contract.StartDate) {
                    Write-Warning "$($person.displayName) has no start date on non-primary contract with externalId [$($contract.ExternalId)]"
                    continue
                }
                else {
                    $startDate = [DateTime]$contract.StartDate
                }

                $record = [PSCustomObject]@{
                    source                = $person.Source.DisplayName
                    externalId            = $person.ExternalId
                    displayName           = $person.DisplayName
                    contractExternalId    = $contract.ExternalId
                    departmentId          = $contract.Department.ExternalId
                    departmentCode        = $contract.Department.Code
                    departmentDescription = $contract.Department.DisplayName
                    titleId               = $contract.Title.ExternalId
                    titleCode             = $contract.Title.Code
                    titleDescription      = $contract.Title.Name
                    contractIsPrimary     = $false
                    startDate             = $startDate
                    endDate               = $endDate
                }
                [void]$ExpandedPersons.Value.Add($record)

                if ($personPropertiesToInclude) {
                    foreach ($personPropertyToInclude in $personPropertiesToInclude) {
                        $personProperty = '$person.' + "$personPropertyToInclude"
                        $personPropertyValue = ($personProperty | Invoke-Expression) 
                        $record | Add-Member -MemberType NoteProperty -Name $personPropertyToInclude.replace(".", "") -Value $personPropertyValue -Force
                    }
                }
                if ($contractPropertiesToInclude) {
                    foreach ($contractPropertyToInclude in $contractPropertiesToInclude) {
                        $contractProperty = '$contract.' + "$contractPropertyToInclude"
                        $contractPropertyValue = ($contractProperty | Invoke-Expression) 
                        $record | Add-Member -MemberType NoteProperty -Name $contractPropertyToInclude.replace(".", "") -Value $contractPropertyValue -Force
                    }
                }

            }
        }
    }
    catch {
        Write-Error $_.Exception
    }
}

#region Retrieve all persons
Write-Information "Gathering persons..." -InformationAction Continue
$snapshot = Get-Content -Path $vaultJson -Encoding UTF8 | ConvertFrom-Json
$persons = $snapshot.Persons
#endregion Retrieve all persons

#region Expand persons with contracts
$expandedPersons = New-Object System.Collections.ArrayList
Expand-Persons -Persons $persons ([ref]$ExpandedPersons)
#endregion Expand persons with contracts

#region Retrieve all users
Write-Information "Gathering users..." -InformationAction Continue

# Get Azure AD users
try {
    $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

    [System.Collections.ArrayList]$azureUsers = @()

    # Define the properties to select (comma seperated)
    # Add optional popertySelection (mandatory: id,displayName,userPrincipalName)
    $properties = @("id", "displayName", "userPrincipalName", "accountEnabled", $userCorrelationAttribute)
    $select = "`$select=$($properties -join ",")"

    # Get Microsoft Azure AD users (https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http)
    Write-Verbose "Querying Azure AD users"

    $baseUri = "https://graph.microsoft.com/"
    $splatWebRequest = @{
        Uri     = "$baseUri/v1.0/users?$select"
        Headers = $headers
        Method  = 'GET'
    }
    $getAzureUsersResponse = $null
    $getAzureUsersResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
    foreach ($azureUser in $getAzureUsersResponse.value) { $null = $azureUsers.Add($azureUser) }
    
    while (![string]::IsNullOrEmpty($getAzureUsersResponse.'@odata.nextLink')) {
        $baseUri = "https://graph.microsoft.com/"
        $splatWebRequest = @{
            Uri     = $getAzureUsersResponse.'@odata.nextLink'
            Headers = $headers
            Method  = 'GET'
        }
        $getAzureUsersResponse = $null
        $getAzureUsersResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
        foreach ($azureUser in $getAzureUsersResponse.value) { $null = $azureUsers.Add($azureUser) }
    }

    Write-Information "Successfully queried Azure AD users. Result count: $($azureUsers.Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

    throw "Error querying Azure AD users. Error Message: $($errorMessage.AuditErrorMessage)"
}

$users = $azureUsers | Where-Object { [String]::IsNullOrEmpty($_.($userCorrelationAttribute)) -eq $false }
Export-Clixml -Path "$($exportPath)users.xml" -InputObject $users
$usersGrouped = $users | Group-Object $userCorrelationAttribute -AsHashTable
#endregion Retrieve all users

#region Retrieve all groups
Write-Information "Gathering groups..." -InformationAction Continue

# Get Microsoft 365 Groups (Currently only Microsoft 365 and Security groups are supported by the Microsoft Graph API: https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)
try {
    $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

    [System.Collections.ArrayList]$m365Groups = @()

    # Define the properties to select (comma seperated)
    # Add optinal popertySelection (mandatory: id,displayName,onPremisesSyncEnabled)
    $properties = @("id", "displayName", "onPremisesSyncEnabled", "groupTypes")
    $select = "`$select=$($properties -join ",")"

    # Get Microsoft 365 Groups only (https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http)
    Write-Verbose "Querying Microsoft 365 groups"

    $baseUri = "https://graph.microsoft.com/"
    $m365GroupFilter = "`$filter=groupTypes/any(c:c+eq+'Unified')"
    $splatWebRequest = @{
        Uri     = "$baseUri/v1.0/groups?$m365GroupFilter&$select"
        Headers = $headers
        Method  = 'GET'
    }
    $getM365GroupsResponse = $null
    $getM365GroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
    foreach ($M365Group in $getM365GroupsResponse.value) { $null = $m365Groups.Add($M365Group) }
    
    while (![string]::IsNullOrEmpty($getM365GroupsResponse.'@odata.nextLink')) {
        $baseUri = "https://graph.microsoft.com/"
        $splatWebRequest = @{
            Uri     = $getM365GroupsResponse.'@odata.nextLink'
            Headers = $headers
            Method  = 'GET'
        }
        $getM365GroupsResponse = $null
        $getM365GroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
        foreach ($M365Group in $getM365GroupsResponse.value) { $null = $m365Groups.Add($M365Group) }
    }

    # Add GroupType property to object
    $m365Groups | Add-Member -MemberType NoteProperty -Name "GroupType" -Value $null -Force
    $m365Groups | ForEach-Object {
        $_.GroupType = "Microsoft 365 Group"
    }    

    Write-Information "Successfully queried Microsoft 365 groups. Result count: $($m365Groups.Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

    throw "Error querying Microsoft 365 Groups. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Get Security Groups (Currently only Microsoft 365 and Security groups are supported by the Microsoft Graph API: https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)
try {
    $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

    [System.Collections.ArrayList]$securityGroups = @()

    # Define the properties to select (comma seperated)
    # Add optinal popertySelection (mandatory: id,displayName,onPremisesSyncEnabled)
    $properties = @("id", "displayName", "onPremisesSyncEnabled", "groupTypes")
    $select = "`$select=$($properties -join ",")"

    # Get Security Groups only (https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0)
    Write-Verbose "Querying Security groups"

    $securityGroupFilter = "`$filter=NOT(groupTypes/any(c:c+eq+'DynamicMembership')) and onPremisesSyncEnabled eq null and mailEnabled eq false and securityEnabled eq true"
    $baseUri = "https://graph.microsoft.com/"
    $splatWebRequest = @{
        Uri     = "$baseUri/v1.0/groups?$securityGroupFilter&$select&`$count=true"
        Headers = $headers
        Method  = 'GET'
    }
    $getSecurityGroupsResponse = $null
    $getSecurityGroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
    foreach ($SecurityGroup in $getSecurityGroupsResponse.value) { $null = $securityGroups.Add($SecurityGroup) }
    
    while (![string]::IsNullOrEmpty($getSecurityGroupsResponse.'@odata.nextLink')) {
        $baseUri = "https://graph.microsoft.com/"
        $splatWebRequest = @{
            Uri     = $getSecurityGroupsResponse.'@odata.nextLink'
            Headers = $headers
            Method  = 'GET'
        }
        $getSecurityGroupsResponse = $null
        $getSecurityGroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
        foreach ($SecurityGroup in $getSecurityGroupsResponse.value) { $null = $securityGroups.Add($SecurityGroup) }
    }

    # Add GroupType property to object
    $securityGroups | Add-Member -MemberType NoteProperty -Name "GroupType" -Value $null -Force
    $securityGroups | ForEach-Object {
        $_.GroupType = "Security Group"
    }

    Write-Information "Successfully queried Security groups. Result count: $($securityGroups.Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

    throw "Error querying Security Groups. Error Message: $($errorMessage.AuditErrorMessage)"
}

$groups = $m365Groups + $securityGroups
Export-Clixml -Path "$($exportPath)groups.xml" -InputObject $groups
$groupsGrouped = $groups | Group-Object id -AsHashTable
#endregion Retrieve all groups

#region Retrieve the membership of groups, requires fetch per group
$groupsWithMembers = New-Object System.Collections.ArrayList

# Get members of groups
try {
    Write-Information "Retrieving group memberships for each group..." -InformationAction Continue

    $headers = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

    [System.Collections.ArrayList]$groupsWithMembers = @()

    # Retrieve the membership of groups, requires fetch per group
    foreach ($group in $Groups) {
        [System.Collections.ArrayList]$groupMembers = @()

        # Get members of group (https://learn.microsoft.com/en-us/graph/api/group-list-members?view=graph-rest-1.0&tabs=http)
        $properties = @("id", "displayName", "userPrincipalName", $userCorrelationAttribute)
        $select = "`$select=$($properties -join ",")"

        $baseUri = "https://graph.microsoft.com/"
        $splatWebRequest = @{
            Uri     = "$baseUri/v1.0/groups/$($group.id)/members?$select"
            Headers = $headers
            Method  = 'GET'
        }
        $getGroupMembersResponse = $null
        $getGroupMembersResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
        foreach ($groupMember in $getGroupMembersResponse.value) { $null = $groupMembers.Add($groupMember) }    
        
        while (![string]::IsNullOrEmpty($getGroupMembersResponse.'@odata.nextLink')) {
            $baseUri = "https://graph.microsoft.com/"
            $splatWebRequest = @{
                Uri     = $getGroupMembersResponse.'@odata.nextLink'
                Headers = $headers
                Method  = 'GET'
            }
            $getGroupMembersResponse = $null
            $getGroupMembersResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
            foreach ($groupMember in $getGroupMembersResponse.value) { $null = $groupMembers.Add($groupMember) }
        }

        $groupAugmented = [PSCustomObject]@{}

        if ($groupMembers.'@odata.type' -eq '#microsoft.graph.group') {
            $groupAugmented = [PSCustomObject]@{
                Id     = $group.id
                Name   = $group.displayName
                Groups = $groupMembers
            }
        }

        if ($groupMembers.'@odata.type' -eq '#microsoft.graph.user') {
            $groupAugmented = [PSCustomObject]@{
                Id    = $group.id
                Name  = $group.displayName
                Users = $groupMembers
            }
        }

        if ($groupAugmented.Id -ne $null) {
            [void]$groupsWithMembers.Add($groupAugmented)      
        }
    }
    
    Write-Information "Successfully retrieved group memberships for each group. Result count: $($groupsWithMembers.Users.Count)"  
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

    throw "Error retrieving group memberships for each group. Error Message: $($errorMessage.AuditErrorMessage)"
}

Export-Clixml -Path "$($exportPath)groupsWithMembers.xml" -InputObject $groupsWithMembers
$groupsWithMembers = Import-Clixml -Path "$($exportPath)groupsWithMembers.xml"
#endegion Retrieve the membership of groups, requires fetch per group

$groupsWithMembersHashTable = $groupsWithMembers | Group-Object "id" -AsHashTable

#region Transform group memberships into users with memberOf
$usersWithMemberOf = New-Object System.Collections.ArrayList
Invoke-TransformMembershipsToMemberOf -GroupsWithMembers $groupsWithMembers ([ref]$usersWithMemberOf)
Export-Clixml -Path "$($exportPath)usersWithMemberOf.xml" -InputObject $usersWithMemberOf
$usersWithMemberOf = $usersWithMemberOf | Group-Object "userGuid" -AsHashTable
#endregion Transform group memberships into users with memberOf

$personPermissions = New-Object System.Collections.ArrayList

# Retrieve evalution
if (-not[string]::IsNullOrEmpty($evaluationReportCsv)) {
    Write-Information "Gathering data from evaluation report export..." -InformationAction Continue
    $evaluationReport = Import-Csv -Path $evaluationReportCsv -Delimiter "," -Encoding UTF8
    $evaluationPermissions = $evaluationReport | Where-Object { $_.System -eq $evaluationSystemName -and $_.Type -eq "Permission" -and $_.Operation -eq "Grant" -and $_.EntitlementName -Like "$evaluationPermissionTypeName - *" }

    # Add GroupName to evaluation since we need to match to the correct groups
    $evaluationPermissions | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $null -Force
    $evaluationPermissions | ForEach-Object {
        # Replace the permission type name so the name matches the actual group in Target system
        $_.GroupName = $_.EntitlementName -replace "$evaluationPermissionTypeName - "
    }

    # Transform Evaluation Report into persons with entitlements
    $evaluatedPersonsWithEntitlement = $null
    $evaluatedPersonsWithEntitlement = $evaluationPermissions | Group-Object "Person" -AsHashTable
}

# Retrieve entitlements
if (-not[string]::IsNullOrEmpty($grantedEntitlementsCsv)) {
    Write-Information "Gathering data from granted entitlements export..." -InformationAction Continue
    $entitlementsReport = Import-Csv -Path $grantedEntitlementsCsv -Delimiter "," -Encoding UTF8
    $entitlementsGranted = $entitlementsReport | Where-Object { $_.System -eq $entitlementsSystemName -and $_.EntitlementName -Like "Permission - *" }
 
    # Add GroupName to evaluation since we need to match to the correct groups
    $entitlementsGranted | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $null -Force
    $entitlementsGranted | ForEach-Object {
        foreach ($entitlementsPermissionTypeName in $entitlementsPermissionTypeNames) {
            if ($_.EntitlementName -like "$entitlementsPermissionTypeName - *") {
                # Replace the permission type name so the name matches the actual group in Target system
                $_.GroupName = $_.EntitlementName -replace "$entitlementsPermissionTypeName - "
            }
        }
    }

    # Transform Evaluation Report into persons with entitlements
    $personsWithGrantedEntitlements = $null
    $personsWithGrantedEntitlements = $entitlementsGranted | Group-Object "Person" -AsHashTable
}

# Create three arraylists
$personsWithoutCorrelationValue = [System.Collections.ArrayList]::new()
$personsWithoutUser = [System.Collections.ArrayList]::new()
$personsWithoutPermissions = [System.Collections.ArrayList]::new()

# Count the persons in expandedPersons
$totalUsers = $expandedPersons.Count

# Check if there are persons in totalUsers
if ($totalUsers -eq 0) {
    Write-information "No users to process."
    return
}

# Log points the log the status of the script
$logPoints = @([math]::Ceiling($totalUsers * 0.25), [math]::Ceiling($totalUsers * 0.50), [math]::Ceiling($totalUsers * 0.75))
$counter = 0

foreach ($person in $expandedPersons) {
    $counter++
    $personCorrelationProperty = $personCorrelationAttribute.replace(".", "")
    $personCorrelationValue = $person.$personCorrelationProperty
    $person | Add-Member -MemberType NoteProperty -Name 'isActive' -Value '' -Force  
        
    # Check if the contract of the person is active
    $today = Get-Date
    
    If (($person.startDate -lt $today) -And ($person.endDate -gt $today)) {
        $person.isActive = $true
    }
    else {
        $person.isActive = $false
    }

    if ($null -eq $personCorrelationValue) {
        Write-Verbose "Person $($person.displayName) has no value for correlation attribute: $personCorrelationProperty"
        $personWithoutCorrelationValueObject = [PSCustomObject]@{
            "Person displayname"          = $person.displayName
            "Person externalId"           = $person.externalId
            "Person is active"            = $person.isActive
            "Person correlation property" = $personCorrelationProperty
            "Person correlation value"    = "$($personCorrelationValue)"
        }
        [void]$personsWithoutCorrelationValue.Add($personWithoutCorrelationValueObject)
        continue;
    }
    $user = $usersGrouped[$personCorrelationValue]

    if ($null -eq $user) { 
        Write-Verbose "No user found where $($userCorrelationAttribute) = $($personCorrelationValue) for person $($person.displayName)"
        $personWithoutUserObject = [PSCustomObject]@{
            "Person displayname"          = $person.displayName
            "Person externalId"           = $person.externalId
            "Person is active"            = $person.isActive
            "Person correlation property" = $personCorrelationProperty
            "Person correlation value"    = "$($personCorrelationValue)"
        }
        [void]$personsWithoutUser.Add($personWithoutUserObject)
        continue; 
    }
    
    $permissions = $usersWithMemberOf[$user.id]
    
    #add dummy group
    if ($addDummyGroup -eq $true) {
        $dummyRecord = [PSCustomObject]@{
            source                = $person.source
            externalId            = $person.externalId
            displayName           = $person.displayName
            departmentId          = $person.departmentId
            departmentCode        = $person.departmentCode
            departmentDescription = $person.departmentDescription
            titleId               = $person.titleId
            titleCode             = $person.titleCode
            titleDescription      = $person.titleDescription
            contractIsPrimary     = $person.contractIsPrimary
            startDate             = $person.startDate
            endDate               = $person.endDate
            isActive              = $person.isActive
            userName              = $user.userPrincipalName
            isEnabled             = $user.accountEnabled
            permission            = "Total"
            permissionType        = "Dummy group"
            inEvaluation          = $false
            isGranted             = $false
            FunctieExternalID     = $person.titleId + "|" + $person.titleCode + "|" + $person.externalId
            DepartmentExternalID  = $person.departmentId + "|" + $person.departmentCode + "|" + $person.externalId
        }
        if ($includeNestedGroupMemberships -eq $true) {
            $dummyRecord | Add-Member -MemberType NoteProperty -Name "isNested" -Value $false -Force
            $dummyRecord | Add-Member -MemberType NoteProperty -Name "parentGroup" -Value $null -Force
        }

        if ($personPropertiesToInclude) {
            foreach ($personPropertyToInclude in $personPropertiesToInclude) {
                $personProperty = '$person.' + $personPropertyToInclude.replace(".", "")
                $personPropertyValue = ($personProperty | Invoke-Expression) 
                $dummyRecord | Add-Member -MemberType NoteProperty -Name $personPropertyToInclude.replace(".", "") -Value $personPropertyValue -Force
            }
        }
        if ($contractPropertiesToInclude) {
            foreach ($contractPropertyToInclude in $contractPropertiesToInclude) {
                $contractProperty = '$person.' + $contractPropertyToInclude.replace(".", "")
                $contractPropertyValue = ($contractProperty | Invoke-Expression) 
                $dummyRecord | Add-Member -MemberType NoteProperty -Name $contractPropertyToInclude.replace(".", "") -Value $contractPropertyValue -Force
            }
        }
        [void]$personPermissions.Add($dummyRecord)
    }

    if ($null -eq $permissions) { 
        Write-Verbose "No permission(s) found where Userguid = $($user.id) for person $($person.displayName)"
        $personWithoutPermissionsObject = [PSCustomObject]@{
            "Person displayname"          = $person.displayName
            "Person externalId"           = $person.externalId
            "Person is active"            = $person.isActive
            "Person correlation property" = $personCorrelationProperty
            "Person correlation value"    = "$($personCorrelationValue)"
            "User ID"                     = "$($user.id)"
        }
        
        [void]$personsWithoutPermissions.Add($personWithoutPermissionsObject)
        continue; 
    }

    # Get evaluated entitlements for person
    if ($null -ne $evaluatedPersonsWithEntitlement) { $evaluatedEntitlements = $evaluatedPersonsWithEntitlement[$person.DisplayName] }

    # Get granted entitlements for person
    if ($null -ne $personsWithGrantedEntitlements) { $grantedEntitlements = $personsWithGrantedEntitlements[$person.DisplayName] }

    foreach ($permission in $permissions) {
        $group = $groupsGrouped[$permission.memberOf]

        if ($null -eq $group) { continue; }
        
        # Check if group is in evaluation
        if ($group.displayName -in $evaluatedEntitlements.GroupName) {
            $inEvaluation = $true
        }
        else {
            $inEvaluation = $false
        }

        # Check if group is in granted entitlements
        if ($group.displayName -in $grantedEntitlements.GroupName) {
            $isGranted = $true
        }
        else {
            $isGranted = $false
        }

        $record = [PSCustomObject]@{
            source                = $person.source
            externalId            = $person.externalId
            displayName           = $person.displayName
            departmentId          = $person.departmentId
            departmentCode        = $person.departmentCode
            departmentDescription = $person.departmentDescription
            titleId               = $person.titleId
            titleCode             = $person.titleCode
            titleDescription      = $person.titleDescription
            contractIsPrimary     = $person.contractIsPrimary
            startDate             = $person.startDate
            endDate               = $person.endDate
            isActive              = $person.isActive
            userName              = $user.userPrincipalName
            isEnabled             = $user.accountEnabled
            permission            = $group.displayName
            permissionType        = $group.GroupType
            inEvaluation          = $inEvaluation
            isGranted             = $isGranted
            FunctieExternalID     = $person.titleId + "|" + $person.titleCode + "|" + $person.externalId
            DepartmentExternalID  = $person.departmentId + "|" + $person.departmentCode + "|" + $person.externalId
        }

        if ($includeNestedGroupMemberships -eq $true) {
            $record | Add-Member -MemberType NoteProperty -Name "isNested" -Value $permission.isNested -Force
            $record | Add-Member -MemberType NoteProperty -Name "parentGroup" -Value $permission.parentGroup -Force
        }

        if ($personPropertiesToInclude) {
            foreach ($personPropertyToInclude in $personPropertiesToInclude) {
                $personProperty = '$person.' + $personPropertyToInclude.replace(".", "")
                $personPropertyValue = ($personProperty | Invoke-Expression) 
                $record | Add-Member -MemberType NoteProperty -Name $personPropertyToInclude.replace(".", "") -Value $personPropertyValue -Force
            }
        }
        if ($contractPropertiesToInclude) {
            foreach ($contractPropertyToInclude in $contractPropertiesToInclude) {
                $contractProperty = '$person.' + $contractPropertyToInclude.replace(".", "")
                $contractPropertyValue = ($contractProperty | Invoke-Expression) 
                $record | Add-Member -MemberType NoteProperty -Name $contractPropertyToInclude.replace(".", "") -Value $contractPropertyValue -Force
            }
        }

        [void]$personPermissions.Add($record)
    }
    # Logging percentage of the script 
    if ($counter -eq $logPoints[0]) {
        Write-information "Status: 25% ($counter of $totalUsers) users processed."
    }
    elseif ($counter -eq $logPoints[1]) {
        Write-information "Status: 50% ($counter of $totalUsers) users processed."
    }
    elseif ($counter -eq $logPoints[2]) {
        Write-information "Status: 75% ($counter of $totalUsers) users processed."
    }
}

#region security logging exports
if (($personsWithoutCorrelationValue | Measure-Object).Count -gt 0) {
    $personsWithoutCorrelationValue | Export-Csv -Path "$($exportPath)personsWithoutCorrelationValue.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
}

if (($personsWithoutUser | Measure-Object).Count -gt 0) {
    $personsWithoutUser | Export-Csv -Path "$($exportPath)personsWithoutUser.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
}

if (($personsWithoutPermissions | Measure-Object).Count -gt 0) {
    $personsWithoutPermissions | Export-Csv -Path "$($exportPath)personsWithoutPermissions.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
}
#endregion

Write-Information "Exporting data to CSV..." -InformationAction Continue
$personPermissions | Export-Csv -Path "$($exportPath)personPermissions.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force