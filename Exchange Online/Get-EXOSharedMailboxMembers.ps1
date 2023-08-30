<#
.SYNOPSIS

.DESCRIPTION

.NOTES
    Author: Ramon Schouten
    Editor: Jeroen Smit
    Created At: 2023-08-03
    Last Edit: 2023-08-03
    Version 1.0 - initial release (inclduing status active for the employee and support for no startdate per employee)
#>

# Specify whether to output the logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Used to connect to Exchange Online using Access Token
$AADOrganization = "<customer domain>.onmicrosoft.com"  # always .onmicrosoft.com
$AADtenantID = "<AZURE_TENANT_ID>"
$AADAppId = "<AZURE_APP_ID>"
$AADAppSecret ="<AZURE_APP_SECRET>"

# Toggle to include nested groupmemberships in Shared Mailboxes (up to a maximum of 1 layer deep)
$includeNestedGroupMemberships = $true # or $false

## Replace path with your path for vault.json, Evaluation.csv and entitlements.csv.
## Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments
$exportPath = "C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\"

# Optionally, specifiy the parameters below when you want to check the groups against an evaluation report
# The location of the Evaluation Report Csv (needs to be manually exported from a HelloID Provisioning evaluation).
$evaluationReportCsv = $exportPath + "EvaluationReport.csv"
# The name of the system on which to check the permissions in the evaluation (Required when using the evaluation report)
# Note: in HelloID Provisioning we mainly use the system name "Exchange Online Permissions", but this can differ.
# Change this accordingly to your HelloID Provisioning configuration
$evaluationSystemName = "Exchange Online Permissions"
# The name of the permission type on which to check the permissions in the evaluation (Required when using the entitlements report) (Default for Exchange Online is: Permission)
$evaluationPermissionTypeName = "Permission"
# The names of the permissions that the HelloID Provisions target systems grants
# Note: in HelloID Provisioning we mainly grant the Full Access & Send As within a single permission, but this can differ.
# Change this accordingly to your HelloID Provisioning configuration
$systemPermissionOptions = @("Full Access", "Send As") # Supported options: "Full Access","Send As","Send On Behalf"

# Optionally, specifiy the parameters below when you want to check the groups against a granted entitlements report
# The location of the Granted Entitlements Csv (needs to be manually exported from a HelloID Provisioning Granted Entitlements).
$grantedEntitlementsCsv = $exportPath + "Entitlements.csv"
# The name of the system on which to check the permissions in the granted entitlements (Required when using the entitlements report)
# Note: in HelloID Provisioning we mainly use the system name "Exchange Online Permissions", but this can differ.
# Change this accordingly to your HelloID Provisioning configuration
$entitlementsSystemName = "Exchange Online Permissions"  
# The name of the permission type on which to check the permissions in the granted entitlements (Required when using the entitlements report) (Default for Exchange Online is: Permission)
$entitlementsPermissionTypeName = "Permission"

## The attribute used to correlate a person to an account
$personCorrelationAttribute = "externalId" # or e.g. "Contact.Business.Email"
$entraUserCorrelationAttribute = "employeeId" # or e.g. "userPrincipalName"

# The location of the Vault export in JSON format (needs to be manually exported from a HelloID Provisioning snapshot).
$vaultJson = $exportPath + "vault.json"
# Specify the Person fields from the HelloID Vault export to include in the report (These have to match the exact name from he Vault.json export) - Must always contains personCorrelationAttribute!
$personPropertiesToInclude = @($personCorrelationAttribute, "source.displayname", "custom.locatie")
# Specify the Contracts fields from the HelloID Vault export to include in the report (These have to match the exact name from he Vault.json export)
$contractPropertiesToInclude = @("costCenter.displayname", "custom.locatie", "Costcenter.name")

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

#region functions
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
        $entraBaseUri = "https://login.microsoftonline.com/"
        $entraAuthUri = $entraBaseUri + "$TenantId/oauth2/token"
    
        $entraBody = @{
            Grant_type    = "client_credentials"
            Client_id     = "$ClientId"
            Client_secret = "$ClientSecret"
            Resource      = "https://graph.microsoft.com"
        }
    
        $entraResponse = Invoke-RestMethod -Method POST -Uri $entraAuthUri -Body $entraBody -ContentType 'application/x-www-form-urlencoded'
        $entraAccessToken = $entraResponse.access_token
    
        #Add the authorization header to the request
        Write-Verbose 'Adding Authorization headers'

        $entraHeaders = [System.Collections.Generic.Dictionary[[String], [String]]]::new()
        $entraHeaders.Add('Authorization', "Bearer $entraAccessToken")
        $entraHeaders.Add('Accept', 'application/json')
        $entraHeaders.Add('Content-Type', 'application/json')
        # Needed to filter on specific attributes (https://docs.microsoft.com/en-us/graph/aad-advanced-queries)
        $entraHeaders.Add('ConsistencyLevel', 'eventual')

        Write-Output $entraHeaders
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

function Expand-Persons {
    param(
        [parameter(Mandatory = $true)]$Persons,
        [parameter(Mandatory = $true)][ref]$ExpandedPersons
    )

    try {
        Write-Information "Expanding persons with contracts..." -InformationAction Continue

        # Sort data per person
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

            # Add addition fields of the person
            if ($personPropertiesToInclude) {
                foreach ($personPropertyToInclude in $personPropertiesToInclude) {
                    $personProperty = '$person' + ".$personPropertyToInclude"
                    $personPropertyValue = ($personProperty | Invoke-Expression) 
                    $record | Add-Member -MemberType NoteProperty -Name $personPropertyToInclude.replace(".", "") -Value $personPropertyValue -Force
                }
            }
            # Add addition fields of the contract(s) of the person
            if ($contractPropertiesToInclude) {
                foreach ($contractPropertyToInclude in $contractPropertiesToInclude) {
                    $contractProperty = '$person.PrimaryContract' + ".$contractPropertyToInclude"
                    $contractPropertyValue = ($contractProperty | Invoke-Expression) 
                    $record | Add-Member -MemberType NoteProperty -Name $contractPropertyToInclude.replace(".", "") -Value $contractPropertyValue -Force
                }
            }

            [void]$ExpandedPersons.Value.Add($record)

            # Expand per contract the different fields
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

                # Add addition fields of the person
                if ($personPropertiesToInclude) {
                    foreach ($personPropertyToInclude in $personPropertiesToInclude) {
                        $personProperty = '$person.' + "$personPropertyToInclude"
                        $personPropertyValue = ($personProperty | Invoke-Expression) 
                        $record | Add-Member -MemberType NoteProperty -Name $personPropertyToInclude.replace(".", "") -Value $personPropertyValue -Force
                    }
                }
                # Add addition fields of the contract(s) of the person
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
#endregion functions

#region Retrieve all persons
Write-Information "Gathering persons..." -InformationAction Continue
$snapshot = Get-Content -Path $vaultJson -Encoding UTF8 | ConvertFrom-Json
$persons = $snapshot.Persons
#endregion Retrieve all persons

#region Expand persons with contracts
$expandedPersons = New-Object System.Collections.ArrayList
Expand-Persons -Persons $snapshot.Persons ([ref]$ExpandedPersons)
#endregion Expand persons with contracts

#region Retrieve all users
Write-Information "Gathering users..." -InformationAction Continue

# Get Entra ID users
try {
    $entraHeaders = New-AuthorizationHeaders -TenantId $AADtenantID -ClientId $AADAppId -ClientSecret $AADAppSecret

    [System.Collections.ArrayList]$entraUsers = @()

    # Define the properties to select (comma seperated)
    # Add optional popertySelection (mandatory: id,displayName,userPrincipalName)
    $entraProperties = @("id", "displayName", "userPrincipalName", "accountEnabled", $entraUserCorrelationAttribute)
    $entraSelect = "`$select=$($entraProperties -join ",")"

    # Get Microsoft Entra ID users (https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http)
    Write-Verbose "Querying Entra ID users"

    $entraBaseUri = "https://graph.microsoft.com/"
    $entraSplatWebRequest = @{
        Uri     = "$entraBaseUri/v1.0/users?$entraSelect&`$top=999&`$count=true"
        Headers = $entraHeaders
        Method  = 'GET'
    }
    $getEntraUsersResponse = $null
    $getEntraUsersResponse = Invoke-RestMethod @entraSplatWebRequest -Verbose:$false
    foreach ($entraUser in $getEntraUsersResponse.value) { $null = $entraUsers.Add($entraUser) }
    
    while (![string]::IsNullOrEmpty($getEntraUsersResponse.'@odata.nextLink')) {
        $entraBaseUri = "https://graph.microsoft.com/"
        $entraSplatWebRequest = @{
            Uri     = $getEntraUsersResponse.'@odata.nextLink'
            Headers = $entraHeaders
            Method  = 'GET'
        }
        $getEntraUsersResponse = $null
        $getEntraUsersResponse = Invoke-RestMethod @entraSplatWebRequest -Verbose:$false
        foreach ($entraUser in $getEntraUsersResponse.value) { $null = $entraUsers.Add($entraUser) }
    }

    Write-Information "Successfully queried Entra ID users. Result count: $($entraUsers.Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

    throw "Error querying Entra ID users. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Get users only with a correlationattribute filled in AAD
$users = $entraUsers | Where-Object { [String]::IsNullOrEmpty($_.($entraUserCorrelationAttribute)) -eq $false }
$usersGroupedOnCorrelationAttribute = $users | Group-Object $entraUserCorrelationAttribute -AsHashTable
$usersGroupedOnUPN = $users | Group-Object userPrincipalName -AsHashTable
$usersGroupedOnId = $users | Group-Object id -AsHashTable
#endregion Retrieve all users

Write-Information "Connecting to Exchange Online..."

try {
    #region Connect to Exchange Online
    try {
        # Create Access Token to connect to Exchange Online
        Write-Verbose "Creating Access Token"

        $exoBaseUri = "https://login.microsoftonline.com/"
        $exoAuthUri = $exoBaseUri + "$AADTenantId/oauth2/token"
        
        $exoBody = @{
            Grant_type    = "client_credentials"
            Client_id     = "$AADAppID"
            Client_secret = "$AADAppSecret"
            Resource      = "https://outlook.office365.com"
        }

        $exoAuthSplatWebRequest = @{
            Uri             = $exoAuthUri
            Method          = "POST"
            Body            = $exoBody
            ContentType     = "application/x-www-form-urlencoded"
            UseBasicParsing = $true
        }
        $exoResponse = Invoke-RestMethod @exoAuthSplatWebRequest
        $exoAccessToken = $exoResponse.access_token

        # Connect to Exchange Online in an unattended scripting scenario using Access Token
        Write-Verbose "Connecting to Exchange Online Tenant [$($AADTenantId)] and Organization [$($AADOrganization)] using App ID [$($AADAppID)]"

        $exchangeSessionParams = @{
            Organization     = $AADOrganization
            AppID            = $AADAppID
            AccessToken      = $exoAccessToken
            ShowBanner       = $false
            ShowProgress     = $false
            TrackPerformance = $false
            ErrorAction      = 'Stop'
        }
        $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams

        Write-Information "Successfully connected to Exchange Online"
    }
    catch {
        throw "Error connecting to Exchange Online Tenant [$($AADTenantId)] and Organization [$($AADOrganization)] using App ID [$($AADAppID)]. Error: $_"
    }
    #endregion Connect to Exchange Online

    #region Get Exchange online groups
    # Exchange Online groups are needed so all the attributes aren available
    try {
        Write-Verbose "Querying Exchange groups"

        $groups = Get-Group -ResultSize Unlimited
 
        $groupsGroupedOnDisplayname = $groups | Group-Object Displayname -AsHashTable  
        $groupsGroupedOnName = $groups | Group-Object Name -AsHashTable  

        Write-Information "Successfully queried Exchange groups. Result count: $(($groups | Measure-Object).Count)"
    }
    catch { 
        throw "Error querying all Exchange groups. Error: $_"
    }
    #endregion Get Exchange online groups

    #region Get Mailbox
    try {
        Write-Verbose "Querying all Shared Mailboxes"

        $mailboxes = Get-EXOMailbox -RecipientTypeDetails SharedMailbox -Properties GrantSendOnBehalfTo -ResultSize Unlimited # Returns Mailbox object

        Write-Information "Successfully queried all Shared Mailboxes. Result count: $(($mailboxes | Measure-Object).Count)"
    }
    catch {
        throw "Error querying all Shared Mailboxes. Error: $_"
    }
    #endregion Get Mailbox

    [System.Collections.ArrayList]$fullAccessUsers = @()
    [System.Collections.ArrayList]$sendAsUsers = @()
    [System.Collections.ArrayList]$sendOnBehalfUsers = @()

    foreach ($mailbox in $mailboxes) {
        #region Get objects with Full Access to Shared Mailbox
        try {
            Write-Verbose "Querying Full Access Permissions to Mailbox [$($mailbox.UserPrincipalName)]"

            $fullAccessPermissions = Get-EXOMailboxPermission -Identity $mailbox.UserPrincipalName -ResultSize Unlimited # Returns UPN of users, DisplayName of groups

            # Filter out "NT AUTHORITY\*" and "Domain Admins" Group
            $fullAccessPermissions = $fullAccessPermissions | Where-Object { ($_.accessRights -like "*fullaccess*") -and -not($_.Deny -eq $true) -and -not($_.User -like "NT AUTHORITY\*") -and -not($_.User -like "*\Domain Admins") }

            foreach ($fullAccessPermission in $fullAccessPermissions) {
                $fullAccessUser = $null
                # list of al the users in the mailbox. This includes the groups member from the mailbox

                if ($null -ne $fullAccessPermission.User) {
                    $fullAccessUser = $null
                    $fullAccessUser = $usersGroupedOnUPN[$($fullAccessPermission.user)]
                    if ($null -ne $fullAccessUser) {
                        $fullAccessUserObject = [PSCustomObject]@{
                            MailboxDisplayName       = $mailbox.DisplayName
                            MailboxName              = $mailbox.Name
                            MailboxUserPrincipalName = $mailbox.UserPrincipalName
                            MailboxId                = $mailbox.Id
                            UserId                   = $fullAccessUser.id
                            UserDisplayName          = $fullAccessUser.displayName
                            UserUserPrincipalName    = $fullAccessUser.userPrincipalName
                            UserIsNested             = $false
                            UserParentGroup          = $null
                        }

                        [void]$fullAccessUsers.Add($fullAccessUserObject)
                    }
                    Else {
                        $fullAccessGroup = $null
                        $fullAccessGroup = $groupsGroupedOnDisplayname[$($fullAccessPermission.user)]
                        if ($null -ne $fullAccessGroup) {
                            Write-Verbose "$($fullAccessPermission.user) is a group"
                        
                            # Get users of the nested groups
                            foreach ($groupmember in $fullAccessGroup.Members) {
                                $fullAccessNestedUser = $null
                                $fullAccessNestedUser = $usersGroupedOnId[$groupmember]
                                if ($null -ne $fullAccessNestedUser) {

                                    $fullAccessUserObject = [PSCustomObject]@{
                                        MailboxDisplayName       = $mailbox.DisplayName
                                        MailboxName              = $mailbox.Name
                                        MailboxUserPrincipalName = $mailbox.UserPrincipalName
                                        MailboxId                = $mailbox.Id
                                        UserId                   = $fullAccessNestedUser.id
                                        UserDisplayName          = $fullAccessNestedUser.displayName
                                        UserUserPrincipalName    = $fullAccessNestedUser.userPrincipalName
                                        UserIsNested             = $true
                                        UserParentGroup          = $fullAccessGroup.displayName
                                    }

                                    [void]$fullAccessUsers.Add($fullAccessUserObject)
                                }
                            }
                            # Write-Verbose "Mailbox $($mailbox.UserPrincipalName) with group $($fullAccessGroup.DisplayName) has nested members. Result count nested: $(($fullAccessNestedUsers | Measure-Object).Count)"
                        }
                    }
                }
            }

            Write-Verbose "Successfully queried Full Access Permissions to Mailbox [$($mailbox.UserPrincipalName)]. Result count: $(($fullAccessPermissions | Measure-Object).Count)"
    
        }
        catch {
            throw "Error querying Full Access Permissions to Mailbox [$($mailbox.UserPrincipalName)]. Error: $_"
        }
    
        #endregion Get objects with Full Access to Shared Mailbox

        #region Get objects with Send As to Shared Mailbox
        try {
            Write-Verbose "Querying Send As Permissions to Mailbox [$($mailbox.UserPrincipalName)]"

            $sendAsPermissions = Get-EXORecipientPermission -Identity $mailbox.UserPrincipalName -AccessRights 'SendAs' -ResultSize Unlimited # Returns UPN of users, Name of groups

            # Filter out "NT AUTHORITY\*" and "Domain Admins" Group
            $sendAsPermissions = $sendAsPermissions | Where-Object { -not($_.Deny -eq $true) -and -not($_.Trustee -like "NT AUTHORITY\*") -and -not($_.Trustee -like "*\Domain Admins") }

            foreach ($sendAsPermission in $sendAsPermissions) {
                $sendAsUser = $null
                # list of al the users in the mailbox. This includes the groups member from the mailbox

                if ($null -ne $sendAsPermission.Trustee) {
                    $sendAsUser = $null
                    $sendAsUser = $usersGroupedOnUPN[$($sendAsPermission.Trustee)]
                    if ($null -ne $sendAsUser) {
                        $sendAsUserObject = [PSCustomObject]@{
                            MailboxDisplayName       = $mailbox.DisplayName
                            MailboxName              = $mailbox.Name
                            MailboxUserPrincipalName = $mailbox.UserPrincipalName
                            MailboxId                = $mailbox.Id
                            UserId                   = $sendAsUser.id
                            UserDisplayName          = $sendAsUser.displayName
                            UserUserPrincipalName    = $sendAsUser.userPrincipalName
                            UserIsNested             = $false
                            UserParentGroup          = $null
                        }

                        [void]$sendAsUsers.Add($sendAsUserObject)
                    }
                    Else {
                        $sendAsGroup = $null
                        $sendAsGroup = $groupsGroupedOnName[$($sendAsPermission.Trustee)]
                        if ($null -ne $sendAsGroup) {
                            Write-Verbose "$($sendAsPermission.Trustee) is a group"
                        
                            # Get users of the nested groups
                            foreach ($groupmember in $sendAsGroup.Members) {
                                $sendAsNestedUser = $null
                                $sendAsNestedUser = $usersGroupedOnId[$groupmember]
                                if ($null -ne $sendAsNestedUser) {

                                    $sendAsUserObject = [PSCustomObject]@{
                                        MailboxDisplayName       = $mailbox.DisplayName
                                        MailboxName              = $mailbox.Name
                                        MailboxUserPrincipalName = $mailbox.UserPrincipalName
                                        MailboxId                = $mailbox.Id
                                        UserId                   = $sendAsNestedUser.id
                                        UserDisplayName          = $sendAsNestedUser.displayName
                                        UserUserPrincipalName    = $sendAsNestedUser.userPrincipalName
                                        UserIsNested             = $true
                                        UserParentGroup          = $sendAsGroup.displayName
                                    }

                                    [void]$sendAsUsers.Add($sendAsUserObject)
                                }
                            }
                            # Write-Verbose "Mailbox $($mailbox.UserPrincipalName) with group $($sendAsGroup.DisplayName) has nested members. Result count nested: $(($fullAccessNestedUsers | Measure-Object).Count)"
                        }
                    }
                }
            }

            Write-Verbose "Successfully queried Send As Permissions to Mailbox [$($mailbox.UserPrincipalName)]. Result count: $(($sendAsPermissions | Measure-Object).Count)"
        }
        catch {
            throw "Error querying Send As Permissions to Mailbox [$($mailbox.UserPrincipalName)]. Error: $_"
        }
        #endregion Get objects with Send As to Shared Mailbox

        #region Get objects with Send On Behalf to Shared Mailbox
        try {
            Write-Verbose "Querying Send On Behalf Permissions to Mailbox [$($mailbox.UserPrincipalName)]"
                
            $sendOnBehalfPermissions = $mailbox | ForEach-Object { $_.GrantSendOnBehalfTo } # Returns Id of users, Name of groups

            foreach ($sendOnBehalfPermission in $sendOnBehalfPermissions) {
                $sendOnBehalfUser = $null
                # list of al the users in the mailbox. This includes the groups member from the mailbox

                if ($null -ne $sendOnBehalfPermission) {
                    $sendOnBehalfUser = $null
                    $sendOnBehalfUser = $usersGroupedOnId[$($sendOnBehalfPermission)]
                    if ($null -ne $sendOnBehalfUser) {
                        $sendOnBehalfUserObject = [PSCustomObject]@{
                            MailboxDisplayName       = $mailbox.DisplayName
                            MailboxName              = $mailbox.Name
                            MailboxUserPrincipalName = $mailbox.UserPrincipalName
                            MailboxId                = $mailbox.Id
                            UserId                   = $sendOnBehalfUser.id
                            UserDisplayName          = $sendOnBehalfUser.displayName
                            UserUserPrincipalName    = $sendOnBehalfUser.userPrincipalName
                            UserIsNested             = $false
                            UserParentGroup          = $null
                        }

                        [void]$sendOnBehalfUsers.Add($sendOnBehalfUserObject)
                    }
                    Else {
                        $sendOnBehalfGroup = $null
                        $sendOnBehalfGroup = $groupsGroupedOnName[$($sendOnBehalfPermission)]
                        if ($null -ne $sendOnBehalfGroup) {
                            Write-Verbose "$($sendOnBehalfPermission) is a group"
                        
                            # Get users of the nested groups
                            foreach ($groupmember in $sendOnBehalfGroup.Members) {
                                $sendOnBehalfNestedUser = $null
                                $sendOnBehalfNestedUser = $usersGroupedOnId[$groupmember]
                                if ($null -ne $sendOnBehalfNestedUser) {

                                    $sendOnBehalfUserObject = [PSCustomObject]@{
                                        MailboxDisplayName       = $mailbox.DisplayName
                                        MailboxName              = $mailbox.Name
                                        MailboxUserPrincipalName = $mailbox.UserPrincipalName
                                        MailboxId                = $mailbox.Id
                                        UserId                   = $sendOnBehalfNestedUser.id
                                        UserDisplayName          = $sendOnBehalfNestedUser.displayName
                                        UserUserPrincipalName    = $sendOnBehalfNestedUser.userPrincipalName
                                        UserIsNested             = $true
                                        UserParentGroup          = $sendOnBehalfGroup.displayName
                                    }

                                    [void]$sendOnBehalfUsers.Add($sendOnBehalfUserObject)
                                }
                            }
                        }
                    }
                }
            }
            Write-Verbose "Successfully queried Send On Behalf Permissions to Mailbox [$($mailbox.UserPrincipalName)]. Result count: $(($sendOnBehalfPermissions | Measure-Object).Count)"
        }
        catch {
            throw "Error querying Send On Behalf Permissions to Mailbox [$($mailbox.UserPrincipalName)]. Error: $_"
        }
        #endregion Get objects with Send On Behalf to Shared Mailbox

        
    }
}
finally {
    Disconnect-ExchangeOnline -Confirm:$false
}

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
        If ($_.EntitlementName -like "*Shared Mailbox*") {
            $_.GroupName = $_.EntitlementName -replace "$evaluationPermissionTypeName - Shared Mailbox - "
        }
        elseif ($_.EntitlementName -like "*Distribution Group*") {
            $_.GroupName = $_.EntitlementName -replace "$evaluationPermissionTypeName - Distribution Group - "
        }
        elseif ($_.EntitlementName -like "*Mail-enabled Security Group*") {
            $_.GroupName = $_.EntitlementName -replace "$evaluationPermissionTypeName - Mail-enabled Security Group - "
        }
        else {
            $_.GroupName = $_.EntitlementName -replace "$evaluationPermissionTypeName - "
        }
        
    }

    # Transform Evaluation Report into persons with entitlements
    $evaluatedPersonsWithEntitlement = $null
    $evaluatedPersonsWithEntitlement = $evaluationPermissions | Group-Object "Person" -AsHashTable
}

# Retrieve entitlements 
if (-not[string]::IsNullOrEmpty($grantedEntitlementsCsv)) {
    Write-Information "Gathering data from granted entitlements export..." -InformationAction Continue
    $entitlementsReport = Import-Csv -Path $grantedEntitlementsCsv -Delimiter "," -Encoding UTF8
    $entitlementsGranted = $entitlementsReport | Where-Object { $_.System -eq $entitlementsSystemName -and $_.Status -eq "Granted" -and $_.EntitlementName -Like "$entitlementsPermissionTypeName - *" }

    # Add GroupName to entitlements since we need to match to the correct groups
    $entitlementsGranted | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $null -Force
    $entitlementsGranted | ForEach-Object {
        # Replace the permission type name so the name matches the actual group in Target system
        If ($_.EntitlementName -like "*Shared Mailbox*") {
            $_.GroupName = $_.EntitlementName -replace "$entitlementsPermissionTypeName - Shared Mailbox - "
        }
        elseif ($_.EntitlementName -like "*Distribution Group*") {
            $_.GroupName = $_.EntitlementName -replace "$entitlementsPermissionTypeName - Distribution Group - "
        }
        elseif ($_.EntitlementName -like "*Mail-enabled Security Group*") {
            $_.GroupName = $_.EntitlementName -replace "$evaluationPermissionTypeName - Mail-enabled Security Group - "
        }
        else {
            $_.GroupName = $_.EntitlementName -replace "$entitlementsPermissionTypeName - "
        }
    }

    # Transform Entitlements Report into persons with entitlements
    $personsWithGrantedEntitlements = $null
    $personsWithGrantedEntitlements = $entitlementsGranted | Group-Object "Person" -AsHashTable
}

foreach ($person in $expandedPersons) {
    $personCorrelationProperty = $personCorrelationAttribute.replace(".", "")
    $personCorrelationValue = $person.$personCorrelationProperty
    if ($null -eq $personCorrelationValue) {
        Write-Warning "Person $($person.displayName) has no value for correlation attribute: $personCorrelationProperty"
        continue;
    }

    # Check if the contract of the person is active
    $person | Add-Member -MemberType NoteProperty -Name 'isActive' -Value '' -Force
    $today = Get-Date
    
    If (($person.startDate -lt $today) -And ($person.endDate -gt $today)) {
        $person.isActive = $true
    }
    else {
        $person.isActive = $false
    }   

    $user = $usersGroupedOnCorrelationAttribute[$personCorrelationValue]

    if ($null -eq $user) { continue; }

    if ($null -ne $evaluatedPersonsWithEntitlement) { $evaluatedEntitlements = $evaluatedPersonsWithEntitlement[$person.DisplayName] }

    if ($null -ne $personsWithGrantedEntitlements) { $grantedEntitlements = $personsWithGrantedEntitlements[$person.DisplayName] }

    # Full Access
    $fullAccessPermissions = $null
    $fullAccessPermissions = $fullAccessUsers | Where-Object { $user.userPrincipalName -in $_.UserUserPrincipalName }

    # Send As
    $sendAsPermissions = $null
    $sendAsPermissions = $sendAsUsers | Where-Object { $user.userPrincipalName -in $_.UserUserPrincipalName }

    # #Send On Behalf
    $sendOnBehalfPermissions = $null
    $sendOnBehalfPermissions = $sendOnBehalfUsers | Where-Object { $user.userPrincipalName -in $_.UserUserPrincipalName }
    
    # Check if variables are filled
    if ($null -eq $fullAccessPermissions -and $null -eq $sendAsPermissions -and $null -eq $sendOnBehalfPermissions) { continue; }

    # Create record(s) for Full Access
    foreach ($fullAccessPermission in $fullAccessPermissions) {
        if ($fullAccessPermission.MailboxDisplayName -in $evaluatedEntitlements.GroupName) {
            $inEvaluation = $true
        }
        else {
            $inEvaluation = $false
        }

        if ($fullAccessPermission.MailboxDisplayName -in $grantedEntitlements.GroupName) {
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
            mailboxUPN            = $fullAccessPermission.UserPrincipalName
            mailboxName           = $fullAccessPermission.MailboxName
            mailboxDisplayName    = $fullAccessPermission.MailboxDisplayName
            permissionType        = "Full Access"
            inEvaluation          = $false # false by default, is calculated in later step
            isGranted             = $false # false by default, is calculated in later step
            functieExternalID     = $person.titleId + "|" + $person.titleCode + "|" + $person.externalId
            departmentExternalID  = $person.departmentId + "|" + $person.departmentCode + "|" + $person.externalId
        }

        if ($record.permissionType -in $systemPermissionOptions) {
            $record.inEvaluation = $inEvaluation
            $record.isGranted = $isGranted
        }

        if ($includeNestedGroupMemberships -eq $true) {
            $record | Add-Member -MemberType NoteProperty -Name "isNested" -Value $fullAccessPermission.UserIsNested -Force
            $record | Add-Member -MemberType NoteProperty -Name "parentGroup" -Value $fullAccessPermission.UserParentGroup -Force
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

    # Create record(s) for Send As
    foreach ($sendAsPermission in $sendAsPermissions) {
        if ($sendAsPermission.MailboxDisplayName -in $evaluatedEntitlements.GroupName) {
            $inEvaluation = $true
        }
        else {
            $inEvaluation = $false
        }

        if ($sendAsPermission.MailboxDisplayName -in $grantedEntitlements.GroupName) {
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
            mailboxUPN            = $sendAsPermission.UserPrincipalName
            mailboxName           = $sendAsPermission.MailboxName
            mailboxDisplayName    = $sendAsPermission.MailboxDisplayName
            permissionType        = "Send As"
            inEvaluation          = $false # false by default, is calculated in later step
            isGranted             = $false # false by default, is calculated in later step
            functieExternalID     = $person.titleId + "|" + $person.titleCode + "|" + $person.externalId
            departmentExternalID  = $person.departmentId + "|" + $person.departmentCode + "|" + $person.externalId
        }

        if ($record.permissionType -in $systemPermissionOptions) {
            $record.inEvaluation = $inEvaluation
            $record.isGranted = $isGranted
        }

        if ($includeNestedGroupMemberships -eq $true) {
            $record | Add-Member -MemberType NoteProperty -Name "isNested" -Value $sendAsPermission.UserIsNested -Force
            $record | Add-Member -MemberType NoteProperty -Name "parentGroup" -Value $sendAsPermission.UserParentGroup -Force
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
    
    # Create record(s) for Send On Behalf
    foreach ($sendOnBehalfPermission in $sendOnBehalfPermissions) {
        if ($sendOnBehalfPermission.MailboxDisplayName -in $evaluatedEntitlements.GroupName) {
            $inEvaluation = $true
        }
        else {
            $inEvaluation = $false
        }

        if ($sendOnBehalfPermission.MailboxDisplayName -in $grantedEntitlements.GroupName) {
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
            mailboxUPN            = $sendOnBehalfPermission.UserPrincipalName
            mailboxName           = $sendOnBehalfPermission.MailboxName
            mailboxDisplayName    = $sendOnBehalfPermission.MailboxDisplayName
            permissionType        = "Send On Behalf"
            inEvaluation          = $false # false by default, is calculated in later step
            isGranted             = $false # false by default, is calculated in later step
            functieExternalID     = $person.titleId + "|" + $person.titleCode + "|" + $person.externalId
            departmentExternalID  = $person.departmentId + "|" + $person.departmentCode + "|" + $person.externalId
        }

        if ($record.permissionType -in $systemPermissionOptions) {
            $record.inEvaluation = $inEvaluation
            $record.isGranted = $isGranted
        }

        if ($includeNestedGroupMemberships -eq $true) {
            $record | Add-Member -MemberType NoteProperty -Name "isNested" -Value $sendOnBehalfPermission.UserIsNested -Force
            $record | Add-Member -MemberType NoteProperty -Name "parentGroup" -Value $sendOnBehalfPermission.UserParentGroup -Force
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
}

Write-Information "Exporting data to CSV..." -InformationAction Continue
$personPermissions | Export-Csv -Path "$($exportPath)personPermissions.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force