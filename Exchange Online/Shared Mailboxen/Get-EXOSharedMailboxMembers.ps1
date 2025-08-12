<#
.SYNOPSIS

.DESCRIPTION

.NOTES
    Author: Ramon Schouten
    Editor: Remco Houthuijzen
    Created At: 2023-08-03
    Last Edit: 2025-08-12
    Version 1.0 - RS - initial release (inclduing status active for the employee and support for no startdate per employee)
    Version 1.1 - JS - Added reporting for persons with no correlation attribute, persons with no account or accounts with no permissions
    Version 1.2 - RH - Added dummy group option
    Version 1.2.1 - JS - Fix column 'Status' is removed from export 'entilements.csv'
    Version 1.3 (RH) - added certificate support
#>

# Specify whether to output the logging
$VerbosePreference = "SilentlyContinue"
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Define authorization method
$CertificateAuthentication = $false # or $true

# Used to connect to Exchange Online using Access Token
$EntraIDOrganization = "<customer domain>.onmicrosoft.com"  # always .onmicrosoft.com
$EntraIDtenantID = "<EntraID_TENANT_ID>"
$EntraIDAppId = "<EntraID_APP_ID>"
$EntraIDAppSecret = "<EntraID_APP_SECRET>"
$AppCertificateBase64String = "<Certificate_Base64_String>"
$AppCertificatePassword = "<Certificate_Password>"

# Toggle to include nested groupmemberships in Shared Mailboxes (up to a maximum of 1 layer deep)
$includeNestedGroupMemberships = $true # or $false

# Toggle to add dummy permission to result for each person
$addDummyPermission = $true # or $false

## Replace path with your path for vault.json, Evaluation.csv and entitlements.csv.
## Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments
$exportPath = "C:\HelloID\RoleminingEXO\"

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
$systemPermissionOptions = @("Full Access", "Send As", "Send On Behalf") # Supported options: "Full Access","Send As","Send On Behalf"

# Optionally, specifiy the parameters below when you want to check the groups against a granted entitlements report
# The location of the Granted Entitlements Csv (needs to be manually exported from a HelloID Provisioning Granted Entitlements).
$grantedEntitlementsCsv = $exportPath + "Entitlements.csv"
# The name of the system on which to check the permissions in the granted entitlements (Required when using the entitlements report)
# Note: in HelloID Provisioning we mainly use the system name "Exchange Online Permissions", but this can differ.
# Change this accordingly to your HelloID Provisioning configuration
$entitlementsSystemName = "Exchange Online"  
# The name of the permission type on which to check the permissions in the granted entitlements (Required when using the entitlements report) (Default for Exchange Online is: Permission)
$entitlementsPermissionTypeName = "Permission - Shared Mailbox"

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

function Get-MSEntraCertificate {
    [CmdletBinding()]
    param(
        [parameter(Mandatory)]
        [string]
        $CertificateBase64String,

        [parameter(Mandatory)]
        [string]
        $CertificatePassword
    )
    try {        
        $rawCertificate = [system.convert]::FromBase64String($CertificateBase64String)
        # $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable)
        $certificate = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($rawCertificate, $CertificatePassword, [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::Exportable -bor [System.Security.Cryptography.X509Certificates.X509KeyStorageFlags]::EphemeralKeySet)
        Write-Output $certificate
    }
    catch {
        $PSCmdlet.ThrowTerminatingError($_)
    }
}

function Get-MSEntraAccessToken {
    [CmdletBinding()]
    [OutputType([System.Collections.Generic.Dictionary[[String], [String]]])]
    param(
        [Parameter(Mandatory)]
        $Certificate,

        [parameter(Mandatory)]
        [string]
        $TenantID,

        [parameter(Mandatory)]
        [string]
        $AppId
    )
    try {
        # Get the DER encoded bytes of the certificate
        $derBytes = $Certificate.RawData

        # Compute the SHA-256 hash of the DER encoded bytes
        $sha256 = [System.Security.Cryptography.SHA256]::Create()
        $hashBytes = $sha256.ComputeHash($derBytes)
        $base64Thumbprint = [System.Convert]::ToBase64String($hashBytes).Replace('+', '-').Replace('/', '_').Replace('=', '')

        # Create a JWT (JSON Web Token) header
        $header = @{
            'alg'      = 'RS256'
            'typ'      = 'JWT'
            'x5t#S256' = $base64Thumbprint
        } | ConvertTo-Json
        $base64Header = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($header))

        # Calculate the Unix timestamp (seconds since 1970-01-01T00:00:00Z) for 'exp', 'nbf' and 'iat'
        $currentUnixTimestamp = [math]::Round(((Get-Date).ToUniversalTime() - ([datetime]'1970-01-01T00:00:00Z').ToUniversalTime()).TotalSeconds)

        # Create a JWT payload
        $payload = [Ordered]@{
            'iss' = "$($AppId)"
            'sub' = "$($AppId)"
            'aud' = "https://login.microsoftonline.com/$($TenantID)/oauth2/token"
            'exp' = ($currentUnixTimestamp + 3600) # Expires in 1 hour
            'nbf' = ($currentUnixTimestamp - 300) # Not before 5 minutes ago
            'iat' = $currentUnixTimestamp
            'jti' = [Guid]::NewGuid().ToString()
        } | ConvertTo-Json
        $base64Payload = [System.Convert]::ToBase64String([System.Text.Encoding]::UTF8.GetBytes($payload)).Replace('+', '-').Replace('/', '_').Replace('=', '')

        #################################################################################################################################################
        # Old CAPI code
        #################################################################################################################################################
        #   # Extract the private key from the certificate
        #     $rsaPrivate = $Certificate.PrivateKey
        #     $rsa = [System.Security.Cryptography.RSACryptoServiceProvider]::new()
        #     $rsa.ImportParameters($rsaPrivate.ExportParameters($true))

        #     # Sign the JWT
        #     $signatureInput = "$base64Header.$base64Payload"
        #     $signature = $rsa.SignData([Text.Encoding]::UTF8.GetBytes($signatureInput), 'SHA256')
        #     $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')

        #     # Create the JWT token
        #     $jwtToken = "$($base64Header).$($base64Payload).$($base64Signature)"
        #################################################################################################################################################

        # This also supports CNG instead of only CAPI 
        $rsaPrivate = [System.Security.Cryptography.X509Certificates.RSACertificateExtensions]::GetRSAPrivateKey($Certificate)
        $signatureInput = "$base64Header.$base64Payload"
        $bytesToSign = [Text.Encoding]::UTF8.GetBytes($signatureInput)
        $hashAlgorithm = [System.Security.Cryptography.HashAlgorithmName]::SHA256
        $padding = [System.Security.Cryptography.RSASignaturePadding]::Pkcs1
        $signature = $rsaPrivate.SignData($bytesToSign, $hashAlgorithm, $padding)
        $base64Signature = [System.Convert]::ToBase64String($signature).Replace('+', '-').Replace('/', '_').Replace('=', '')
        $jwtToken = "$base64Header.$base64Payload.$base64Signature"

        $createEntraAccessTokenBody = @{
            grant_type            = 'client_credentials'
            client_id             = $AppId
            client_assertion_type = 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer'
            client_assertion      = $jwtToken
            resource              = 'https://graph.microsoft.com'
        }

        $createEntraAccessTokenSplatParams = @{
            Uri         = "https://login.microsoftonline.com/$($TenantID)/oauth2/token"
            Body        = $createEntraAccessTokenBody
            Method      = 'POST'
            ContentType = 'application/x-www-form-urlencoded'
            Verbose     = $false
            ErrorAction = 'Stop'
        }

        $createEntraAccessTokenResponse = Invoke-RestMethod @createEntraAccessTokenSplatParams
        $accessToken = $createEntraAccessTokenResponse.access_token
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
    if ($CertificateAuthentication -eq $true) {
        $certificate = Get-MSEntraCertificate -CertificateBase64String $AppCertificateBase64String -CertificatePassword $AppCertificatePassword
        $entraHeaders = Get-MSEntraAccessToken -Certificate $certificate -TenantID $EntraIDtenantID -AppId $EntraIDAppId
        Write-Information "Successfully created headers using certificate authentication"
    }
    else {
        $entraHeaders = New-AuthorizationHeaders -TenantId $EntraIDtenantID -ClientId $EntraIDAppId -ClientSecret $EntraIDAppSecret
        Write-Information "Successfully created headers using app secret"
    }


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
        if ($CertificateAuthentication -eq $true) {
            $certificate = Get-MSEntraCertificate -CertificateBase64String $AppCertificateBase64String -CertificatePassword $AppCertificatePassword
            $exchangeSessionParams = @{
                Organization     = $EntraIDOrganization
                AppID            = $EntraIDAppId
                Certificate      = $certificate
                ShowBanner       = $false
                ShowProgress     = $false
                TrackPerformance = $false
                ErrorAction      = 'Stop'
            }
            $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams

            Write-Information "Successfully connected to Exchange Online with certificate authentication"
        }
        else {
            # Create Access Token to connect to Exchange Online
            Write-Verbose "Creating Access Token"

            $exoBaseUri = "https://login.microsoftonline.com/"
            $exoAuthUri = $exoBaseUri + "$EntraIDtenantID/oauth2/token"
        
            $exoBody = @{
                Grant_type    = "client_credentials"
                Client_id     = "$EntraIDAppId"
                Client_secret = "$EntraIDAppSecret"
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
            Write-Verbose "Connecting to Exchange Online Tenant [$($EntraIDtenantID)] and Organization [$($EntraIDOrganization)] using App ID [$($EntraIDAppId)]"

            $exchangeSessionParams = @{
                Organization     = $EntraIDOrganization
                AppID            = $EntraIDAppId
                AccessToken      = $exoAccessToken
                ShowBanner       = $false
                ShowProgress     = $false
                TrackPerformance = $false
                ErrorAction      = 'Stop'
            }
            $exchangeSession = Connect-ExchangeOnline @exchangeSessionParams

            Write-Information "Successfully connected to Exchange Online with app secret"
        }
    }
    catch {
        throw "Error connecting to Exchange Online Tenant [$($EntraIDtenantID)] and Organization [$($EntraIDOrganization)] using App ID [$($EntraIDAppId)]. Error: $_"
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

    Write-information "Retrieving permissions ($($systemPermissionOptions -Join ',')) for each mailbox..."
    [System.Collections.ArrayList]$fullAccessUsers = @()
    [System.Collections.ArrayList]$sendAsUsers = @()
    [System.Collections.ArrayList]$sendOnBehalfUsers = @()

    foreach ($systemPermissionOption in $systemPermissionOptions) {
        # Log points the log the status of the script
        $logPoints = @([math]::Ceiling($mailboxes.Count * 0.25), [math]::Ceiling($mailboxes.Count * 0.50), [math]::Ceiling($mailboxes.Count * 0.75))
        $counter = 0

        foreach ($mailbox in $mailboxes) {
            $counter++

            # Logging percentage of the script 
            if ($counter -eq $logPoints[0]) {
                Write-information "Status: 25% ($counter of $($mailboxes.Count)) mailboxes processed for permission: $($systemPermissionOption)."
            }
            elseif ($counter -eq $logPoints[1]) {
                Write-information "Status: 50% ($counter of $($mailboxes.Count)) mailboxes processed for permission: $($systemPermissionOption)."
            }
            elseif ($counter -eq $logPoints[2]) {
                Write-information "Status: 75% ($counter of $($mailboxes.Count)) mailboxes processed for permission: $($systemPermissionOption)."
            }

            switch ($systemPermissionOption) {
                "Full Access" {
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
                    break
                }
                "Send As" {
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
                    break
                }
                "Send On Behalf" {
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
                    break
                }
            }
        }
    }

    Write-Information "Gathered permissions ($($systemPermissionOptions -Join ',')) for each mailbox. Result count: Full Access: $(($fullAccessUsers | Measure-Object).Count). Send As: $(($sendAsUsers | Measure-Object).Count). Send on Behalf: $(($sendOnBehalfUsers | Measure-Object).Count)"
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
    $entitlementsGranted = $entitlementsReport | Where-Object { $_.System -eq $entitlementsSystemName -and $_.EntitlementName -Like "$entitlementsPermissionTypeName - *" }

    # Add GroupName to entitlements since we need to match to the correct groups
    $entitlementsGranted | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $null -Force
    $entitlementsGranted | ForEach-Object {
        # Replace the permission type name so the name matches the actual group in Target system
        # If ($_.EntitlementName -like "*Shared Mailbox*") {
        #     $_.GroupName = $_.EntitlementName -replace "$entitlementsPermissionTypeName - Shared Mailbox - "
        # }
        # elseif ($_.EntitlementName -like "*Distribution Group*") {
        #     $_.GroupName = $_.EntitlementName -replace "$entitlementsPermissionTypeName - Distribution Group - "
        # }
        # elseif ($_.EntitlementName -like "*Mail-enabled Security Group*") {
        #     $_.GroupName = $_.EntitlementName -replace "$evaluationPermissionTypeName - Mail-enabled Security Group - "
        # }
        # else {
        #     $_.GroupName = $_.EntitlementName -replace "$entitlementsPermissionTypeName - "
        # }

        $_.GroupName = $_.EntitlementName -replace "$entitlementsPermissionTypeName - "
    }

    # Transform Entitlements Report into persons with entitlements
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

    $user = $usersGroupedOnCorrelationAttribute[$personCorrelationValue]

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

    if ($null -ne $evaluatedPersonsWithEntitlement) { $evaluatedEntitlements = $evaluatedPersonsWithEntitlement[$person.DisplayName] }

    if ($null -ne $personsWithGrantedEntitlements) { $grantedEntitlements = $personsWithGrantedEntitlements[$person.DisplayName] }


    # Create record(s) for Dummy permission
    foreach ($systemPermissionOption in $systemPermissionOptions) {
        
        if ($addDummyPermission -eq $true) {
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
                mailboxUPN            = "Dummy@dummy.com"
                mailboxName           = "Dummy"
                mailboxDisplayName    = "Dummy"
                permissionType        = $systemPermissionOption
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
    }

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
    if ($null -eq $fullAccessPermissions -and $null -eq $sendAsPermissions -and $null -eq $sendOnBehalfPermissions) { 
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

#region security logging exports
if (($personsWithoutCorrelationValue | Measure-Object).Count -gt 0) {
    Write-Information "Exporting [$(($personsWithoutCorrelationValue | Measure-Object).Count)] personsWithoutCorrelationValue to CSV..." -InformationAction Continue
    $personsWithoutCorrelationValue | Export-Csv -Path "$($exportPath)personsWithoutCorrelationValue.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
}

if (($personsWithoutUser | Measure-Object).Count -gt 0) {
    Write-Information "Exporting [$(($personsWithoutUser | Measure-Object).Count)] personsWithoutUser to CSV..." -InformationAction Continue
    $personsWithoutUser | Export-Csv -Path "$($exportPath)personsWithoutUser.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
}

if (($personsWithoutPermissions | Measure-Object).Count -gt 0) {
    Write-Information "Exporting [$(($personsWithoutPermissions | Measure-Object).Count)] personsWithoutPermissions to CSV..." -InformationAction Continue
    $personsWithoutPermissions | Export-Csv -Path "$($exportPath)personsWithoutPermissions.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
}
#endregion

Write-Information "Exporting [$(($personPermissions | Measure-Object).Count)] personPermissions for [$(($personPermissions | Select-Object -Property displayName, source -Unique | Measure-Object).Count)] persons to CSV..." -InformationAction Continue
$personPermissions | Export-Csv -Path "$($exportPath)personPermissions.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force
