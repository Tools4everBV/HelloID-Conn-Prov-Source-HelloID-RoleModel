<#
.SYNOPSIS

.DESCRIPTION

.NOTES
    Author: Ramon Schouten
    Editor: Remco Houthuijzen
    Created At: 2025-01-29
    Last Edit: 2025-08-12
    Version 1.0 (RS) - initial release 
    Version 1.1 (RH) - added certificate support
#>
# Specify whether to output the logging
$VerbosePreference = 'SilentlyContinue'
$InformationPreference = "Continue"
$WarningPreference = "Continue"

# Define authorization method
$CertificateAuthentication = $false # or $true

# Used to connect to EntraID Graph API, specify the tenant id, app id & app secret
$EntraIDtenantID = "<EntraID_TENANT_ID>"
$EntraIDAppId = "<EntraID_APP_ID>"
$EntraIDAppSecret = "<EntraID_APP_SECRET>"
$AppCertificateBase64String = "<Certificate_Base64_String>"
$AppCertificatePassword = "<Certificate_Password>"

# Toggle to include nested groupmemberships (up to a maximum of 1 layer deep)
$includeNestedGroupMemberships = $true # or $false

# Toggle to add dummy group to result for each person
$addDummyGroup = $true # or $false

# Replace path with your path for vault.json, Evaluation.csv and entitlements.csv.
# Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments
$exportPath = "C:\HelloID\RoleminingExchangeOnline\"

# Optionally, specifiy the parameters below when you want to check the groups against an evaluation report
# The location of the Evaluation Report Csv (needs to be manually exported from a HelloID Provisioning evaluation).
$evaluationReportCsv = $exportPath + "EvaluationReport.csv"
# The name of the system on which to check the permissions in the evaluation (Required when using the evaluation report)
$evaluationSystemName = "Exchange Online"
# The name of the permission type on which to check the permissions in the evaluation (Required when using the entitlements report) (Default for Entra ID is: Group Membership)
$evaluationPermissionTypeName = "Group Membership"

# Optionally, specifiy the parameters below when you want to check the groups against a granted entitlements report
# The location of the Granted Entitlements Csv (needs to be manually exported from a HelloID Provisioning Granted Entitlements).
$grantedEntitlementsCsv = $exportPath + "Entitlements.csv"
# The name of the system on which to check the permissions in the granted entitlements (Required when using the entitlements report)
$entitlementsSystemName = "Exchange Online"
# The name(s) of the permission type on which to check the permissions in the granted entitlements (Required when using the entitlements report) (Default for Entra ID is: Group Membership)
$entitlementsPermissionTypeNames = @("Permission - Mail-enabled Security Group", "Permission - Distribution Group", "Mail-enabled Security Group", "Distribution Group")

# The attribute used to correlate a person to an account
$personCorrelationAttribute = "externalId" # or e.g. "Contact.Business.email"
$userCorrelationAttribute = "employeeId" # or e.g. "userPrincipalName"

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

# Get Entra ID users
try {
    if ($CertificateAuthentication -eq $true) {
        $certificate = Get-MSEntraCertificate -CertificateBase64String $AppCertificateBase64String -CertificatePassword $AppCertificatePassword
        $headers = Get-MSEntraAccessToken -Certificate $certificate -TenantID $EntraIDtenantID -AppId $EntraIDAppId
        Write-Information "Successfully created headers using certificate authentication"
    }
    else {
        $headers = New-AuthorizationHeaders -TenantId $EntraIDtenantID -ClientId $EntraIDAppId -ClientSecret $EntraIDAppSecret
        Write-Information "Successfully created headers using app secret"
    }

    [System.Collections.ArrayList]$entraIdUsers = @()

    # Define the properties to select (comma seperated)
    # Add optional popertySelection (mandatory: id,displayName,userPrincipalName)
    $properties = @("id", "displayName", "userPrincipalName", "accountEnabled", $userCorrelationAttribute)
    $select = "`$select=$($properties -join ",")"

    # Get Microsoft Entra ID users (https://learn.microsoft.com/en-us/graph/api/user-list?view=graph-rest-1.0&tabs=http)
    Write-Verbose "Querying Entra ID users"

    $baseUri = "https://graph.microsoft.com/"
    $splatWebRequest = @{
        Uri     = "$baseUri/v1.0/users?$select"
        Headers = $headers
        Method  = 'GET'
    }
    $getEntraIdUsersResponse = $null
    $getEntraIdUsersResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
    foreach ($entraIdUser in $getEntraIdUsersResponse.value) { $null = $entraIdUsers.Add($entraIdUser) }
    
    while (![string]::IsNullOrEmpty($getEntraIdUsersResponse.'@odata.nextLink')) {
        $baseUri = "https://graph.microsoft.com/"
        $splatWebRequest = @{
            Uri     = $getEntraIdUsersResponse.'@odata.nextLink'
            Headers = $headers
            Method  = 'GET'
        }
        $getEntraIdUsersResponse = $null
        $getEntraIdUsersResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
        foreach ($entraIdUser in $getEntraIdUsersResponse.value) { $null = $entraIdUsers.Add($entraIdUser) }
    }

    Write-Information "Successfully queried Entra ID users. Result count: $($entraIdUsers.Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

    throw "Error querying Entra ID users. Error Message: $($errorMessage.AuditErrorMessage)"
}

$users = $entraIdUsers | Where-Object { [String]::IsNullOrEmpty($_.($userCorrelationAttribute)) -eq $false }
Export-Clixml -Path "$($exportPath)users.xml" -InputObject $users
$usersGrouped = $users | Group-Object $userCorrelationAttribute -AsHashTable
#endregion Retrieve all users

#region Retrieve all groups
Write-Information "Gathering groups..." -InformationAction Continue

# Get Mail-enabled security Groups
try {
    if ($CertificateAuthentication -eq $true) {
        $certificate = Get-MSEntraCertificate -CertificateBase64String $AppCertificateBase64String -CertificatePassword $AppCertificatePassword
        $headers = Get-MSEntraAccessToken -Certificate $certificate -TenantID $EntraIDtenantID -AppId $EntraIDAppId
        Write-Information "Successfully created headers using certificate authentication"
    }
    else {
        $headers = New-AuthorizationHeaders -TenantId $EntraIDtenantID -ClientId $EntraIDAppId -ClientSecret $EntraIDAppSecret
        Write-Information "Successfully created headers using app secret"
    }

    [System.Collections.ArrayList]$mailEnabledSecurityGroups = @()

    # Define the properties to select (comma seperated)
    # Add optinal popertySelection (mandatory: id,displayName,onPremisesSyncEnabled)
    $properties = @("id", "displayName", "onPremisesSyncEnabled", "groupTypes")
    $select = "`$select=$($properties -join ",")"

    # Get Mail-enabled security Groups only (https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http)
    Write-Verbose "Querying Mail-enabled security groups"

    $baseUri = "https://graph.microsoft.com/"
    $mailEnabledSecurityGroupFilter = "`$filter=NOT groupTypes/any(c:c eq 'Unified') and mailEnabled eq true and securityEnabled eq true&`$count=true"
    $splatWebRequest = @{
        Uri     = "$baseUri/v1.0/groups?$mailEnabledSecurityGroupFilter&$select"
        Headers = $headers
        Method  = 'GET'
    }
    $getMailEnabledSecurityGroupsResponse = $null
    $getMailEnabledSecurityGroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
    foreach ($MailEnabledSecurityGroup in $getMailEnabledSecurityGroupsResponse.value) { $null = $mailEnabledSecurityGroups.Add($MailEnabledSecurityGroup) }
    
    while (![string]::IsNullOrEmpty($getMailEnabledSecurityGroupsResponse.'@odata.nextLink')) {
        $baseUri = "https://graph.microsoft.com/"
        $splatWebRequest = @{
            Uri     = $getMailEnabledSecurityGroupsResponse.'@odata.nextLink'
            Headers = $headers
            Method  = 'GET'
        }
        $getMailEnabledSecurityGroupsResponse = $null
        $getMailEnabledSecurityGroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
        foreach ($MailEnabledSecurityGroup in $getMailEnabledSecurityGroupsResponse.value) { $null = $mailEnabledSecurityGroups.Add($MailEnabledSecurityGroup) }
    }

    # Add GroupType property to object
    $mailEnabledSecurityGroups | Add-Member -MemberType NoteProperty -Name "GroupType" -Value $null -Force
    $mailEnabledSecurityGroups | ForEach-Object {
        $_.GroupType = "Mail-enabled security Group"
    }    

    Write-Information "Successfully queried Mail-enabled security groups. Result count: $($mailEnabledSecurityGroups.Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

    throw "Error querying Mail-enabled security Groups. Error Message: $($errorMessage.AuditErrorMessage)"
}

# Get Distribution Groups
try {
    if ($CertificateAuthentication -eq $true) {
        $certificate = Get-MSEntraCertificate -CertificateBase64String $AppCertificateBase64String -CertificatePassword $AppCertificatePassword
        $headers = Get-MSEntraAccessToken -Certificate $certificate -TenantID $EntraIDtenantID -AppId $EntraIDAppId
        Write-Information "Successfully created headers using certificate authentication"
    }
    else {
        $headers = New-AuthorizationHeaders -TenantId $EntraIDtenantID -ClientId $EntraIDAppId -ClientSecret $EntraIDAppSecret
        Write-Information "Successfully created headers using app secret"
    }

    [System.Collections.ArrayList]$distributionGroups = @()

    # Define the properties to select (comma seperated)
    # Add optinal popertySelection (mandatory: id,displayName,onPremisesSyncEnabled)
    $properties = @("id", "displayName", "onPremisesSyncEnabled", "groupTypes")
    $select = "`$select=$($properties -join ",")"

    # Get Distribution Groups only (https://docs.microsoft.com/en-us/graph/api/group-list?view=graph-rest-1.0&tabs=http)
    Write-Verbose "Querying Distribution groups"

    $baseUri = "https://graph.microsoft.com/"
    $distributionGroupFilter = "`$filter=NOT groupTypes/any(c:c eq 'Unified') and mailEnabled eq true and securityEnabled eq false&`$count=true"
    $splatWebRequest = @{
        Uri     = "$baseUri/v1.0/groups?$distributionGroupFilter&$select"
        Headers = $headers
        Method  = 'GET'
    }
    $getDistributionGroupsResponse = $null
    $getDistributionGroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
    foreach ($DistributionGroup in $getDistributionGroupsResponse.value) { $null = $distributionGroups.Add($DistributionGroup) }
    
    while (![string]::IsNullOrEmpty($getDistributionGroupsResponse.'@odata.nextLink')) {
        $baseUri = "https://graph.microsoft.com/"
        $splatWebRequest = @{
            Uri     = $getDistributionGroupsResponse.'@odata.nextLink'
            Headers = $headers
            Method  = 'GET'
        }
        $getDistributionGroupsResponse = $null
        $getDistributionGroupsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
        foreach ($DistributionGroup in $getDistributionGroupsResponse.value) { $null = $distributionGroups.Add($DistributionGroup) }
    }

    # Add GroupType property to object
    $distributionGroups | Add-Member -MemberType NoteProperty -Name "GroupType" -Value $null -Force
    $distributionGroups | ForEach-Object {
        $_.GroupType = "Distribution Group"
    }    

    Write-Information "Successfully queried Distribution groups. Result count: $($distributionGroups.Count)"
}
catch {
    $ex = $PSItem
    $errorMessage = Get-ErrorMessage -ErrorObject $ex

    Write-Verbose "Error at Line '$($ex.InvocationInfo.ScriptLineNumber)': $($ex.InvocationInfo.Line). Error: $($errorMessage.VerboseErrorMessage)"

    throw "Error querying Distribution Groups. Error Message: $($errorMessage.AuditErrorMessage)"
}

$groups = $mailEnabledSecurityGroups + $distributionGroups
Export-Clixml -Path "$($exportPath)groups.xml" -InputObject $groups
$groupsGrouped = $groups | Group-Object id -AsString -AsHashTable
#endregion Retrieve all groups

# Get nested group memberships
if ($IncludeNestedGroupMemberships -eq $true) {
    # Retrieve the membership of groups, requires fetch per group
    try {
        Write-Information "Retrieving group memberships for each group..." -InformationAction Continue

        # Log points the log the status of the script
        $logPoints = @([math]::Ceiling($groups.Count * 0.25), [math]::Ceiling($groups.Count * 0.50), [math]::Ceiling($groups.Count * 0.75))
        $counter = 0

        # Create list of all groups with their group memberships
        $GroupsWithMemberships = [System.Collections.ArrayList]::new()

        foreach ($group in $groups) {
            $counter++

            # Logging percentage of the script 
            if ($counter -eq $logPoints[0]) {
                Write-information "Status: 25% ($counter of $($groups.Count)) groups processed."
            }
            elseif ($counter -eq $logPoints[1]) {
                Write-information "Status: 50% ($counter of $($groups.Count)) groups processed."
            }
            elseif ($counter -eq $logPoints[2]) {
                Write-information "Status: 75% ($counter of $($groups.Count)) groups processed."
            }

            #region Get groups's memberships
            # API docs: https://learn.microsoft.com/en-us/graph/api/group-list-memberof?view=graph-rest-1.0&tabs=http
            $getEntraIDGroupMembershipsSplatParams = @{
                Uri         = "https://graph.microsoft.com/v1.0/groups/$($group.id)/memberof"
                Headers     = $headers
                Method      = "GET"
                Verbose     = $false
                ErrorAction = "Stop"
            }

            $getEntraIDGroupMembershipsResponse = $null
            $getEntraIDGroupMembershipsResponse = Invoke-RestMethod @getEntraIDGroupMembershipsSplatParams
            $groupMembers = $getEntraIDGroupMembershipsResponse.Value
            #endregion

            foreach ($groupMember in $groupMembers) {
                # Create custom object for group with group membership
                $GroupCustomObject = [PSCustomObject]@{
                    ParentGroupName = $group.displayName
                    ParentGroupGuid = $group.id
                    ChildGroupName  = $groupMember.displayName
                    ChildGroupGuid  = $groupMember.id
                }

                # Add the custom object for group with group membership to list of all groups with their group memberships
                [void]$GroupsWithMemberships.Add($GroupCustomObject)
            }
        }

        Write-Information "Gathered group memberships for each group. Result count: $(($UsersWithMemberships | Measure-Object).Count)" -InformationAction Continue
    }
    catch {
        Write-Error $_.Exception
    }

    $groupsWithMemberOf = $null
    $groupsWithMemberOf = $GroupsWithMemberships | Group-Object -Property "ParentGroupGuid" -AsString -AsHashTable
}

# Retrieve the membership of users, requires fetch per user
try {
    Write-Information "Retrieving group memberships for each user..." -InformationAction Continue

    # Log points the log the status of the script
    $logPoints = @([math]::Ceiling($Users.Count * 0.25), [math]::Ceiling($Users.Count * 0.50), [math]::Ceiling($Users.Count * 0.75))
    $counter = 0

    # Create list of all users with their group memberships
    $UsersWithMemberships = [System.Collections.ArrayList]::new()

    foreach ($User in $Users) {
        $counter++

        # Logging percentage of the script 
        if ($counter -eq $logPoints[0]) {
            Write-information "Status: 25% ($counter of $($Users.Count)) users processed."
        }
        elseif ($counter -eq $logPoints[1]) {
            Write-information "Status: 50% ($counter of $($Users.Count)) users processed."
        }
        elseif ($counter -eq $logPoints[2]) {
            Write-information "Status: 75% ($counter of $($Users.Count)) users processed."
        }

        #region Get user's memberships
        [System.Collections.ArrayList]$userMemberships = @()
        # API docs: https://learn.microsoft.com/en-us/graph/api/user-list-memberof?view=graph-rest-1.0&tabs=http
        $getEntraIDUserMembershipsSplatParams = @{
            Uri         = "https://graph.microsoft.com/v1.0/users/$($user.id)/memberOf"
            Headers     = $headers
            Method      = "GET"
            Verbose     = $false
            ErrorAction = "Stop"
        }

        $getEntraIDUserMembershipsResponse = $null
        $getEntraIDUserMembershipsResponse = Invoke-RestMethod @getEntraIDUserMembershipsSplatParams
        foreach ($SecurityGroup in $getEntraIDUserMembershipsResponse.value) { $null = $userMemberships.Add($SecurityGroup) }

        while (![string]::IsNullOrEmpty($getEntraIDUserMembershipsResponse.'@odata.nextLink')) {
            $baseUri = "https://graph.microsoft.com/"
            $splatWebRequest = @{
                Uri     = $getEntraIDUserMembershipsResponse.'@odata.nextLink'
                Headers = $headers
                Method  = 'GET'
            }
            $getEntraIDUserMembershipsResponse = $null
            $getEntraIDUserMembershipsResponse = Invoke-RestMethod @splatWebRequest -Verbose:$false
            foreach ($SecurityGroup in $getEntraIDUserMembershipsResponse.value) { $null = $userMemberships.Add($SecurityGroup) }
        }
        #endregion

        foreach ($userMembership in $userMemberships) {
            if ($groupsGrouped.ContainsKey("$($userMembership.id)")) {           
                # Create custom object for user with group membership
                $UserCustomObject = [PSCustomObject]@{
                    UserName        = $User.displayName
                    UserGuid        = $User.id
                    GroupName       = $userMembership.displayName
                    GroupGuid       = $userMembership.id
                    IsNested        = $false
                    "Member/Parent" = $null
                }

                # Add the custom object for user with group membership to list of all users with their group memberships
                [void]$UsersWithMemberships.Add($UserCustomObject)

                if ($IncludeNestedGroupMemberships -eq $true) {
                    if ($null -ne $groupsWithMemberOf -and $groupsWithMemberOf.ContainsKey("$($userMembership.id)")) {
                        $groupMembers = $groupsWithMemberOf["$($userMembership.id)"]

                        foreach ($groupMember in $groupMembers) {
                            # Create custom object for user with group membership
                            $UserCustomObject = [PSCustomObject]@{
                                UserName        = $User.displayName
                                UserGuid        = $User.id
                                GroupName       = $groupMember.ChildGroupName
                                GroupGuid       = $groupMember.ChildGroupGuid
                                IsNested        = $true
                                "Member/Parent" = $groupMember.ParentGroupName
                            }
    
                            # Add the custom object for user with group membership to list of all users with their group memberships
                            [void]$UsersWithMemberships.Add($UserCustomObject)
                        }
                    }
                }
            }
        }
    }

    Write-Information "Gathered group memberships for each user. Result count: $(($UsersWithMemberships | Measure-Object).Count)" -InformationAction Continue
}
catch {
    Write-Error $_.Exception
}

$usersWithMemberOf = $UsersWithMemberships | Group-Object -Property "UserGuid" -AsString -AsHashTable

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
    
    $permissions = $usersWithMemberOf["$($user.id)"]
    
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
            $dummyRecord | Add-Member -MemberType NoteProperty -Name "Member/Parent" -Value $null -Force
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
        $group = $groupsGrouped[$permission.GroupGuid]

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
            $record | Add-Member -MemberType NoteProperty -Name "Member/Parent" -Value $permission."Member/Parent" -Force
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
