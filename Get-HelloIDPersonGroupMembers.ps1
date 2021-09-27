<#
.SYNOPSIS

.DESCRIPTION

.NOTES
    Author: Arnout van der Vorst
    Editor: Ramon Schouten
    Last Edit: 2021-07-07
    Version 1.0 - initial release
    Version 1.0.1 - Minor updates
    Version 1.1.0 - Added enhancements for checks on evaluation report export and granted entitlements export
#>
# Specify whether to output the verbose logging
$verboseLogging = $false

# Specify the tenant urlapi key, secret
$tenantUri = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
# Filter the accounts and groups in the HelloID directory based on a single filter
$source = "enyoi.local"
# Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments
$exportPath = "C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\"

# The location of the Vault export in JSON format (needs to be manually exported from a HelloID Provisioning snapshot).
$vaultJson = "C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\JSON_file_export\vault.json"

# Optionally, specifiy the parameters below when you want to check the groups against an evaluation report
# The location of the Evaluation Report Csv (needs to be manually exported from a HelloID Provisioning evaluation).
$evaluationReportCsv = "C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\Evaluation_Summary_export\EvaluationReport.csv"
# The name of the system on which to check the permissions in the evaluation (Required when using the evaluation report)
$evaluationSystemName = "Microsoft Active Directory"

# Optionally, specifiy the parameters below when you want to check the groups against a granted entitlements report
# The location of the Granted Entitlements Csv (needs to be manually exported from a HelloID Provisioning Granted Entitlements).
$grantedEntitlementsCsv = "C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\Entitlements_export\Entitlements.csv"
# The name of the system on which to check the permissions in the evaluation (Required when using the entitlements report)
$entitlementsSystemName = "Microsoft Active Directory"

# The attribute used to correlate a person to an account
$personCorrelationAttribute = "ExternalId"
$userCorrelationAttribute = "employeeId"

# Basic api uri config
$uriUsers = $tenantUri + "/api/v1/users"
$uriGroups = $tenantUri + "/api/v1/groups"

# Construct the auth header
$pair = "${apiKey}:${apiSecret}"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"
$headers = @{ Authorization = $basicAuthValue }

# Set TLS to accept TLS, TLS 1.1 and TLS 1.2
[Net.ServicePointManager]::SecurityProtocol = [Net.SecurityProtocolType]::Tls -bor [Net.SecurityProtocolType]::Tls11 -bor [Net.SecurityProtocolType]::Tls12

Function Get-StringHash([String] $String, $HashName = "MD5") {
    $StringBuilder = New-Object System.Text.StringBuilder

    [System.Security.Cryptography.HashAlgorithm]::Create($HashName).ComputeHash([System.Text.Encoding]::UTF8.GetBytes($String)) | ForEach-Object {
        [Void]$StringBuilder.Append($_.ToString("x2"))
    }

    $StringBuilder.ToString()
}

# Default function to get paged connector data
function Get-RESTAPIPagedData {
    param(
        [parameter(Mandatory = $true)]$BaseUri,
        [parameter(Mandatory = $true)]$Headers,
        [parameter(Mandatory = $true)][ref]$data
    )

    try {
        $take = 100
        $skip = 0

        $uri = $BaseUri + "?skip=$skip&take=$take"
        $dataset = Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -UseBasicParsing
        Write-Verbose -Verbose:$verboseLogging "Getting data from $uri"

        foreach ($record in $dataset) { [void]$data.Value.add($record) }

        $skip += $take
        while ($dataset.Count -eq $take){
            $uri = $BaseUri + "?skip=$skip&take=$take"

            Write-Verbose -Verbose:$verboseLogging "Getting data from $uri"
            $dataset = Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -UseBasicParsing
            Start-Sleep -Milliseconds 50

            $skip += $take

            foreach ($record in $dataset) { [void]$data.Value.add($record) }
        }
    }
    catch {
        $data.Value = $null
        Write-Error $_.Exception
    }
}

function Get-HelloIDGroupsWithMembers {
    param(
        [parameter(Mandatory = $true)]$Groups,
        [parameter(Mandatory = $true)]$Users,
        [parameter(Mandatory = $true)][ref]$groupsWithMembers
    )

    try {
        Write-Information "Retrieving group memberships for each HelloID group..." -InformationAction Continue

        $UsersGrouped = $Users | Group-Object userGuid -AsHashTable

        # Retrieve the membership of groups, requires fetch per group
        foreach ($group in $Groups) {
            $uriGroup = $uriGroups + "/" + $group.groupGuid
            Write-Verbose -Verbose:$verboseLogging "Getting group from $uriGroup"
            $groupAugmented = Invoke-RestMethod -Method Get -Uri $uriGroup -Headers $headers -UseBasicParsing
            $groupAugmented = $groupAugmented | Select-Object groupGuid, name, users

            $groupAugmented | Add-Member -MemberType NoteProperty -Name "usersResolved" -Value $null -Force

            $usersResolved = New-Object System.Collections.ArrayList

            foreach ($user in $groupAugmented.users) {
                $userResolved = $UsersGrouped[$user] | Select-Object -First 1 -Property userName, userGuid

                [void]$usersResolved.Add($userResolved)
            }

            $groupAugmented.usersResolved = $usersResolved

            [void]$groupsWithMembers.Value.Add($groupAugmented)
        }
    }
    catch {
        $groupsWithMembers.Value = $null
        Write-Error $_.Exception
    }
}

function Invoke-TransformMembershipsToMemberOf {
    param(
        [parameter(Mandatory = $true)]$GroupsWithMembers,
        [parameter(Mandatory = $true)][ref]$usersWithMemberOf
    )

    try {
        Write-Information "Transforming group memberships to users with memberOf..." -InformationAction Continue

        foreach ($record in $GroupsWithMembers) {
            foreach ($userGuid in $record.users) {
                $userWithMemberOf = [PSCustomObject]@{
                    userGuid = $userGuid
                    memberOf = $record.groupGuid
                }

                [void]$usersWithMemberOf.Value.Add($userWithMemberOf)
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

            $record = [PSCustomObject]@{
                externalId            = $person.($personCorrelationAttribute)
                displayName           = $person.DisplayName
                contractExternalId    = $person.PrimaryContract.ExternalId
                departmentId          = $person.PrimaryContract.Department.ExternalId
                departmentCode        = $person.PrimaryContract.Department.Code
                departmentDescription = $person.PrimaryContract.Department.DisplayName
                titleId               = $person.PrimaryContract.Title.ExternalId
                titleCode             = $person.PrimaryContract.Title.Code
                titleDescription      = $person.PrimaryContract.Title.Name
                contractIsPrimary     = $true
                startDate             = [DateTime]$person.PrimaryContract.StartDate
                endDate               = $endDate
            }
            [void]$ExpandedPersons.Value.Add($record)

            foreach ($contract in $person.Contracts) {
                if ($contract.ExternalId -eq $person.PrimaryContract.ExternalId) { continue; }

                if ($null -eq $contract.EndDate) {
                    $endDate = Get-Date -Date "2199-01-01 00:00:00"
                    $endDate = $endDate.AddDays(1).AddSeconds(-1)
                }

                $record = [PSCustomObject]@{
                    externalId            = $person.($personCorrelationAttribute)
                    displayName           = $person.DisplayName
                    contractExternalId    = $contract.ExternalId
                    departmentId          = $contract.Department.ExternalId
                    departmentCode        = $contract.Department.Code
                    departmentDescription = $contract.Department.DisplayName
                    titleId               = $contract.Title.ExternalId
                    titleCode             = $contract.Title.Code
                    titleDescription      = $contract.Title.Name
                    contractIsPrimary     = $false
                    startDate             = [DateTime]$contract.StartDate
                    endDate               = $endDate
                }
                [void]$ExpandedPersons.Value.Add($record)
            }
        }
    }
    catch {
        Write-Error $_.Exception
    }
}


# Retrieve all persons
Write-Information "Gathering persons..." -InformationAction Continue
$snapshot = Get-Content -Path $vaultJson -Encoding UTF8 | ConvertFrom-Json
$persons = $snapshot.Persons

# Expand persons with contracts
$expandedPersons = New-Object System.Collections.ArrayList
Expand-Persons -Persons $snapshot.Persons ([ref]$ExpandedPersons)

# Retrieve all users
Write-Information "Gathering users..." -InformationAction Continue
$users = New-Object System.Collections.ArrayList
Get-RESTAPIPagedData -BaseUri $uriUsers -Headers $headers ([ref]$users)
$users = $users | Where-Object { $_.source -eq $source }
$users = $users | Where-Object { $_.isDeleted -eq $False }
$users = $users | Select-Object userGuid, userName, isEnabled -ExpandProperty userAttributes
$users = $users | Where-Object { [String]::IsNullOrEmpty($_.($userCorrelationAttribute)) -eq $false }
Export-Clixml -Path "$($exportPath)users.xml" -InputObject $users
$usersGrouped = $users | Group-Object $userCorrelationAttribute -AsHashTable

# Retrieve all groups
Write-Information "Gathering groups..." -InformationAction Continue
$groups = New-Object System.Collections.ArrayList
Get-RESTAPIPagedData -BaseUri $uriGroups -Headers $headers ([ref]$groups)
$groups = $groups | Where-Object { $_.source -eq $source }
$groups = $groups | Where-Object { $_.isDeleted -eq $False }
$groups = $groups | Where-Object { $_.isEnabled -eq $True }
Export-Clixml -Path "$($exportPath)groups.xml" -InputObject $groups
$groupsGrouped = $groups | Group-Object groupGuid -AsHashTable

# Retrieve the membership of groups, requires fetch per group
$groupsWithMembers = New-Object System.Collections.ArrayList
Get-HelloIDGroupsWithMembers -Groups $groups -Users $users ([ref]$groupsWithMembers)
Export-Clixml -Path "$($exportPath)groupsWithMembers.xml" -InputObject $groupsWithMembers
$groupsWithMembers = Import-Clixml -Path "$($exportPath)groupsWithMembers.xml"

# Transform group memberships into users with memberOf
$usersWithMemberOf = New-Object System.Collections.ArrayList
Invoke-TransformMembershipsToMemberOf -GroupsWithMembers $groupsWithMembers ([ref]$usersWithMemberOf)
Export-Clixml -Path "$($exportPath)usersWithMemberOf.xml" -InputObject $usersWithMemberOf
$usersWithMemberOf = $usersWithMemberOf | Group-Object "userGuid" -AsHashTable

$personPermissions = New-Object System.Collections.ArrayList

# Retrieve evalution
if(-not[string]::IsNullOrEmpty($evaluationReportCsv)){
    Write-Information "Gathering data from evaluation report export..." -InformationAction Continue
    $evaluationReport = Import-Csv -Path $evaluationReportCsv -Delimiter "," -Encoding UTF8
    $evaluationPermissions = $evaluationReport | Where-Object {$_.System -eq $evaluationSystemName -and $_.Type -eq "Permission" -and $_.Operation -eq "Grant"}

    # Add GroupName to evaluation since we need to match to the correct groups
    $evaluationPermissions | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $null -Force
    $evaluationPermissions | ForEach-Object {
        $groupPathMatch = $_.EntitlementName -match '\((.*?)\)'
        if(-not[string]::IsNullOrEmpty($matches)){
            $groupPath = $matches[1] # second index, because the first matches value includes ()
            $groupName = ($groupPath -split '/')[-1]
            $_.GroupName = $groupName
        }
    }

    # Transform Evaluation Report into persons with entitlements
    $evaluatedPersonsWithEntitlement = $null
    $evaluatedPersonsWithEntitlement = $evaluationPermissions | Group-Object "Person" -AsHashTable
}

# Retrieve entitlements
if(-not[string]::IsNullOrEmpty($grantedEntitlementsCsv)){
    Write-Information "Gathering data from granted entitlements export..." -InformationAction Continue
    $entitlementsReport = Import-Csv -Path $grantedEntitlementsCsv -Delimiter "," -Encoding UTF8
    $entitlementsGranted = $entitlementsReport | Where-Object {$_.System -eq $entitlementsSystemName -and $_.Status -eq "Granted" }

    # Add GroupName to evaluation since we need to match to the correct groups
    $entitlementsGranted | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $null -Force
    $entitlementsGranted | ForEach-Object {
        $groupPathMatch = $_.EntitlementName -match '\((.*?)\)'
        if(-not[string]::IsNullOrEmpty($matches)){
            $groupPath = $matches[1] # second index, because the first matches value includes ()
            $groupName = ($groupPath -split '/')[-1]
            $_.GroupName = $groupName
        }
    }

    # Transform Evaluation Report into persons with entitlements
    $personsWithGrantedEntitlements = $null
    $personsWithGrantedEntitlements = $entitlementsGranted | Group-Object "Person" -AsHashTable
}

foreach ($person in $expandedPersons) {
    $user = $usersGrouped[$person.externalId]

    if ($null -eq $user) { continue; }

    $permissions = $usersWithMemberOf[$user.userGUID]

    if ($null -eq $permissions) { continue; }

    # Get evaluated entitlements for person
    if($null -ne $evaluatedPersonsWithEntitlement){ $evaluatedEntitlements = $evaluatedPersonsWithEntitlement[$person.DisplayName] }

    # Get granted entitlements for person
    if($null -ne $personsWithGrantedEntitlements){ $grantedEntitlements = $personsWithGrantedEntitlements[$person.DisplayName] }

    foreach ($permission in $permissions) {
        $group = $groupsGrouped[$permission.memberOf]

        if ($null -eq $group) { continue; }
        
        # Check if group is in evaluation
        if($group.name -in $evaluatedEntitlements.GroupName){
            $inEvaluation = $true
        }else{
            $inEvaluation = $false
        }

        # Check if group is in granted entitlements
        if($group.name -in $grantedEntitlements.GroupName){
            $isGranted = $true
        }else{
            $isGranted = $false
        }

        $record = [PSCustomObject]@{
            externalId              = $person.externalId
            displayName             = $person.displayName
            departmentId            = $person.departmentId
            departmentCode          = $person.departmentCode
            departmentDescription   = $person.departmentDescription
            titleId                 = $person.titleId
            titleCode               = $person.titleCode
            titleDescription        = $person.titleDescription
            contractIsPrimary       = $person.contractIsPrimary
            startDate               = $person.startDate
            endDate                 = $person.endDate
            userName                = $user.userName
            isEnabled               = $user.isEnabled
            permission              = $group.name
            inEvaluation            = $inEvaluation
            isGranted               = $isGranted
        }

        [void]$personPermissions.Add($record)
    }
}

Write-Information "Exporting data to CSV..." -InformationAction Continue
$personPermissions | Export-Csv -Path "$($exportPath)personPermissions.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force