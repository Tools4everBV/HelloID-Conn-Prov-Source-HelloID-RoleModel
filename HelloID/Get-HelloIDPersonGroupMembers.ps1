<#
.SYNOPSIS

.DESCRIPTION

.NOTES
    Author: Arnout van der Vorst
    Editor: Jeroen Smit
    Last Edit: 2024-03-25
    Version 1.0 - initial release
    Version 1.0.1 - Minor updates
    Version 1.1.0 - Added enhancements for checks on evaluation report export and granted entitlements export
    Version 1.1.1 - Added enhancements for nested groupmemberships (1 layer deep), additional source properties to inclued and minor fixes
    Version 1.1.2 - Added dynamic correlation attribute
    Version 1.1.3 - Added support for helloid user custom attributes in correlation
    Version 1.1.4 - Added status active for the employee
    Version 1.1.5 - Added support for no startdate per employee
    Version 1.1.6 - Added reporting for persons with no correlation attribute, persons with no account or accounts with no permissions
    Version 1.1.7 - Fix column 'Status' is removed from export 'entilements.csv'
#>
# Specify whether to output the verbose logging
$verboseLogging = $false

# Specify the tenant urlapi key, secret
$tenantUri = "https://<CUSTOMER>.helloid.com"
$apiKey = "<API_KEY>"
$apiSecret = "API_SECRET"
# Filter the accounts and groups in the HelloID directory based on a single filter
$source = "enyoi.local"

# Toggle to include nested groupmemberships (up to a maximum of 1 layer deep)
$includeNestedGroupMemberships = $true # or $false

# Replace path with your path for vault.json, Evaluation.csv and entitlements.csv.
# Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments
$exportPath = "C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\"

# Optionally, specifiy the parameters below when you want to check the groups against an evaluation report
# The location of the Evaluation Report Csv (needs to be manually exported from a HelloID Provisioning evaluation).
$evaluationReportCsv = $exportPath + "Evaluation.csv"
# The name of the system on which to check the permissions in the evaluation (Required when using the evaluation report)
$evaluationSystemName = "Microsoft Active Directory"
# The name of the permission type on which to check the permissions in the evaluation (Required when using the entitlements report) (Default for AD and Azure AD is: Group Membership)
$evaluationPermissionTypeName = "Group Membership"

# Optionally, specifiy the parameters below when you want to check the groups against a granted entitlements report
# The location of the Granted Entitlements Csv (needs to be manually exported from a HelloID Provisioning Granted Entitlements).
$grantedEntitlementsCsv = $exportPath + "Entitlements.csv"
# The name of the system on which to check the permissions in the evaluation (Required when using the entitlements report)
$entitlementsSystemName = "Microsoft Active Directory"
# The name of the permission type on which to check the permissions in the evaluation (Required when using the entitlements report) (Default for AD and Azure AD is: Group Membership)
$entitlementsPermissionTypeName = "Group Membership"

# The attribute used to correlate a person to an account
$personCorrelationAttribute = "Contact.Business.Email" # or e.g. "externalId"
$userCorrelationAttribute = "contactEmail" # or e.g. "userAttributes.EmployeeID"

# The location of the Vault export in JSON format (needs to be manually exported from a HelloID Provisioning snapshot).
$vaultJson = $exportPath + "vault.json"
# Specify the Person fields from the HelloID Vault export to include in the report (These have to match the exact name from he Vault.json export) - Must always contains personCorrelationAttribute!
$personPropertiesToInclude = @($personCorrelationAttribute, "source.displayname", "custom.locatie")
# Specify the Contracts fields from the HelloID Vault export to include in the report (These have to match the exact name from he Vault.json export)
$contractPropertiesToInclude = @("costCenter.displayname", "custom.locatie", "Costcenter.name")

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
        while ($dataset.Count -eq $take) {
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
            $groupAugmented = $groupAugmented | Select-Object groupGuid, name, users, groups

            $groupAugmented | Add-Member -MemberType NoteProperty -Name "usersResolved" -Value $null -Force
            $usersResolved = New-Object System.Collections.ArrayList
            foreach ($user in $groupAugmented.users) {
                $userResolved = $UsersGrouped[$user] | Select-Object -First 1 -Property userName, userGuid

                [void]$usersResolved.Add($userResolved)
            }

            $groupAugmented.usersResolved = $usersResolved

            if ($includeNestedGroupMemberships -eq $true) {
                $groupAugmented | Add-Member -MemberType NoteProperty -Name "groupsResolved" -Value $null -Force
                $groupsResolved = New-Object System.Collections.ArrayList
                foreach ($group in $groupAugmented.groups) {
                    $groupResolved = $groupsGrouped[$group] | Select-Object -First 1 -Property name, groupGuid

                    [void]$groupsResolved.Add($groupResolved)
                }
                $groupAugmented.groupsResolved = $groupsResolved
            }

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

        foreach ($record in $GroupsWithMembers | Where-Object { ![String]::IsNullOrEmpty($_.users) } ) {
            foreach ($userGuid in $record.users) {
                $userWithMemberOf = [PSCustomObject]@{
                    userGuid    = $userGuid
                    memberOf    = $record.groupGuid
                    isNested    = $false
                    parentGroup = $null
                }

                [void]$usersWithMemberOf.Value.Add($userWithMemberOf)
            }
        }

        if ($includeNestedGroupMemberships -eq $true) {
            $usersWithMemberOfGrouped = $usersWithMemberOf.Value | Group-Object memberOf -AsHashTable

            foreach ($record in $GroupsWithMembers | Where-Object { ![String]::IsNullOrEmpty($_.groups) } ) {
                foreach ($groupGuid in $record.groups) {
                    foreach ($userGuid in $usersWithMemberOfGrouped[$groupGuid].userGuid) {
                        $userWithMemberOf = [PSCustomObject]@{
                            userGuid    = $userGuid
                            groupGuid   = $groupGuid
                            memberOf    = $record.groupGuid
                            isNested    = $true
                            parentGroup = $groupsGrouped[$groupGuid].name
                        }

                        [void]$usersWithMemberOf.Value.Add($userWithMemberOf)
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
if ($userCorrelationAttribute.ToLower() -Like "userattributes.*") {
    $users = $users | Select-Object userGuid, userName, isEnabled -ExpandProperty userAttributes
    $userCorrelationAttribute = $userCorrelationAttribute.ToLower().replace("userattributes.", "")
}
else {
    $users = $users | Select-Object userGuid, userName, isEnabled, $userCorrelationAttribute -ExpandProperty userAttributes
}
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
if (-not[string]::IsNullOrEmpty($evaluationReportCsv)) {
    Write-Information "Gathering data from evaluation report export..." -InformationAction Continue
    $evaluationReport = Import-Csv -Path $evaluationReportCsv -Delimiter "," -Encoding UTF8
    $evaluationPermissions = $evaluationReport | Where-Object { $_.System -eq $evaluationSystemName -and $_.Type -eq "Permission" -and $_.Operation -eq "Grant" -and $_.EntitlementName -Like "$evaluationPermissionTypeName - *" }

    # Add GroupName to evaluation since we need to match to the correct groups
    $evaluationPermissions | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $null -Force
    $evaluationPermissions | ForEach-Object {

        # If Target system is AD, the entitlement contains the CannonicalName between brackets, so this needs some regex to filter this out
        if ($_.System -eq "Microsoft Active Directory") {
            # First apply regex to match for groups with brackets
            $groupNameMatches = [regex]::Matches($_.EntitlementName, '\(.*?\)\)')
            if (-not[String]::IsNullOrEmpty($groupNameMatches)) {
                # If multiple brackets are found, additional actions are required to sanitize the groupname, such as replacing "))" with ")"
                $groupName = (($groupNameMatches -split '/')[-1]).Replace("))", ")")
                $_.GroupName = $groupName -replace "$evaluationPermissionTypeName - "
            }
            else {
                # If no matches are found, apply regex to match for groups without brackets
                $groupNameMatches = [regex]::Matches($_.EntitlementName, '\(.*?\)')
                # If a match is found, additional actions are required to sanitize the groupname, such as removing the trailing ")"
                $groupName = (($groupNameMatches -split '/')[-1]).Replace(")", "")
                $_.GroupName = $groupName -replace "$evaluationPermissionTypeName - "
            }
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

    # Add GroupName to evaluation since we need to match to the correct groups
    $entitlementsGranted | Add-Member -MemberType NoteProperty -Name "GroupName" -Value $null -Force
    $entitlementsGranted | ForEach-Object {

        # If Target system is AD, the entitlement contains the CannonicalName between brackets, so this needs some regex to filter this out
        if ($_.System -eq "Microsoft Active Directory") {
            try {
                # First apply regex to match for groups with brackets
                $groupNameMatches = [regex]::Matches($_.EntitlementName, '\(.*?\)\)')
                if (-not[String]::IsNullOrEmpty($groupNameMatches)) {
                    # If multiple brackets are found, additional actions are required to sanitize the groupname, such as replacing "))" with ")"
                    $groupName = (($groupNameMatches -split '/')[-1]).Replace("))", ")")
                    $_.GroupName = $groupName -replace "$entitlementsPermissionTypeName - "
                }
                else {
                    # If no matches are found, apply regex to match for groups without brackets
                    $groupNameMatches = [regex]::Matches($_.EntitlementName, '\(.*?\)')
                    # If a match is found, additional actions are required to sanitize the groupname, such as removing the trailing ")"
                    $groupName = (($groupNameMatches -split '/')[-1]).Replace(")", "")
                    $_.GroupName = $groupName -replace "$entitlementsPermissionTypeName - "
                }
            }
            catch {
                Write-Error $_
            }
        }
        else {
            $_.GroupName = $_.EntitlementName -replace "$entitlementsPermissionTypeName - "
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
        Write-Verbose -Verbose "Person $($person.displayName) has no value for correlation attribute: $personCorrelationProperty"
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
        Write-Verbose -verbose "No user found where $($userCorrelationAttribute) = $($personCorrelationValue) for person $($person.displayName)"
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

    $permissions = $usersWithMemberOf[$user.userGUID]

    if ($null -eq $permissions) { 
        Write-Verbose -verbose "No permission(s) found where Userguid = $($user.id) for person $($person.displayName)"
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
        if ($group.name -in $evaluatedEntitlements.GroupName) {
            $inEvaluation = $true
        }
        else {
            $inEvaluation = $false
        }

        # Check if group is in granted entitlements
        if ($group.name -in $grantedEntitlements.GroupName) {
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
            startDate             = ($person.startDate).ToString('yyyy-MM-dd')
            endDate               = ($person.endDate).ToString('yyyy-MM-dd')
            isActive              = $person.isActive
            userName              = $user.userName
            isEnabled             = $user.isEnabled
            permission            = $group.name
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