<#
.SYNOPSIS

.DESCRIPTION

.NOTES
    Author: Jeroen Smit
    Last Edit: 2023-08-22
    Version 1.0 - initial release
#>
# Specify whether to output the verbose logging
#$verboseLogging = $false

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
$personCorrelationAttribute = "externalId"
$userCorrelationAttribute = "EmployeeID"

# The location of the Vault export in JSON format (needs to be manually exported from a HelloID Provisioning snapshot).
$vaultJson = $exportPath + "vault.json"
# Specify the Person fields from the HelloID Vault export to include in the report (These have to match the exact name from he Vault.json export) - Must always contains personCorrelationAttribute!
$personPropertiesToInclude = @($personCorrelationAttribute, "source.displayname", "custom.locatie")
# Specify the Contracts fields from the HelloID Vault export to include in the report (These have to match the exact name from he Vault.json export)
$contractPropertiesToInclude = @("costCenter.displayname", "Costcenter.name", "custom.locatie")

function Get-ADGroupsWithMembers {
    param(
        [parameter(Mandatory = $true)]$Groups,
        [parameter(Mandatory = $true)]$Users,
        [parameter(Mandatory = $true)][ref]$groupsWithMembers
    )

    try {

        Write-Information "Retrieving group memberships for each AD group..." -InformationAction Continue

        # Retrieve the membership of groups,  
        foreach ($group in $groups) {
    
            # Retrieve members per group
            $usersGrouped = New-Object System.Collections.ArrayList  
            $groupsGrouped = New-Object System.Collections.ArrayList

            $usersWithinGroup = Get-ADGroupMember -Identity $group.ObjectGUID          
            
            # Check if the member is an user or a group
            foreach ($userWithinGroup in $usersWithinGroup) {
                If ($userWithinGroup.objectClass -eq "user") {
                    $userWithinGroup = $userWithinGroup.objectGUID.ToString()
                
                    [void]$usersGrouped.Add($userWithinGroup)
                
                }
                elseif ($userWithinGroup.objectClass -eq "group") {
                    $groupWithinGroup = $userWithinGroup.objectGUID.ToString()
                
                    [void]$groupsGrouped.Add($groupWithinGroup)
                }
            }
                
            $groupWithMembers = [PSCustomObject]@{
                groupGuid = $group.ObjectGUID
                name      = $group.Name
                users     = $usersGrouped
                groups    = $groupsGrouped
            }
                   
            [void]$groupsWithMembers.Value.Add($groupWithMembers)
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
            $usersWithMemberOfGrouped = $usersWithMemberOf.Value | Group-Object -Property memberOf -AsString -AsHashTable

            foreach ($record in $GroupsWithMembers | Where-Object { ![String]::IsNullOrEmpty($_.groups) } ) {
                foreach ($groupGuid in $record.groups) {
                    foreach ($userGuid in $usersWithMemberOfGrouped[$groupGuid].userGuid) {
                        $userWithMemberOf = [PSCustomObject]@{
                            userGuid    = $userGuid
                            groupGuid   = $groupGuid
                            memberOf    = $record.groupGuid
                            isNested    = $true
                            parentGroup = $groupsGrouped[$groupGuid].Name
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
$users = Get-aduser -Filter { (ObjectClass -eq 'user') } -Properties DisplayName, EmployeeID, EmployeeNumber, MemberOf, SamAccountName, UserPrincipalName
$users = $users | Where-Object { $_.Enabled -eq $true }
$users = $users | Where-Object { [String]::IsNullOrEmpty($_.($userCorrelationAttribute)) -eq $false }
$usersGrouped = $users | Group-Object -Property $userCorrelationAttribute -AsString -AsHashTable

# Retrieve all groups
Write-Information "Gathering groups..." -InformationAction Continue
$groups = New-Object System.Collections.ArrayList
$groups = Get-ADGroup -Filter * | Select-Object Name, ObjectGUID, ObjectClass, DistinguishedName
$groups = $groups | Where-Object { $_.DistinguishedName -notmatch 'CN=Builtin' }
$groupsGrouped = $groups | Group-Object -Property ObjectGUID -AsString -AsHashTable

# Retrieve the membership of groups, requires fetch per group
$groupsWithMembers = New-Object System.Collections.ArrayList
Get-ADGroupsWithMembers -Groups $groups -Users $users ([ref]$groupsWithMembers)

# Transform group memberships into users with memberOf
$usersWithMemberOf = New-Object System.Collections.ArrayList
Invoke-TransformMembershipsToMemberOf -GroupsWithMembers $groupsWithMembers ([ref]$usersWithMemberOf)
$usersWithMemberOf = $usersWithMemberOf | Group-Object -Property "userGuid" -AsString -AsHashTable

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
    $evaluatedPersonsWithEntitlement = $evaluationPermissions | Group-Object -Property "Person" -AsString -AsHashTable
}

# Retrieve entitlements
if (-not[string]::IsNullOrEmpty($grantedEntitlementsCsv)) {
    Write-Information "Gathering data from granted entitlements export..." -InformationAction Continue
    $entitlementsReport = Import-Csv -Path $grantedEntitlementsCsv -Delimiter "," -Encoding UTF8
    $entitlementsGranted = $entitlementsReport | Where-Object { $_.System -eq $entitlementsSystemName -and $_.Status -eq "Granted" -and $_.EntitlementName -Like "$entitlementsPermissionTypeName - *" }

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
    $personsWithGrantedEntitlements = $entitlementsGranted | Group-Object -Property "Person" -AsString -AsHashTable
}

foreach ($person in $expandedPersons) {
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
        Write-Warning "Person $($person.displayName) has no value for correlation attribute: $personCorrelationProperty"
        continue;
    }

    $user = $usersGrouped[$personCorrelationValue]

    if (($user | Measure-Object).Count -eq 0) { continue; }

    $permissions = $usersWithMemberOf["$($user.ObjectGUID)"]

    if (($permissions | Measure-Object).Count -eq 0) { continue; }

    # Get evaluated entitlements for person
    if ($null -ne $evaluatedPersonsWithEntitlement) { $evaluatedEntitlements = $evaluatedPersonsWithEntitlement[$person.DisplayName] }

    # Get granted entitlements for person
    if ($null -ne $personsWithGrantedEntitlements) { $grantedEntitlements = $personsWithGrantedEntitlements[$person.DisplayName] }

    foreach ($permission in $permissions) {
        $group = $groupsGrouped["$($permission.memberOf)"]

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
            UPN                   = $user.UserPrincipalName
            SamAccountName        = $user.SamAccountName
            isEnabled             = $user.Enabled
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
}

Write-Information "Exporting data to CSV..." -InformationAction Continue
$personPermissions | Export-Csv -Path "$($exportPath)personPermissions.csv" -Delimiter ";" -Encoding UTF8 -NoTypeInformation -Force