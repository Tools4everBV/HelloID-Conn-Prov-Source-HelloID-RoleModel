<#
.SYNOPSIS

.DESCRIPTION

.NOTES
    Author: Jeroen Smit
    Editor: Jeroen Smit
    Created At: 2023-08-22
    Last Edit: 2024-03-25
    Version 1.0 - initial release
    Version 1.1 - added reporting for persons with no correlation attribute, persons with no account or accounts with no permissions
    Version 1.1.1 - fix column 'Status' is removed from export 'entilements.csv'
    Version 1.1.2 - fix: calculate dummy permission even if person has no other permissions
#>
# Specify whether to output the verbose logging
#$verboseLogging = $false

# Toggle to include nested groupmemberships
$includeNestedGroupMemberships = $true # or $false
$nestedGroupMembershipsMaxDepth = 5 # 0 will result in no nested groupmemberships

# Toggle to add dummy permission to result for each person
$addDummyPermission = $true # or $false

# Replace path with your path for vault.json, Evaluation.csv and entitlements.csv.
# Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments
$exportPath = "C:\HelloID\RoleminingAD\"

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
$personPropertiesToInclude = @($personCorrelationAttribute, "source.displayname")
# Specify the Contracts fields from the HelloID Vault export to include in the report (These have to match the exact name from he Vault.json export)
$contractPropertiesToInclude = @("costCenter.externalId", "Costcenter.name")

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

        Write-Information "Expanded persons with contracts. Result count: $(($ExpandedPersons.Value | Select-Object -Property displayName, source -Unique | Measure-Object).Count)" -InformationAction Continue
    }
    catch {
        Write-Error $_.Exception
    }
}

function Get-NestedGroupMemberships {
    param (
        [Parameter(Mandatory = $true)]
        [PSObject]$User,

        [Parameter(Mandatory = $true)]
        [PSObject]$Group,

        [Parameter(Mandatory = $true)]
        [System.Collections.ArrayList]$UsersWithMemberships,

        [Parameter(Mandatory = $true)]
        [Hashtable]$GroupsGroupedByDistinguishedName,

        [Parameter(Mandatory = $true)]
        [int]$CurrentDepth,

        [Parameter(Mandatory = $true)]
        [int]$MaxDepth
    )

    if ($CurrentDepth -gt $MaxDepth) {
        return
    }

    foreach ($NestedGroup in $Group.MemberOf) {
        # Get group object by distinguished name
        $nestedGroupObject = $GroupsGroupedByDistinguishedName["$($NestedGroup)"]

        if ($null -ne $nestedGroupObject) {
            # Filter member for only groups and get group object by distinguished name
            $memberGroups = [System.Collections.ArrayList]::new()
            foreach ($nestedGroupMember in $nestedGroupObject.Member) {
                if ($groupsGroupedByDistinguishedName.ContainsKey($nestedGroupMember)) {
                    [void]$memberGroups.Add($groupsGroupedByDistinguishedName[$nestedGroupMember])
                }
            }

            # Filter memberof for only groups and get group object by distinguished name
            $memberOfGroups = [System.Collections.ArrayList]::new()
            foreach ($nestedGroupMemberOf in $nestedGroupObject.MemberOf) {
                if ($groupsGroupedByDistinguishedName.ContainsKey($nestedGroupMemberOf)) {
                    [void]$memberOfGroups.Add($groupsGroupedByDistinguishedName[$nestedGroupMemberOf])
                }
            }

            $NestedUserCustomObject = [PSCustomObject]@{
                UserName         = $User.Name
                UserGuid         = $User.ObjectGUID
                GroupName        = $nestedGroupObject.Name
                GroupGuid        = $nestedGroupObject.ObjectGUID
                IsNested         = $true
                "Member/Parent"  = $memberGroups.Name -join "|"
                "MemberOf/Child" = $memberOfGroups.Name -join "|"
            }

            [void]$UsersWithMemberships.Add($NestedUserCustomObject)

            # Recursively get nested group memberships
            $NestedGroupMembershipsParams = @{
                User                             = $User
                Group                            = $NestedGroupObject
                UsersWithMemberships             = $UsersWithMemberships
                GroupsGroupedByDistinguishedName = $GroupsGroupedByDistinguishedName
                CurrentDepth                     = $CurrentDepth + 1
                MaxDepth                         = $MaxDepth
            }

            Get-NestedGroupMemberships @NestedGroupMembershipsParams
        }
    }
}

# Retrieve all persons
Write-Information "Gathering persons..." -InformationAction Continue
$snapshot = Get-Content -Path $vaultJson -Encoding UTF8 | ConvertFrom-Json
$persons = $snapshot.Persons
Write-Information "Gathered persons. Result count: $(($persons | Measure-Object).Count)" -InformationAction Continue

# Expand persons with contracts
$expandedPersons = New-Object System.Collections.ArrayList
Expand-Persons -Persons $snapshot.Persons ([ref]$ExpandedPersons)

# Retrieve all users
Write-Information "Gathering users..." -InformationAction Continue
$users = New-Object System.Collections.ArrayList
$users = Get-aduser -Filter { (ObjectClass -eq 'user') } -Properties Name, DisplayName, EmployeeID, EmployeeNumber, MemberOf, SamAccountName, UserPrincipalName, DistinguishedName
$users = $users | Where-Object { $_.Enabled -eq $true }
$users = $users | Where-Object { [String]::IsNullOrEmpty($_.($userCorrelationAttribute)) -eq $false }
$usersGrouped = $users | Group-Object -Property $userCorrelationAttribute -AsString -AsHashTable
Write-Information "Gathered users. Result count: $(($users | Measure-Object).Count)" -InformationAction Continue

# Retrieve all groups
Write-Information "Gathering groups..." -InformationAction Continue
$groups = New-Object System.Collections.ArrayList
$groups = Get-ADGroup -Filter * -Properties Name, ObjectGUID, ObjectClass, DistinguishedName, Member, MemberOf, whenChanged, whenCreated
$groups = $groups | Where-Object { 
    $_.DistinguishedName -notmatch 'CN=Builtin' -or $_.Name -eq 'Domain Users' 
}
$groupsGrouped = $groups | Group-Object -Property ObjectGUID -AsString -AsHashTable
$groupsGroupedByDistinguishedName = $groups | Group-Object -Property DistinguishedName -AsString -AsHashTable
Write-Information "Gathered groups. Result count: $(($groups | Measure-Object).Count)" -InformationAction Continue

# Retrieve the membership of users, requires fetch per user
try {
    Write-Information "Retrieving group memberships for each AD user..." -InformationAction Continue

    # Create list of all users with their group memberships
    $UsersWithMemberships = [System.Collections.ArrayList]::new()

    foreach ($User in $Users) {
        foreach ($GroupMember in $User.MemberOf) {
            if ($groupsGroupedByDistinguishedName.ContainsKey($GroupMember)) {
                # Get group object by distinguished name
                $GroupObject = $null
                $GroupObject = $groupsGroupedByDistinguishedName["$($GroupMember)"]

                # Filter member for only groups and get group object by distinguished name
                $memberGroups = [System.Collections.ArrayList]::new()
                foreach ($groupMember in $GroupObject.Member) {
                    if ($groupsGroupedByDistinguishedName.ContainsKey($groupMember)) {
                        [void]$memberGroups.Add($groupsGroupedByDistinguishedName["$groupMember"])
                    }
                }

                # Filter memberof for only groups and get group object by distinguished name
                $memberOfGroups = [System.Collections.ArrayList]::new()
                foreach ($groupMemberOf in $GroupObject.MemberOf) {
                    if ($groupsGroupedByDistinguishedName.ContainsKey($groupMemberOf)) {
                        [void]$memberOfGroups.Add($groupsGroupedByDistinguishedName["$groupMemberOf"])
                    }
                }
            
                # Create custom object for user with group membership
                $UserCustomObject = [PSCustomObject]@{
                    UserName         = $User.Name
                    UserGuid         = $User.ObjectGUID
                    GroupName        = $GroupObject.Name
                    GroupGuid        = $GroupObject.ObjectGUID
                    IsNested         = $false
                    "Member/Parent"  = $memberGroups.Name -join "|"
                    "MemberOf/Child" = $memberOfGroups.Name -join "|"
                }

                # Add the custom object for user with group membership to list of all users with their group memberships
                [void]$UsersWithMemberships.Add($UserCustomObject)

                if ($IncludeNestedGroupMemberships -eq $true) {
                    # Get nested group memberships
                    $NestedGroupMembershipsParams = @{
                        User                             = $User
                        Group                            = $GroupObject
                        UsersWithMemberships             = $UsersWithMemberships
                        GroupsGroupedByDistinguishedName = $groupsGroupedByDistinguishedName
                        CurrentDepth                     = 1
                        MaxDepth                         = $nestedGroupMembershipsMaxDepth
                    }

                    Get-NestedGroupMemberships @NestedGroupMembershipsParams
                }
            }
        }
    }

    Write-Information "Gathered group memberships for each AD user. Result count: $(($UsersWithMemberships | Measure-Object).Count)" -InformationAction Continue
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

        # If Target system is AD, the entitlement contains the CannonicalName between brackets, so this needs some regex to filter this out
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

    # Transform Evaluation Report into persons with entitlements
    $evaluatedPersonsWithEntitlement = $null
    $evaluatedPersonsWithEntitlement = $evaluationPermissions | Group-Object -Property "Person" -AsString -AsHashTable
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
    $personsWithGrantedEntitlements = $entitlementsGranted | Group-Object -Property "Person" -AsString -AsHashTable
}

# Create three arraylists
$personsWithoutCorrelationValue = [System.Collections.ArrayList]::new()
$personsWithoutUser = [System.Collections.ArrayList]::new()
$personsWithoutPermissions = [System.Collections.ArrayList]::new()

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

    # Create record for Dummy permission
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
            startDate             = ($person.startDate).ToString('yyyy-MM-dd')
            endDate               = ($person.endDate).ToString('yyyy-MM-dd')
            isActive              = $person.isActive
            UPN                   = $user.UserPrincipalName
            SamAccountName        = $user.SamAccountName
            isEnabled             = $user.Enabled
            permission            = "Dummy"
            GroupWhenCreated      = $null
            GroupWhenChanged      = $null
            inEvaluation          = $false
            isGranted             = $false
            FunctieExternalID     = $person.titleId + "|" + $person.titleCode + "|" + $person.externalId
            DepartmentExternalID  = $person.departmentId + "|" + $person.departmentCode + "|" + $person.externalId
        }

        if ($includeNestedGroupMemberships -eq $true) {
            $dummyRecord | Add-Member -MemberType NoteProperty -Name "isNested" -Value $false -Force
            $dummyRecord | Add-Member -MemberType NoteProperty -Name "Member/Parent" -Value $null -Force
            $dummyRecord | Add-Member -MemberType NoteProperty -Name "MemberOf/Child"  -Value $null -Force
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

    $permissions = $usersWithMemberOf["$($user.ObjectGUID)"]

    if ($null -eq $permissions) { 
        Write-Verbose "No permission(s) found where Userguid = $($user.ObjectGUID) for person $($person.displayName)"
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
        $group = $groupsGrouped["$($permission.groupGuid)"]

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
            GroupWhenCreated      = ($group.whenCreated).ToString('yyyy-MM-dd')
            GroupWhenChanged      = ($group.whenChanged).ToString('yyyy-MM-dd')
            inEvaluation          = $inEvaluation
            isGranted             = $isGranted
            FunctieExternalID     = $person.titleId + "|" + $person.titleCode + "|" + $person.externalId
            DepartmentExternalID  = $person.departmentId + "|" + $person.departmentCode + "|" + $person.externalId
        }

        if ($includeNestedGroupMemberships -eq $true) {
            $record | Add-Member -MemberType NoteProperty -Name "isNested" -Value $permission.isNested -Force
            $record | Add-Member -MemberType NoteProperty -Name "Member/Parent" -Value $permission."Member/Parent" -Force
            $record | Add-Member -MemberType NoteProperty -Name "MemberOf/Child"  -Value $permission."MemberOf/Child" -Force
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