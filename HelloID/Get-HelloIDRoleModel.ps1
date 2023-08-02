<#
.SYNOPSIS
    Generates a predictive role/entitlement model for use in HelloID Provisioning business rules
    Requires the HelloID API to query the HelloID user and group directory

.DESCRIPTION
    This script generates clusters of accounts based on similar department and title attributes
    The clusters are defined as roles
    A global "Everyone" role is always included to find similar entitlements for all accounts regardless of department and/or title
    Per role, similar entitlements are calculated using a relevance score
    The relevance score is defined as the percentage of accounts having the entitlement vs the total number of accounts clustered in that role
    Per entitlement, we have accounts marked as "Not entitled" and "Not in role"
    "Not entitled": accounts who are clustered in the role but do not have the entitlement
    "Not in role": accounts who have the entitlement but are not clustered in the role
    Colors definitions:
    - Light blue: global entitlements linked to the everyone rule, these do not need defining in detailed roles
    - Green: entitlements on detailed roles that have a 100% relevance score
    - Yellow: entitlements on detailed roles that have a >(threshold_parameter)% and <100% score

.NOTES
    Last Edit: 2021-07-07
    Version 1.0 - initial release
    Version 1.0.1 - Minor updates
#>

# Specify the tenant urlapi key, secret
$tenantUri = "https://CUSTOMER.helloid.com"
$apiKey = "API_KEY"
$apiSecret = "API_SECRET"
# Filter the accounts and groups in the HelloID directory based on a single filter
$source = "enyoi.local"
# Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments
$exportPath = "C:\HelloID\Provisioning\RoleMining_export\HelloIDRoleModel\"
# Determines when a permission is relevant enough to be included in the report.
$relevanceThreshold = 70
# A role is only included if the number of occupants/acounts meets the threshold
$roleOccupantsThreshold = 1
# Output the report for a max $ of roles
$maxRoles = 50

# Basic api uri config
$uriUsers = $tenantUri + "/api/v1/users"
$uriGroups = $tenantUri + "/api/v1/groups"

# Construct the auth header
$pair = "${apiKey}:${apiSecret}"
$bytes = [System.Text.Encoding]::ASCII.GetBytes($pair)
$base64 = [System.Convert]::ToBase64String($bytes)
$basicAuthValue = "Basic $base64"
$headers = @{ Authorization = $basicAuthValue }

# Make sure we use at least TLS 1.2
if ([Net.ServicePointManager]::SecurityProtocol -notmatch "Tls12") {
    [Net.ServicePointManager]::SecurityProtocol += [Net.SecurityProtocolType]::Tls12
}

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
        Write-Verbose -Verbose "Getting data from $uri"

        foreach ($record in $dataset) { [void]$data.Value.add($record) }

        $skip += $take
        while ($dataset.Count -eq $take) {
            $uri = $BaseUri + "?skip=$skip&take=$take"

            Write-Verbose -Verbose "Getting data from $uri"
            $dataset = Invoke-RestMethod -Method Get -Uri $uri -Headers $Headers -UseBasicParsing
            Start-Sleep -Milliseconds 50

            $skip += $take

            foreach ($record in $dataset) { [void]$data.Value.add($record) }
        }
    }
    catch {
        $data.Value = $null
        Write-Verbose $_.Exception
    }
}

function Get-HelloIDGroupsWithMembers {
    param(
        [parameter(Mandatory = $true)]$Groups,
        [parameter(Mandatory = $true)]$Users,
        [parameter(Mandatory = $true)][ref]$groupsWithMembers
    )

    try {
        Write-Verbose -Verbose "Retrieving group memberships for each HelloID group..."

        $UsersGrouped = $Users | Group-Object userGuid -AsHashTable

        # Retrieve the membership of groups, requires fetch per group
        foreach ($group in $Groups) {
            $uriGroup = $uriGroups + "/" + $group.groupGuid
            Write-Verbose -Verbose "Getting group from $uriGroup"
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
        Write-Verbose -Verbose $_.Exception
    }
}

function Invoke-TransformMembershipsToMemberOf {
    param(
        [parameter(Mandatory = $true)]$GroupsWithMembers,
        [parameter(Mandatory = $true)][ref]$usersWithMemberOf
    )

    try {
        Write-Verbose -Verbose "Transforming group memberships to users with memberOf..."

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
        Write-Verbose -Verbose $_.Exception
    }
}

function Get-RolesFromHelloIDUsers {
    param(
        [parameter(Mandatory = $true)]$users,
        [parameter(Mandatory = $true)]$Threshold,
        [parameter(Mandatory = $true)][ref]$roles
    )

    try {
        Write-Verbose -Verbose "Deducing roles from HelloID user accounts..."

        $usersWithAttributes = $users | Select-Object userGuid -ExpandProperty "userAttributes"

        $usersWithRoles = New-Object System.Collections.ArrayList
        foreach ($user in $usersWithAttributes) {
            $record1 = [PSCustomObject]@{
                userGuid = $user.userGUID
                role     = "[GLOBAL]Everyone"
                isGlobal = $True
            }
            $record2 = [PSCustomObject]@{
                userGuid = $user.userGuid
                role     = "[DEPARTMENT]" + $user."department"
                isGlobal = $False
            }
            $record3 = [PSCustomObject]@{
                userGuid = $user.userGuid
                role     = "[JOBTITLE]" + $user."title"
                isGlobal = $False
            }

            [void]$usersWithRoles.Add($record1)
            [void]$usersWithRoles.Add($record2)
            [void]$usersWithRoles.Add($record3)
        }

        # Group by role
        $usersWithRolesGrouped = $usersWithRoles | Group-Object role

        # Build list of unique roles
        $usersWithRolesGrouped | ForEach-Object {
            $identities = $_.Group | Select-Object -ExpandProperty userGuid | Sort-Object -Unique
            $isGlobal = $_.Group | Select-Object -ExpandProperty isGlobal | Select-Object -First 1
            $role = [PSCustomObject]@{
                role       = $_.Name
                isGlobal   = $isGlobal
                identities = $identities
                count      = $identities.Count
            }

            [void]$roles.Value.add($role)
        }

        $roles.Value = $roles.Value | Where-Object { $_.count -ge $Threshold }
        $roles.Value = $roles.Value | Sort-Object count -Descending
    }
    catch {
        $roles.Value = $null
        Write-Verbose -Verbose $_.Exception
    }
}

Function Get-RolesPermissions {
    param(
        [parameter(Mandatory = $true)]$UsersGrouped,
        [parameter(Mandatory = $true)]$UsersWithMemberOf,
        [parameter(Mandatory = $true)]$GroupsWithMembers,
        [parameter(Mandatory = $true)]$GroupsGrouped,
        [parameter(Mandatory = $true)]$Threshold,
        [parameter(Mandatory = $true)][ref]$roles
    )

    try {
        Write-Verbose -Verbose "Calculating and aggregating role permissions..."

        $GroupsWithMembersGrouped = $GroupsWithMembers | Group-Object name -AsHashTable

        $roles.Value | Add-Member -MemberType NoteProperty -Name "accounts" -Value $null
        $roles.Value | Add-Member -MemberType NoteProperty -Name "permissions" -Value $null
        foreach ($role in $roles.Value) {
            $permissions = New-Object System.Collections.ArrayList
            $rolePermissions = New-Object System.Collections.ArrayList
            $identities = $role.identities
            $accounts = New-Object System.Collections.ArrayList

            # Build a list of all permissions and the identities in the each role
            foreach ($identity in $identities) {
                $account = $UsersGrouped[$identity] | Select-Object userGuid, userName
                if ($null -eq $account) { continue; }
                $userMemberOf = $UsersWithMemberOf[$account.userGuid]
                foreach ($element in $userMemberOf) {
                    # Resolve group
                    $group = $groupsGrouped[$element.memberOf]
                    if ($null -eq $group) { continue; }

                    $permission = [PSCustomObject]@{
                        identity   = $identity
                        account    = $account
                        permission = $group.name
                    }
                    [void]$permissions.Add($permission)
                }
                if ($null -ne $account) {
                    [void]$accounts.Add($account)
                }
            }

            # Number of matched accounts
            $role.accounts = $accounts.Count

            # Group on permission
            $permissionsGrouped = $permissions | Group-Object permission

            # Build a list of the permissions with relevance, calculate excluded identities
            $rolePermissions = New-Object System.Collections.ArrayList
            foreach ($permission in $permissionsGrouped) {
                $permissionGroup = $GroupsWithMembersGrouped[$permission.Name] | Select-Object -First 1

                $included = @($permission.Group | Select-Object -ExpandProperty account)
                $includedNotInRole = $permissionGroup.usersResolved | Where-Object { $_.userGuid -notin $role.identities } | Select-Object -ExpandProperty userName
                $excluded = $accounts | Where-Object { $_.userGuid -notin $included.userGuid } | Select-Object -ExpandProperty userName
                $relevanceAccount = $permission.Group.Count / $accounts.Count * 100
                if ($relevanceAccount -lt $Threshold) { continue; }

                $rolePermission = [PSCustomObject]@{
                    name              = $permission.Name
                    count             = $permission.Group.Count
                    relevanceAccount  = $relevanceAccount
                    includedNotInRole = $includedNotInRole
                    excluded          = $excluded
                    isGlobal          = $role.isGlobal
                }
                [void]$rolePermissions.Add($rolePermission)
            }

            $role.permissions = $rolePermissions | Sort-Object relevanceAccount -Descending
        }

        # Postprocess to mark global permissions
        $globalRole = $roles.Value | Where-Object { $_.isGlobal -eq $True }
        $globalRolePermissions = $globalRole.permissions | Select-Object -ExpandProperty name
        foreach ($role in $roles.Value) {
            if ($role.isGlobal -eq $True) {
                foreach ($rolePermission in $role.permissions) {
                    # All permissions in global roles are global by default
                    $rolePermission.isGlobal = $True
                }
            }
            else {
                foreach ($rolePermission in $role.permissions) {
                    # If the permission is included in the global role, mark it as global too
                    if ($rolePermission.name -in $globalRolePermissions) {
                        $rolePermission.isGlobal = $True
                    }
                }
            }
        }
    }
    catch {
        $roles.Value = $null
        Write-Verbose -Verbose $_.Exception
    }
}

function Export-Roles {
    param(
        [parameter(Mandatory = $true)]$Roles,
        [parameter(Mandatory = $true)]$Max,
        [parameter(Mandatory = $true)]$FilePath
    )

    try {
        Write-Verbose -Verbose "Exporting data to CSV..."

        $Roles = $Roles | Select-Object -First $Max

        $header = "role;number_of_accounts;permissie_relevance;permission_count;permission;not_entitled;not_in_role"

        $export = New-Object System.Collections.ArrayList
        foreach ($record in $Roles) {
            foreach ($item in $record.permissions) {
                $relevance = [math]::Round($item.relevanceAccount)

                $line = $record.role + ";"
                $line += [string]$record.accounts + ";"
                $line += [string]$relevance + ";"
                $line += [string]$item.count + ";"
                $line += [string]$item.name + ";"
                # Optionally include the excluded accounts for audit purposes
                $line += $item.excluded -join '|'
                $line += ";"
                $line += $item.includedNotInRole -join '|'

                [void]$export.add($line)
            }
        }

        $header | Out-File -FilePath $FilePath
        $export | Out-File -FilePath $FilePath -Append
    }
    catch {
        Write-Verbose -Verbose $_.Exception
    }
}

Function Export-RolesHTML {
    param(
        [parameter(Mandatory = $true)]$Roles,
        [parameter(Mandatory = $true)]$Max,
        [parameter(Mandatory = $true)]$FilePath
    )

    try {
        Write-Verbose -Verbose "Exporting data to HTML..."

        $Roles = $Roles | Select-Object -First $Max

        $stream = [System.IO.StreamWriter]::new($FilePath)

        $cumulativeIdentities = New-Object System.Collections.ArrayList
        $totalAccounts = ($Roles | Where-Object { $_.isGlobal -eq $true } | Select-Object -First 1).accounts

        # HTML header
        $stream.WriteLine("<!doctype html>")
        $stream.WriteLine("<html lang='en'>")
        $stream.WriteLine("<head>")
        $stream.WriteLine("<title>Report</title>")
        $stream.WriteLine("<!-- Required meta tags -->")
        $stream.WriteLine("<meta charset='utf-8'>")
        $stream.WriteLine("<meta name='viewport' content='width=device-width, initial-scale=1, shrink-to-fit=no'>")
        $stream.WriteLine("<!-- Bootstrap CSS -->")
        $stream.WriteLine("<link href='https://cdn.jsdelivr.net/npm/bootstrap@5.0.1/dist/css/bootstrap.min.css' rel='stylesheet' integrity='sha384-+0n0xVW2eSR5OomGNYDnhzAbDsOXxcvSN1TPprVMTNDbiYZCxYbOOl7+AMvyTG2x' crossorigin='anonymous'>")
        $stream.WriteLine("</head><body>")

        $stream.WriteLine("<body>")
        $stream.WriteLine("<script src='https://cdn.jsdelivr.net/npm/bootstrap@5.0.1/dist/js/bootstrap.bundle.min.js' integrity='sha384-gtEjrD/SeCtmISkJkNUaaKMoLD0//ElJ19smozuHV6z3Iehds+3Ulb9Bn9Plx0x4' crossorigin='anonymous'></script>")
        $stream.WriteLine("<table class='table table-dark table-striped'>")
        $stream.WriteLine("<thead><tr><th>Role</th><th># of accounts</th><td>Cumulative coverage</td><th>Permissions</th></thead>")
        $stream.WriteLine("<tbody>")

        foreach ($record in $Roles) {
            if ($record.isGlobal -eq $false) {
                $cumulativeIdentities += $record.identities
                $cumulativeIdentities = $cumulativeIdentities | Sort-Object -Unique
            }

            $accountCoverage = [math]::Round($cumulativeIdentities.Count / $totalAccounts * 100)

            $stream.WriteLine("<tr>")
            $stream.WriteLine("<td>" + $record.role + "</td>")
            $stream.WriteLine("<td>" + $record.accounts + "</td>")
            $stream.WriteLine("<td>" + $cumulativeIdentities.Count + " (" + $accountCoverage + "%)" + "</td>")

            $stream.WriteLine("<td>")
            $stream.Write("<table class='table table-dark'>")
            foreach ($item in $record.permissions) {
                $relevance = [math]::Round($item.relevanceAccount)

                if ($relevance -eq 100) {
                    $style = "class='text-success'"
                }
                elseif ($relevance -ge $Threshold -and $relevance -lt 100) {
                    $style = "class='text-warning'"
                }
                else {
                    $style = "class='text-danger'"
                }

                if ($item.isGlobal -eq $True) {
                    $style = "class='text-info'"
                }

                $stream.Write("<tr $style>")

                $stream.Write("<td>" + [string]$relevance + "%</td>")
                $stream.Write("<td>" + [string]$item.count + "/" + [string]$record.accounts + "</td>")
                $stream.Write("<td>" + $item.name + "</td>")

                $stream.Write("<td>")

                if ($null -ne $item.excluded) {
                    $id = Get-StringHash -String "$($record.role)_$($item.name)"
                    $id = "excluded_" + $id

                    $stream.Write("<button class='btn btn-primary' type='button' data-bs-toggle='collapse' data-bs-target='#$id' aria-expanded='false' aria-controls='$id'>")
                    $stream.Write("Not entitled ($($item.excluded.Count))")
                    $stream.Write("</button>")
                    $stream.Write("<div class='collapse' id='$id'>")

                    $stream.Write("<table data-toggle='collapse' class='table table-dark'>")
                    if ($item.excluded.Count -gt 100) {
                        $stream.Write("<tr class='text-danger'>")
                        $stream.Write("<td>100+ accounts not entitled!</td>")
                        $stream.Write("</tr>")
                    }
                    else {
                        foreach ($exclusion in $item.excluded) {
                            $stream.Write("<tr>")
                            $stream.Write("<td>" + $exclusion + "</td>")
                            $stream.Write("</tr>")
                        }
                    }
                    $stream.Write("</table>")

                    $stream.Write("</div>")
                }

                $stream.Write("</td>")
                $stream.Write("<td>")

                if ($null -ne $item.includedNotInRole -and $item.isGlobal -eq $false) {
                    $id = Get-StringHash -String "$($record.role)_$($item.name)"
                    $id = "included_" + $id

                    $stream.Write("<button class='btn btn-primary' type='button' data-bs-toggle='collapse' data-bs-target='#$id' aria-expanded='false' aria-controls='$id'>")
                    $stream.Write("Not in role ($($item.includedNotInRole.Count))")
                    $stream.Write("</button>")
                    $stream.Write("<div class='collapse' id='$id'>")

                    $stream.Write("<table data-toggle='collapse' class='table table-dark'>")
                    if ($item.includedNotInRole.Count -gt 100) {
                        $stream.Write("<tr class='text-danger'>")
                        $stream.Write("<td>100+ accounts not in role!</td>")
                        $stream.Write("</tr>")
                    }
                    else {
                        foreach ($inclusion in $item.includedNotInRole) {
                            $stream.Write("<tr class='text-danger'>")
                            $stream.Write("<td>" + $inclusion + "</td>")
                            $stream.Write("</tr>")
                        }
                    }
                    $stream.Write("</table>")

                    $stream.Write("</div>")
                }

                $stream.Write("</td>")
            }
            $stream.Write("</table>")
            $stream.WriteLine("</td>")

            $stream.WriteLine("</tr>")
        }

        $stream.WriteLine("</tbody>")
        $stream.WriteLine("</table>")
        $stream.WriteLine("</body>")
        $stream.WriteLine("</html>")

        $stream.Close()
    }
    catch {
        Write-Verbose -Verbose $_.Exception
    }
}

# Retrieve all users
$users = New-Object System.Collections.ArrayList
Get-RESTAPIPagedData -BaseUri $uriUsers -Headers $headers ([ref]$users)
$users = $users | Where-Object { $_.source -eq $source }
$users = $users | Where-Object { $_.isDeleted -eq $False }
$users = $users | Where-Object { $_.isEnabled -eq $True }
Export-Clixml -Path "$($exportPath)users.xml" -InputObject $users

# Retrieve all groups
$groups = New-Object System.Collections.ArrayList
Get-RESTAPIPagedData -BaseUri $uriGroups -Headers $headers ([ref]$groups)
$groups = $groups | Where-Object { $_.source -eq $source }
$groups = $groups | Where-Object { $_.isDeleted -eq $False }
$groups = $groups | Where-Object { $_.isEnabled -eq $True }
Export-Clixml -Path "$($exportPath)groups.xml" -InputObject $groups

# Retrieve the membership of groups, requires fetch per group
$groupsWithMembers = New-Object System.Collections.ArrayList
Get-HelloIDGroupsWithMembers -Groups $groups -Users $users ([ref]$groupsWithMembers)
Export-Clixml -Path "$($exportPath)groupsWithMembers.xml" -InputObject $groupsWithMembers
$groupsWithMembers = Import-Clixml -Path "$($exportPath)groupsWithMembers.xml"

# Group data
$usersGrouped = $users | Group-Object userGuid -AsHashTable
$groupsGrouped = $groups | Group-Object groupGuid -AsHashTable

# Construct roles from HelloID users with their attributes
$roles = New-Object System.Collections.ArrayList
Get-RolesFromHelloIDUsers -Users $users -Threshold $roleOccupantsThreshold ([ref]$roles)
Export-Clixml -Path "$($exportPath)roles.xml" -InputObject $roles

# Transform group memberships into users with memberOf
$usersWithMemberOf = New-Object System.Collections.ArrayList
Invoke-TransformMembershipsToMemberOf -GroupsWithMembers $groupsWithMembers ([ref]$usersWithMemberOf)
Export-Clixml -Path "$($exportPath)usersWithMemberOf.xml" -InputObject $usersWithMemberOf
$usersWithMemberOf = $usersWithMemberOf | Group-Object "userGuid" -AsHashTable

# Augment the roles with permissions and identities
Get-RolesPermissions -UsersGrouped $usersGrouped -UsersWithMemberOf $usersWithMemberOf -GroupsWithMembers $groupsWithMembers -GroupsGrouped $groupsGrouped -Threshold $relevanceThreshold ([ref]$roles)
Export-Clixml -Path "$($exportPath)rolesPermissions.xml" -InputObject $roles

# Export the data to CSV
Export-Roles -Roles $roles -Max $maxRoles -FilePath "$($exportPath)roleModel.csv"

# Export the data to HTML
Export-RolesHTML -Roles $roles -Max $maxRoles -FilePath "$($exportPath)roleModel.html"