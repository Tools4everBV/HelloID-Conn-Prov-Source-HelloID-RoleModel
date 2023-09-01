# HelloID-Conn-Prov-Source-HelloID-RoleModel

| :information_source: Information                                                                                                                                                                                                                                                                                                                                                       |
| :------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements. |

<br />

<!-- Version -->
## Version
| Version | Description     | Date       |
| ------- | --------------- | ---------- |
| 1.0.0   | Initial release | 11/08/2021 |

> __This is the initial version, please let us know about any bugs/features!__
## Warning: 
The API is very powerful, therefore the API key and secret must be kept private and be used with care.

<!-- Description -->
## Description
These Powershell scripts generate overviews to support building a role model

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [HelloID-Conn-Prov-Source-HelloID-RoleModel](#helloid-conn-prov-source-helloid-rolemodel)
  - [Version](#version)
  - [Warning:](#warning)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [Limitation on the scripts](#limitation-on-the-scripts)
  - [User information](#user-information)
    - [Get-HelloIDRoleModel](#get-helloidrolemodel)
    - [Get-HelloIDPersonGroupMembers](#get-helloidpersongroupmembers)
  - [Script outcome](#script-outcome)
  - [PowerShell setup script](#powershell-setup-script)
  - [Update connection and configuration details](#update-connection-and-configuration-details)
    - [Details Get-HelloIDRoleModel](#details-get-helloidrolemodel)
    - [Details Get-HelloIDPersonGroupMembers](#details-get-helloidpersongroupmembers)
- [HelloID Docs](#helloid-docs)

## Limitation on the scripts
For the scripts there is a sync needed from the target to HelloID. For example a sync from the local Active Directory to HelloID. Not every target systeem can synchrochize to HelloID. At the moment only two different target systems (AD and AAD) are tested to correctly sync with the HelloID Directory.

## User information
With the local CSV export, you can make a report that gives insight into the current situation in the Active Directory. The exported data can be input for the business rules yet
to be created.

### Get-HelloIDRoleModel
This script is used by small organizations. This overview offers insight into memberships by department or function. This overview doesn’t give roles across departments of functions.

### Get-HelloIDPersonGroupMembers
This script is used by middle to big organizations. This overview offers insight into the memberships of the employees of the organizations. If the CSV export is turned into a pivot table, several reports can be made.

## Script outcome
After configuring and running the "Get-HelloIDRoleModel.ps1" or "Get-HelloIDPersonGroupMembers.ps1" script, the following outcome will be automatically generated. 
-   CSV file on a configured local location. 
-   Export data to an HTML path (only with Get-HelloIDRoleModel)

## PowerShell setup script
The PowerShell scripts “Get-HelloIDRoleModel.ps1” and "Get-HelloIDPersonGroupMembers.ps1" contains a complete PowerShell script using the HelloID API to create a report for RoleMining purposes. Please follow the steps below to set up and run the “Get-HelloIDRoleModel.ps1” PowerShell script in your environment. 
1. Set up a sync to the HelloID Directory. There are two different target systems that are available Active Directory or Azure Active Directory.
   - Local Active Directory: Set up a “[Synchronize AD](https://docs.helloid.com/hc/en-us/articles/360001592994)” automated task in Automation > Tasks 
   - AzureAD (only AAD)
   Enable synchronization with AAD "[Synchronize AAD] (https://docs.helloid.com/hc/en-us/articles/360019160119-Enable-or-disable-Azure-AD-synchronization)" 
   Because the sync with AAD doesn’t bring the EmployeeId to the HelloID Users. For the script HelloID needs an EmployeeId to correlate the persons and accounts. With "[Sync AzureAD-EmployeeId-HelloID-Users] https://github.com/Tools4everBV/HelloID-Conn-SA-Source-Sync-AzureAD-EmployeeId-HelloID-Users" the EmployeeId can be synced to the HelloID Users. 
2.  Download the " Get-HelloIDRoleModel.ps1" file
3.  Open it in your favorite PowerShell console/editor
4.  Create a HelloID [API key and secret](https://docs.helloid.com/hc/en-us/articles/360002008873-API-Keys-Overview)
5.  Update the connection and configuration details in the script's header
6.  Run the script on a machine with PowerShell support and an internet connection

## Update connection and configuration details
### Details Get-HelloIDRoleModel
| Variable name           | Description                                                                                                                              | Example value                                               |
| ----------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ----------------------------------------------------------- |
| $script:PortalBaseUrl   | Your HelloID portal's URL                                                                                                                | https://customer01.helloid.com                              |
| $apiKey                 | API Key value of your HelloID environment                                                                                                | ********                                                    |
| $apiSecret              | API secret value of your HelloID environment                                                                                             | ********                                                    |
| $source                 | The name of the source in HelloID to filter the accounts and groups on                                                                   | enyoi.local                                                 |
| $exportPath             | The path where the csv file will be exported (Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments) | C:\HelloID\Provisioning\RoleMining_export\HelloIDRoleModel\ |
| $relevanceThreshold     | Determines when a permission is relevant enough to be included in the report                                                             | 70                                                          |
| $roleOccupantsThreshold | A role is only included if the number of occupants/acounts meets the threshold                                                           | 1                                                           |
| $maxRoles               | Output the report for a max $ of roles                                                                                                   | 50                                                          |

### Details Get-HelloIDPersonGroupMembers
| Variable name               | Description                                                                                                                              | Example value                                                 |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------------------------------- |
| $script:PortalBaseUrl       | Your HelloID portal's URL                                                                                                                | https://customer01.helloid.com                                |
| $apiKey                     | API Key value of your HelloID environment                                                                                                | ********                                                      |
| $apiSecret                  | API secret value of your HelloID environment                                                                                             | ********                                                      |
| $source                     | The name of the source in HelloID to filter the accounts and groups on                                                                   | enyoi.local                                                   |
| $exportPath                 | The path where the csv file will be exported (Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments) | C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\ |
| $evaluationSystemName       | The name of the system on which to check the permissions in the evaluation (Only required when using the evaluation report)              | Microsoft Active Directory                                    |
| $entitlementsSystemName     | The name of the system on which to check the permissions in the evaluation (Only required when using the entitlements report)            | Microsoft Active Directory                                    |
| $personCorrelationAttribute | The person attribute used to correlate a person to an account                                                                            | ExternalId                                                    |
| $userCorrelationAttribute   | The user attribute used to correlate a person to an account                                                                              | employeeId                                                    |

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/