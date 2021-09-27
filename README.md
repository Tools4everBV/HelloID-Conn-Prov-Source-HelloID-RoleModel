# HelloID-Conn-Prov-Source-HelloID-RoleModel
<!-- Version -->
## Version
Version 1.0.0.
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
  - [User information](#user-information)
    - [Get-HelloIDRoleModel](#get-helloidrolemodel)
    - [Get-HelloIDPersonGroupMembers](#get-helloidpersongroupmembers)
  - [Script outcome](#script-outcome)
  - [PowerShell setup script](#powershell-setup-script)
  - [Update connection and configuration details](#update-connection-and-configuration-details)
    - [details Get-HelloIDRoleModel](#details-get-helloidrolemodel)
    - [Details Get-HelloIDPersonGroupMembers](#details-get-helloidpersongroupmembers)
- [HelloID Docs](#helloid-docs)

## User information
With the local CSV export, you can make a report that gives insight into the current situation in the Active Directory. The exported data can be input for the business rules yet
to be created. 

### Get-HelloIDRoleModel
This script is used by small organizations. This overview offers insight into memberships by department or function. This overview doesn’t give roles across departments of functions. 

### Get-HelloIDPersonGroupMembers
This script is used by middle to big organizations. This overview offers insight into the memberships of the employees of the organizations. If the CSV export is turned into a pivot table, several reports can be made.


## Script outcome
After configuring and running the "Get-HelloIDRoleModel.ps1" or "Get-HelloIDPersonGroupMembers.ps1" script, the following outcome will be automatically generated. 

-	CSV file on a configured local location. 
-	Export data to an HTML path (only with Get-HelloIDRoleModel)


## PowerShell setup script
The PowerShell scripts “Get-HelloIDRoleModel.ps1” and "Get-HelloIDPersonGroupMembers.ps1" contains a complete PowerShell script using the HelloID API to create a report for RoleMining purposes. Please follow the steps below to set up and run the “Get-HelloIDRoleModel.ps1” PowerShell script in your environment. 


1.	Set up a “[Synchronize AD](https://docs.helloid.com/hc/en-us/articles/360001592994)” automated task in Automation > Tasks 
2.	Download the " Get-HelloIDRoleModel.ps1" file
3.	Open it in your favorite PowerShell console/editor
4.	Create a HelloID [API key and secret](https://docs.helloid.com/hc/en-us/articles/360002008873-API-Keys-Overview)
5.	Update the connection and configuration details in the script's header
6.	Run the script on a machine with PowerShell support and an internet connection


## Update connection and configuration details
### details Get-HelloIDRoleModel
| Variable name                 | Description                                                             | Example value                   |
| ----------------------------- | ----------------------------------------------------------------------- | ------------------------------- |
| $script:PortalBaseUrl         | Your HelloID portal's URL                                               | https://customer01.helloid.com  |
| $apiKey                       | API Key value of your HelloID environment                               | ********                        |
| $apiSecret                    | API secret value of your HelloID environment                            | ********                        |
| $source                       | The name of the source in HelloID to filter the accounts and groups on  | enyoi.local                     |
| $exportPath                   | The path where the csv file will be exported (Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments)  | C:\HelloID\Provisioning\RoleMining_export\HelloIDRoleModel\  |
| $relevanceThreshold           | Determines when a permission is relevant enough to be included in the report  | 70                        |
| $roleOccupantsThreshold       | A role is only included if the number of occupants/acounts meets the threshold  | 1                       |
| $maxRoles                     | Output the report for a max $ of roles                                  | 50                              |

### Details Get-HelloIDPersonGroupMembers
| Variable name                 | Description                                                             | Example value                   |
| ----------------------------- | ----------------------------------------------------------------------- | ------------------------------- |
| $script:PortalBaseUrl         | Your HelloID portal's URL                                               | https://customer01.helloid.com  |
| $apiKey                       | API Key value of your HelloID environment                               | ********                        |
| $apiSecret                    | API secret value of your HelloID environment                            | ********                        |
| $source                       | The name of the source in HelloID to filter the accounts and groups on  | enyoi.local                     |
| $exportPath                   | The path where the csv file will be exported (Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments)   | C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\  |
| $vaultJson                    | The path to the Vault export in JSON format (needs to be manually exported from a HelloID Provisioning snapshot). | C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\JSON_file_export\vault.json |
| $evaluationReportCsv          | The location of the Evaluation Report Csv (needs to be manually exported from a HelloID Provisioning evaluation) (Only required when you want to check the groups against an evaluation report).  | C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\Evaluation_Summary_export\EvaluationReport.csv |
| $evaluationSystemName         | The name of the system on which to check the permissions in the evaluation (Only required when using the evaluation report) | Microsoft Active Directory |
| $grantedEntitlementsCsv       | The location of the Granted Entitlements Csv (needs to be manually exported from a HelloID Provisioning Granted Entitlements) (Only required when you want to check the groups against a granted entitlements report) | C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\Entitlements_export\Entitlements.csv |
| $entitlementsSystemName       | The name of the system on which to check the permissions in the evaluation (Only required when using the entitlements report) | Microsoft Active Directory |
| $personCorrelationAttribute   | The person attribute used to correlate a person to an account           | ExternalId                      |
| $userCorrelationAttribute     | The user attribute used to correlate a person to an account             | employeeId                      |


# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
