# HelloID-Conn-Prov-Source-HelloID-RoleModel
<!-- Version -->
## Version
Version 1.0.0.
> __This is the initial version, please let us know about any bugs/features!__
## Warning: 
The API is very powerful, therefore the API key and secret must be kept private and be used with care.

<!-- Description -->
## Description
  - [Version](#version)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [User information](#user-information)
    - [Get-HelloIDRoleModel](#get-helloidrolemodel)
    - [Get-HelloIDPersonGroupMembers](#get-helloidpersongroupmembers)
  - [Script outcome ](#script-outcome)
  - [PowerShell setup script](#powershell-setup-script)
  - [Update connection and configuration details](#update-connection-and-configuration-details)
    - [details Get-HelloIDRoleModel](#details-get-helloidrolemodel)
    - [details Get-HelloIDPersonGroupMembers](#details-get-helloidpersongroupmembers)
- [HelloID Docs](#helloid-docs)

## User information
With the local CSV export, you can make a report that gives insight into the current situation in the Active Directory. The exported data can be input for the business rules yet
to be created. 
### Get-HelloIDRoleModel
This script is used by small organizations. This overview offers insight into memberships by department or function. This overview doesn’t give roles across departments of
functions. 
### Get-HelloIDPersonGroupMembers
This script is used by middle to big organizations. This overview offers insight into the memberships of the employees of the organizations. If the CSV export is turned into a
pivot table, several reports can be made.


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
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>$script:PortalBaseUrl</td><td>https://customer01.helloid.com</td><td>Your HelloID portal's URL</td></tr>
  <tr><td>$apiKey</td><td>*****</td><td>API Key value of your own environment</td></tr>
  <tr><td>$apiSecret</td><td>*****</td><td>API secret value of your own environment</td></tr>
  <tr><td>$source</td><td>enyoi.local</td><td>Filter the accounts and groups in the HelloID directory based on a single filter</td></tr>
  <tr><td>$exportPath</td><td>C:\HelloID\Provisioning\RoleMining_export\HelloIDRoleModel\</td><td>Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments</td></tr>
  <tr><td>$relevanceThreshold</td><td>70</td><td>Determines when a permission is relevant enough to be included in the report.</td></tr>
  <tr><td>$roleOccupantsThreshold</td><td>1</td><td>A role is only included if the number of occupants/acounts meets the threshold.</td></tr>
  <tr><td>$maxRoles</td><td>50</td><td>Output the report for a max $ of roles</td></tr>
</table>

### Details Get-HelloIDPersonGroupMembers
<table>
  <tr><td><strong>Variable name</strong></td><td><strong>Example value</strong></td><td><strong>Description</strong></td></tr>
  <tr><td>$script:PortalBaseUrl</td><td>https://customer01.helloid.com</td><td>Your HelloID portal's URL</td></tr>
  <tr><td>$apiKey</td><td>*****</td><td>API Key value of your own environment</td></tr>
  <tr><td>$apiSecret</td><td>*****</td><td>API secret value of your own environment</td></tr>
  <tr><td>$source</td><td>enyoi.local</td><td>Filter the accounts and groups in the HelloID directory based on a single filter</td></tr>
  <tr><td>$exportPath</td><td>C:\HelloID\Provisioning\RoleMining_export\HelloIDRoleModel\</td><td>Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments</td></tr>
  <tr><td>$json</td><td>C:\HelloID\Provisioning\RoleMining_export\JSON_file_export\vault.json</td><td>The location of the Vault export in JSON format (needs to be manually exported from a HelloID Provisioning snapshot).</td></tr>
  <tr><td>$personCorrelationAttribute</td><td>ExternalId</td><td>The attribute used to correlate a person to an account</td></tr>
  <tr><td>$userCorrelationAttribute</td><td>employeeId</td><td>The attribute used to correlate a person to an account</td></tr>
</table>


# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
