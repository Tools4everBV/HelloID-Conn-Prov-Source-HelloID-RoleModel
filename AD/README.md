# HelloID-Conn-Prov-Source-HelloID-RoleModel

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

<br />

<!-- Version -->
## Version
| Version | Description | Date |
| - | - | - |
| 1.0.0   | Initial release | 2023/09/01  |

> __This is the initial version, please let us know about any bugs/features!__
## Warning: 
With this Application Registration you can see a lot of data. Be careful with de credentials.

<!-- Description -->
## Description
This Powershell script generates an overview (CSV file) that can be turned into an overview that gives insights into memberships of the employees of the organizations. The pivot tables that can be made of the CSV file can deliver input fo the business rules yet to be created.

This script is used by middle to big organizations. This overview offers insight into the memberships of the employees of the organizations. If the CSV export is turned into a pivot table, several reports can be made.

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [HelloID-Conn-Prov-Source-HelloID-RoleModel](#helloid-conn-prov-source-helloid-rolemodel)
  - [Version](#version)
  - [Warning:](#warning)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [Limitation on the scripts](#limitation-on-the-scripts)
  - [Script outcome](#script-outcome)
  - [PowerShell setup script](#powershell-setup-script)
  - [Update connection and configuration details](#update-connection-and-configuration-details)
    - [Details Get-ADPersonGroupMembers](#details-get-adpersongroupmembers)
  - [Introduction](#introduction)
  - [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
    - [Application Registration](#application-registration)
    - [Configuring App Permissions](#configuring-app-permissions)
    - [Authentication and Authorization](#authentication-and-authorization)
    - [Connection settings](#connection-settings)
- [HelloID Docs](#helloid-docs)

## Limitation on the scripts
This script will need to be run on a server with Active Directory access. 

## Script outcome
After configuring and running the "Get-ADPersonGroupMembers.ps1" script, the following outcome will be automatically generated. 
-   CSV file on a configured local location. 

## PowerShell setup script
The PowerShell script "Get-ADPersonGroupMembers.ps1" contains a complete PowerShell script create a CSV file for Role mining purposes. 
1.  Download the "Get-AzurePersonGroupMembers.ps1" file
2.  Open it in your favorite PowerShell console/editor
3.  Update the connection and configuration details in the script's header
4.  Run the script on a machine with PowerShell support and local Active Directory access

## Update connection and configuration details
### Details Get-ADPersonGroupMembers
| Variable name                 | Description                                                             | Example value                   |
| ----------------------------- | ----------------------------------------------------------------------- | ------------------------------- |
| $exportPath                   | The path where the csv file will be exported (Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments at the end of the path)   | C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\  |
| $evaluationSystemName         | The name of the system on which to check the permissions in the evaluation (Only required when using the evaluation report) | Microsoft Active Directory |
| $entitlementsSystemName       | The name of the system on which to check the permissions in the evaluation (Only required when using the entitlements report) | Microsoft Active Directory |
| $personCorrelationAttribute   | The person attribute used to correlate a person to an account           | ExternalId                      |
| $userCorrelationAttribute     | The user attribute used to correlate a person to an account             | employeeId                      |


# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/