# HelloID-Conn-Prov-Source-HelloID-RoleModel

| :information_source: Information |
|:---------------------------|
| This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.       |

<br />

<!-- Version -->
## Version
| Version | Description | Date |
| - | - | - |
| 1.0.0   | Initial release | 2023/04/17  |

> __This is the initial version, please let us know about any bugs/features!__
## Warning: 
With this Application Registration you can see a lot of data. Be careful with de credentials.

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
    - [Get-HelloIDPersonGroupMembers](#get-helloidpersongroupmembers)
  - [Script outcome](#script-outcome)
  - [PowerShell setup script](#powershell-setup-script)
  - [Update connection and configuration details](#update-connection-and-configuration-details)
    - [Details Get-HelloIDPersonGroupMembers](#details-get-helloidpersongroupmembers)
  - Introduction
  - Getting the Azure AD graph API access
    - Application Registration
    - Configuring App Permissions
    - Authentication and Authorization
    - Connection settings
- [HelloID Docs](#helloid-docs)

## Limitation on the scripts
This script with the Application Registration can only look at Microsoft 365 and Security groups in AzureAD. 

## User information
With the local CSV export, you can make a report that gives insight into the current situation in the Azure Active Directory. The exported data can be input for the business rules yet
to be created.

### Get-HelloIDPersonGroupMembers
This script is used by middle to big organizations. This overview offers insight into the memberships of the employees of the organizations. If the CSV export is turned into a pivot table, several reports can be made.

## Script outcome
After configuring and running the "Get-HelloIDRoleModel.ps1" or "Get-HelloIDPersonGroupMembers.ps1" script, the following outcome will be automatically generated. 
-   CSV file on a configured local location. 
-   Export data to an HTML path (only with Get-HelloIDRoleModel)

## PowerShell setup script
The PowerShell scripts "Get-HelloIDPersonGroupMembers.ps1" contains a complete PowerShell script create a report for RoleMining purposes. Please follow the steps below to set up and run the “Get-HelloIDRoleModel.ps1” PowerShell script in your environment. 
1.  Create Application Registration, see description below
2.  Download the " Get-HelloIDRoleModel.ps1" file
3.  Open it in your favorite PowerShell console/editor
4.  Update the connection and configuration details in the script's header
6.  Run the script on a machine with PowerShell support and an internet connection

## Update connection and configuration details
### Details Get-HelloIDPersonGroupMembers
| Variable name                 | Description                                                             | Example value                   |
| ----------------------------- | ----------------------------------------------------------------------- | ------------------------------- |
| $AADtenantID                  | API Key value of your HelloID environment                               | ********                        |
| $AADAppId                     | API secret value of your HelloID environment                            | ********                        |
| $AADAppSecret                 | API secret value of your HelloID environment                            | ********                        |
| $exportPath                   | The path where the csv file will be exported (Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments)   | C:\HelloID\Provisioning\RoleMining_export\PersonGroupMembers\  |
| $evaluationSystemName         | The name of the system on which to check the permissions in the evaluation (Only required when using the evaluation report) | Microsoft Active Directory |
| $entitlementsSystemName       | The name of the system on which to check the permissions in the evaluation (Only required when using the entitlements report) | Microsoft Active Directory |
| $personCorrelationAttribute   | The person attribute used to correlate a person to an account           | ExternalId                      |
| $userCorrelationAttribute     | The user attribute used to correlate a person to an account             | employeeId                      |


## Introduction
The interface to communicate with Microsoft Azure AD is through the Microsoft Graph API.

For this connector we have the option to correlate to existing Azure AD users and provision (dynamic) groupmemberships.
  >__Currently only Microsoft 365 and Security groups are supported by the [Microsoft Graph API](https://docs.microsoft.com/en-us/graph/api/resources/groups-overview?view=graph-rest-1.0).<br>
This means we cannot manage Mail-enabled security groups and Distribution groups, These can only be managed using the [Exchange Online connector](https://github.com/Tools4everBV/HelloID-Conn-Prov-Target-ExchangeOnline).__

If you want to create Azure accounts, please use the built-in Microsoft Azure Active Directory target system.

<!-- GETTING STARTED -->
## Getting the Azure AD graph API access

By using this connector you will have access to user and groupdata that can be used for role mining.

### Application Registration
The first step to connect to Graph API and make requests, is to register a new <b>Azure Active Directory Application</b>. The application is used to connect to the API and to manage permissions.

* Navigate to <b>App Registrations</b> in Azure, and select “New Registration” (<b>Azure Portal > Azure Active Directory > App Registration > New Application Registration</b>).
* Next, give the application a name. In this example we are using “<b>HelloID PowerShell</b>” as application name.
* Specify who can use this application (<b>Accounts in this organizational directory only</b>).
* Specify the Redirect URI. You can enter any url as a redirect URI value. In this example we used http://localhost because it doesn't have to resolve.
* Click the “<b>Register</b>” button to finally create your new application.

Some key items regarding the application are the Application ID (which is the Client ID), the Directory ID (which is the Tenant ID) and Client Secret.

### Configuring App Permissions
The [Microsoft Graph documentation](https://docs.microsoft.com/en-us/graph) provides details on which permission are required for each permission type.

To assign your application the right permissions, navigate to <b>Azure Portal > Azure Active Directory >App Registrations</b>.
Select the application we created before, and select “<b>API Permissions</b>” or “<b>View API Permissions</b>”.
To assign a new permission to your application, click the “<b>Add a permission</b>” button.
From the “<b>Request API Permissions</b>” screen click “<b>Microsoft Graph</b>”.
For this connector the following permissions are used as <b>Application permissions</b>:
*	Read all user’s full profiles by using <b><i>User.Read.All</i></b>
*	Read all groups in an organization’s directory by using <b><i>Group.Read.All</i></b>
*	Read data to an organization’s directory by using <b><i>Directory.Read.All</i></b>

Some high-privilege permissions can be set to admin-restricted and require an administrators consent to be granted.

To grant admin consent to our application press the “<b>Grant admin consent for TENANT</b>” button.

### Authentication and Authorization
There are multiple ways to authenticate to the Graph API with each has its own pros and cons, in this example we are using the Authorization Code grant type.

*	First we need to get the <b>Client ID</b>, go to the <b>Azure Portal > Azure Active Directory > App Registrations</b>.
*	Select your application and copy the Application (client) ID value.
*	After we have the Client ID we also have to create a <b>Client Secret</b>.
*	From the Azure Portal, go to <b>Azure Active Directory > App Registrations</b>.
*	Select the application we have created before, and select "<b>Certificates and Secrets</b>". 
*	Under “Client Secrets” click on the “<b>New Client Secret</b>” button to create a new secret.
*	Provide a logical name for your secret in the Description field, and select the expiration date for your secret.
*	It's IMPORTANT to copy the newly generated client secret, because you cannot see the value anymore after you close the page.
*	At last we need to get the <b>Tenant ID</b>. This can be found in the Azure Portal by going to <b>Azure Active Directory > Overview</b>.

### Connection settings
The following settings are required to connect to the API.

| Setting     | Description |
| ------------ | ----------- |
| Azure AD Tenant ID | Id of the Azure tenant |
| Azure AD App ID | Id of the Azure app |
| Azure AD App Secret | Secret of the Azure app |

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
