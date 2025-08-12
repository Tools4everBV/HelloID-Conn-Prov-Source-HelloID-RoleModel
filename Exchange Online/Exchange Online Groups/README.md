# HelloID-Conn-Prov-Source-HelloID-RoleModel

> [!IMPORTANT]
> This repository contains the connector and configuration code only. The implementer is responsible to acquire the connection details such as username, password, certificate, etc. You might even need to sign a contract or agreement with the supplier before implementing this connector. Please contact the client's application manager to coordinate the connector requirements.    |

> [!WARNING]
> With this Application Registration you can see a lot of data. Be careful with de credentials.

<!-- Description -->
## Description
This Powershell script generates an overview to support building a role model

<!-- TABLE OF CONTENTS -->
## Table of Contents
- [HelloID-Conn-Prov-Source-HelloID-RoleModel](#helloid-conn-prov-source-helloid-rolemodel)
  - [Description](#description)
  - [Table of Contents](#table-of-contents)
  - [Limitation on the scripts](#limitation-on-the-scripts)
  - [User information](#user-information)
    - [Get-EXOSharedMailboxMembers](#get-exosharedmailboxmembers)
  - [Script outcome](#script-outcome)
  - [PowerShell setup script](#powershell-setup-script)
  - [Update connection and configuration details](#update-connection-and-configuration-details)
    - [Details Get-EXOSharedMailboxMembers](#details-get-exosharedmailboxmembers)
  - [Getting the Azure AD graph API access](#getting-the-azure-ad-graph-api-access)
    - [Application Registration](#application-registration)
    - [Configuring App Permissions](#configuring-app-permissions)
    - [Authentication and Authorization](#authentication-and-authorization)
    - [Assign Azure AD roles to the application](#assign-azure-ad-roles-to-the-application)
    - [Connection settings](#connection-settings)
- [HelloID Docs](#helloid-docs)

## Limitation on the scripts
This script with the Application Registration can only look at Mail-enabled security groups, distribution groups and shared mailboxes.

## User information
With the local CSV export, you can make a report that gives insight into the current situation of Shared mailboxes. The exported data can be input for the business rules yet
to be created.

### Get-EXOSharedMailboxMembers
This script is used by middle to big organizations. This overview offers insight into the memberships of the employees of the organizations. If the CSV export is turned into a pivot table, several reports can be made.

## Script outcome
After configuring and running the "Get-EXOSharedMailboxMembers.ps1" script, the following outcome will be automatically generated. 
-   CSV file on a configured local location. 

## PowerShell setup script
The PowerShell scripts "Get-EXOSharedMailboxMembers.ps1" contains a complete PowerShell script create a report for RoleMining purposes.  
1.  Create Application Registration for Azure AD and Exchange Online, see description below
2.  Download the "Get-EXOGroupMembers.ps1" file
3.  Open it in your favorite PowerShell console/editor
4.  Update the connection and configuration details in the script's header
5.  Run the script on a machine with PowerShell support and an internet connection

## Update connection and configuration details
### Details Get-EXOSharedMailboxMembers
| Variable name               | Description                                                                                                                              | Example value                        |
| --------------------------- | ---------------------------------------------------------------------------------------------------------------------------------------- | ------------------------------------ |
| $CertificateAuthentication  | set to `$true` when authenticating with a certificate                                                                                    | `$true` or `$false`                  |
| $EntraIDtenantID            | EntraID tenant id                                                                                                                        | ********                             |
| $EntraIDAppId               | EntraID app id                                                                                                                           | ********                             |
| $EntraIDAppSecret           | EntraID app secret, only needed when connecting with a secret                                                                            | ********                             |
| $AppCertificateBase64String | Base64 string of your certificate, only needed when connecting with a certificate                                                        | ********                             |
| $AppCertificatePassword     | Password of your certificate, only needed when connecting with a certificate                                                             | ********                             |
| $exportPath                 | The path where the csv file will be exported (Make sure the exportPath contains a trailing \ in Windows or / in Unix/MacOS environments) | C:\HelloID\RoleminingExchangeOnline\ |
| $evaluationSystemName       | The name of the system on which to check the permissions in the evaluation (Only required when using the evaluation report)              | Exchange Online                      |
| $entitlementsSystemName     | The name of the system on which to check the permissions in the evaluation (Only required when using the entitlements report)            | Exchange Online                      |
| $personCorrelationAttribute | The person attribute used to correlate a person to an account                                                                            | ExternalId                           |
| $userCorrelationAttribute   | The user attribute used to correlate a person to an account                                                                              | employeeId                           |


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

>__Get AD users__
To assign your application the right permissions, navigate to <b>Azure Portal > Azure Active Directory >App Registrations</b>.
Select the application we created before, and select “<b>API Permissions</b>” or “<b>View API Permissions</b>”.
To assign a new permission to your application, click the “<b>Add a permission</b>” button.
From the “<b>Request API Permissions</b>” screen click “<b>Microsoft Graph</b>”.
For this connector the following permissions are used as <b>Application permissions</b>:
*	Read all user’s full profiles by using <b><i>User.Read.All</i></b>

>__Get Exchange online permissions__
To assign your application the right permissions, navigate to <b>Azure Portal > Azure Active Directory >App Registrations</b>.
Select the application we created before, and select “<b>API Permissions</b>” or “<b>View API Permissions</b>”.
To assign a new permission to your application, click the “<b>Add a permission</b>” button.
From the “<b>Request API Permissions</b>” screen click “<b>Office 365 Exchange Online</b>”.
For this connector the following permissions are used as <b>Application permissions</b>:
> _The Office 365 Exchange Online might not be a selectable API. In thise case, select "APIs my organization uses" and search here for "Office 365 Exchange Online"__
*	Manage Exchange As Application <b><i>Exchange.ManageAsApp</i></b>

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

### Assign Azure AD roles to the application
Azure AD has more than 50 admin roles available. The <b>Exchange Administrator</b> role should provide the required permissions for any task in Exchange Online PowerShell. However, some actions may not be allowed, such as managing other admin accounts, for this the Global Administrator would be required. and Exchange Administrator roles. Please note that the required role may vary based on your configuration.
* To assign the role(s) to your application, navigate to <b>Azure Portal > Azure Active Directory > Roles and administrators</b>.
* On the Roles and administrators page that opens, find and select one of the supported roles e.g. “<b>Exchange Administrator</b>” by clicking on the name of the role (not the check box) in the results.
* On the Assignments page that opens, click the “<b>Add assignments</b>” button.
* In the Add assignments flyout that opens, <b>find and select the app that we created before</b>.
* When you're finished, click <b>Add</b>.
* Back on the Assignments page, <b>verify that the app has been assigned to the role</b>.

For more information about the permissions, please see the Microsoft docs:
* [Permissions in Exchange Online](https://learn.microsoft.com/en-us/exchange/permissions-exo/permissions-exo).
* [Find the permissions required to run any Exchange cmdlet](https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions?view=exchange-ps).
* [View and assign administrator roles in Azure Active Directory](https://learn.microsoft.com/en-us/powershell/exchange/find-exchange-cmdlet-permissions?view=exchange-ps).

### Connection settings
The following settings are required to connect to the API.

| Setting            | Description                                               |
| ------------------ | --------------------------------------------------------- |
| EntraID Tenant ID  | Id of the Entra tenant                                    |
| EntraID App ID     | Id of the Entra app                                       |
| EntraID App Secret | Secret of the Entra app. This is the Value of the secret. |

# HelloID Docs
The official HelloID documentation can be found at: https://docs.helloid.com/
