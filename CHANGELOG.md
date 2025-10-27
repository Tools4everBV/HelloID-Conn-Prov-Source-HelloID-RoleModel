# Change Log
All notable changes to this project will be documented in this file. The format is based on Keep a Changelog, and this project adheres to Semantic Versioning.



## [1.3.1] - 2025-10-27

### Added
- **GitHub workflows for automation:**
  - Added `.github/workflows/createRelease.yaml` to automate release creation based on CHANGELOG.md.
  - Added `.github/workflows/verifyChangelog.yaml` to enforce CHANGELOG.md updates on pull requests.

## [1.3.0] - 2025-01-29

### Added
- Role mining Exchange Online groups ([#30](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/30))

---

## [1.2.7] - 2025-01-29

### Changed
- Enhance AD user retrieval and logging in PowerShell script ([#28](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/28))
- Fix nesting Entra ([#29](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/29))

---

## [1.2.6] - 2024-11-11

### Added
- Feature: add HelloID logging ([#26](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/26))
- Feature: add progress of the script ([#27](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/27))

---

## [1.2.5] - 2024-09-02

### Added
- Support for nested levels and dummy permission ([#22](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/22))

### Fixed
- Calculate dummy permission even if person has no other permissions ([#23](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/23))

---

## [1.2.4] - 2024-07-26

### Fixed
- Calculate dummy permission even if person has no other permissions ([#21](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/21))

---

## [1.2.3] - 2024-05-17

### Fixed
- Fix multiple entitlement names ([#20](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/20))

---

## [1.2.2] - 2024-05-17

### Changed
- Update README.md ([#1](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/1))
- Update Get-HelloIDPersonGroupMembers.ps1 ([#2](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/2))
- V1.1.1 ([#3](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/3))
- Fix contractPropertiesToInclude bug ([#4](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/4))
- Update Get-HelloIDPersonGroupMembers.ps1 ([#5](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/5))
- feature/add status of the contract active/inactive ([#7](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/7))
- feature/Add support for no startdate per employee ([#8](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/8))
- Initial release ([#10](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/10))
- Release v1 AD version ([#12](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/12))
- Initial commit of new scripts for EXO ([#11](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/11))
- Fix: corrected readmes ([#14](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/14))
- Fix: always set content $groupsWithMembers ([#15](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/15))
- Feature added reporting for missing persons and/or account ([#16](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/16))
- Feat: added nesting support for AzureAD ([#18](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/18))
- Fix removed column status in entitlements.csv ([#19](https://github.com/Tools4everBV/HelloID-Conn-Prov-Source-HelloID-RoleModel/pull/19))

--- 

## [1.2.1] - 29-01-2025

### Added
- **Exchange Online Groups:**
  - Initial release of `Get-EXOGroupMembers.ps1` for retrieving Exchange Online group memberships, including support for nested group memberships and dummy group assignment.
  - Integration with Entra ID Graph API for user and group retrieval.
  - Export of person, user, group, and permission data to CSV and XML formats.
  - Support for evaluation and granted entitlements reports from HelloID Provisioning.
  - Security logging for persons without correlation value, user, or permissions.
  - Modular functions for error handling, logging, and data expansion.

## [1.2.0] - 01-09-2023

### Added
- **Active Directory (AD):**
  - Initial release of `Get-ADPersonGroupMembers.ps1` for generating CSV overviews of AD group memberships for role mining.

- **Exchange Online Shared Mailboxes:**
  - Initial release of `Get-EXOSharedMailboxMembers.ps1` for reporting on shared mailbox memberships.

## [1.1.0] - 17-04-2023

### Added
- **Entra ID:**
  - Initial release of `Get-EntraIDPersonGroupMembers.ps1` for generating CSV overviews of Entra ID group memberships for role mining.

## [1.0.0] - 11-08-2021

### Added
- **HelloID:**
  - Initial release of `Get-HelloIDRoleModel.ps1` and `Get-HelloIDPersonGroupMembers.ps1` for generating role model and group membership reports from HelloID Vault data.

