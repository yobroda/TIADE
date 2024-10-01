# **TIADE.ps1**
It is a powershell script that can be used for Initial Enumeration of a Multi-Trust Active Directory Environment by only leveraging the AD Module

[By Yobroda](https://x.com/itsyobroda "yobroda")

## How to use it?
```powershell

PS C:\Users\User\Downloads\TIADE\Files> .\TIADE.ps1
```
## Who is this script for?
As this script utilises only AD Module (the dll, psd1 and corresponding files have been taken from Microsoft Windows Server 2022 EVAL Version), it can be used by System Administrators and Red Teamers/Pentesters alike in their engagements.

## What are the key benefits of this script?
This is an automation script built around to utilise AD Module, which is a Microsoft signed binary, so it must not ring alarm bells. It also works equally well in [Invisi-Shell](https://github.com/OmerYa/Invisi-Shell)  

## What is the UVP of this script?
It first collects all the domains in the multi-trust environment, iterate each of them one by one to enumerate the below mentioned points. 

## What does it enumerate?
* Domain Details such as Domain SID, Forest, DN, Netbios name, PDC Emulator, child domains if any etc.
* Password Policy
* Kerberos Policy
* Trusts (Direction of Trust and access, Delegation enabled across trust, SID filtering etc.)
* Users (Description, logon count)
* Disabled Users
* Users whose password never expires
* Account with no PreAuth required
* Computers (Servers with Ipv4 Address)
* LAPS password for systems (supported only for current domain and if the current user has privileges)
* Service Accounts (User Accounts with SPN)
* Real Service Accounts (GMSA)
* DA's, EA's, Groups with Admin or master keyword
* Current User Group Membership (supported only for current domain)
* Group Membership of All Users
* ACEs over DAs
* Principals having DC Sync Rights
* Unconstrained Delegation
* Constrained Delegation
* RBCD
* Accounts that are marked sensitive and cannot be delegated
* FSPs
* Shadow Security Principals
* AD Connect User for Azure
* Interesting ACLs (only for the Current User for current domain)
* OUs and their corresponding GPOs
* Restricted Groups

## What was the Motivation behind this tool?
[Read Here !!](https://blog.radifine.com/tiade-corresponding-blog-for-script-release-d0aef9037382)

## What is the Roadmap?
* Random Sleep Generator 
* Guid Mapping
* Lot of refactoring to make efficient code
* Lots of optimization (example - default output removal for disabled accounts)
* ACL Scanner
* SID Mapping
* Interface to accept user inputs for LDAP queries
* Protected Users
* ADCS
* Possible Invoke-ShareFinder
* Possible Invoke-SessionHunter
* Possible Get-NetFileServer
* Possible Invoke-FileFinder
* Possible port to full fledged C# .Net application (possibly not the one that runs this script in a powershell runspace)

### Would like to contribute to this repo? - Feel free to reach out to me on X/Twitter. The link to my handle is mentioned at the start of this README.md
