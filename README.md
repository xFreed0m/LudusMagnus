# LudusMagnus
> _“Force has no place where there is need of skill.”_ – Herodotus 


LudusMagnus is an automation project for creating CTF (Capture-The-Flag) and Defend training environments.
The main purpose of this tool, is to allow InfoSec professionals (both offensive and defensive) the ability to train for free.
This tool will deploy a closed network in Azure Cloud, that contains different Operating system, different roles, and awesome vulnerabilities (logic and technical alike). in that environment, we hid several flags (in a CTF-like way: __flag:{}__, where the content in the {} is the flag value), which should be discovered by the attacker and entered in the web application in this solution. Once the attacker submits the last flags (or gives-up and press the stop button) the web application will calculate a score based on the type of flags obtained, their amount and the overall time used.
For defenders, when the system is deployed, an Infection monkey (Thank you gurdicore!) vm is deployed as well and will start attacking the environemnt, and the defenders should try to identify the attacks and halt them. Currently, we don't have a scoring system for the defenders (but we plan on deploying one in the future!)

There are many possible use-cases for this tool, and below are only some that we could think of (will be happy to hear more from you):
* Training ground for Offensive professionals to test their skills against system in a (small) enterprise-like network
* Training ground for Defensive professionals to test their skills against system in a (small) enterprise-like network
* Provide the ability for hiring managers to assess candidates skills in hands-on exercises

BTW, The Ludus Magnus (also known as the Great Gladiatorial Training School) was the largest of the gladiatorial schools in Rome. (Wikipedia)


## Deploy an environment

You need to have:

1. An Azure Subscription (<https://azure.microsoft.com/en-us/free>)
2. PowerShell installed (<https://github.com/PowerShell/PowerShell/releases/tag/v6.1.0>)
3. Azure PowerShell Module installed (<https://www.powershellgallery.com/packages/Az>)

**Please note: if you won't tear-down the environment when done, you WILL BE billed in your subscription for the costs!**

Then, login to your Azure account and select your subscription:

```powershell
Login-AzAccount
Get-AzSubscription
Select-AzSubscription -Subscription '00000000-0000-0000-0000-000000000000'
```

And simply run the Start-LudusMagnus.ps1 script:

```powershell
./Start-LudusMagnus.ps1
```

## Updating the Sandbox environment

### Prepare the build machine

For updating the solution environment and automation, you'll need a build machine with the following tools installed:

#### .NET Core 2.1

Download and install the relevant .NET Core Installer runtime package from:
<https://www.microsoft.com/net/download/dotnet-core/2.1>

#### PowerShell Core 6.1

Download and install the relevant package from: <https://github.com/PowerShell/PowerShell/releases/tag/v6.1.0>

#### Azure PowerShell Modules <https://www.powershellgallery.com/packages/Az>

To install the needed Azure Modules, open PowerShell, and run the following command:

```powershell
Install-Module -Name Az -Scope AllUsers -Force -Verbose
```

#### Desired State Configuration (DSC) Modules

To install the needed DSC Modules, open PowerShell, and run the following command:

```powershell
'ComputerManagementDsc', 'SqlServerDsc', 'xActiveDirectory', 'xNetworking', 'xPendingReboot', 'xStorage', 'xWebAdministration' |
ForEach-Object { Install-Module -Name $_ -Scope AllUsers -Force -Verbose }
```

## Costs
This code is open-source, therefore free for private use. The Azure Cloud costs for hosting the environment is based on Azure pricing (which are subject to change based on Microsoft decision).
While considering that, every new account that signs up for Azure subscriptions receives 200$ for free (Thanks Microsoft!) and currently (Nov 2018) the costs of running this environment for 24 hours is approx. 160$.

> created by Martin Schvartzman and Roei Shepherd (@x_Freedom)
