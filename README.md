![Gladiator](https://natgeo.imgix.net/factsheets/thumbnails/GladiatorSchool.jpg?auto=compress,format&w=1024&h=560&fit=crop)
(source: https://www.nationalgeographic.com.au/history/gladiator-school-discovery-reveals-hard-lives-of-ancient-warriors.aspx)

# LudusMagnus

> _“Force has no place where there is need of skill.”_ – Herodotus 

LudusMagnus is an automation project for creating CTF (Capture-The-Flag) and Defend training environments.
The main purpose of this tool, is to allow InfoSec professionals (both offensive and defensive) the ability to train for free.
This tool will deploy a closed network in Azure Cloud, that contains different Operating system, different roles, and awesome vulnerabilities (logic and technical alike). in that environment, we hid several flags (in a CTF-like way: __flag:{}__, where the content in the {} is the flag value), which should be discovered by the attacker and entered in the web application in this solution. Once the attacker submits the last flags (or gives-up and clicks the submit button) the web application will calculate a score based on the type of flags obtained, their relative score and the overall time elapsed.
For defenders, when the system is deployed, an Infection monkey (Thank you gurdicore!) vm is deployed as well and will start attacking the environemnt. The defenders role is to identify the attacks and halt them. Currently, we don't have a scoring system for the defenders (but we plan on deploying one in the future)

There are many possible use-cases for this tool. Some that we thought of are (we're happy to get more ideas and feedback from you):
* Training ground for Offensive professionals to test their skills against system in a (small) enterprise-like network
* Training ground for Defensive professionals to test their skills against system in a (small) enterprise-like network
* Provide the ability for hiring managers to assess candidates skills in hands-on exercises

BTW, The Ludus Magnus (also known as the Great Gladiatorial Training School) was the largest of the gladiatorial schools in Rome. (Wikipedia)


## Deploy an environment

You need to have:

1. An Azure Subscription (see <https://azure.microsoft.com/en-us/free>)
2. PowerShell installed (see <https://github.com/PowerShell/PowerShell/releases/tag/v6.1.0>)
3. Azure PowerShell Module installed (see <https://www.powershellgallery.com/packages/Az>)

**Note: Please remember to tear-down the sandbox environment when done, since your Azure subscription is billed for the costs!**

Then, open PowerShell (pwsh.exe), login to your Azure account and select your subscription:

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

If you'd like to contribute and/or improve the automation project and environment, you'll need to have a machine ready with several tools

### Preparing the build machine

For updating the solution environment and automation, you'll need a build machine with the following tools installed:

#### .NET Core 2.1

Download and install the relevant .NET Core Installer runtime package from:
<https://www.microsoft.com/net/download/dotnet-core/2.1>

#### PowerShell Core 6.1

Download and install the relevant package from: <https://github.com/PowerShell/PowerShell/releases/tag/v6.1.0>

#### Azure PowerShell Modules <https://www.powershellgallery.com/packages/Az>

To install the needed Azure Modules, open PowerShell (pwsh.exe) and run the following command:

```powershell
Install-Module -Name Az -Scope AllUsers -Force -Verbose
```

#### Desired State Configuration (DSC) Modules

To install the needed DSC Modules, open PowerShell (pwsh.exe) and run the following command:

```powershell
'ComputerManagementDsc', 'SqlServerDsc', 'xActiveDirectory', 'xNetworking', `
  'xPendingReboot', 'xStorage', 'xPSDesiredStateConfiguration', 'xWebAdministration' | 
    ForEach-Object { Install-Module -Name $_ -Scope AllUsers -Force -Verbose }
```
## Attacker instructions

After installing all the prerequisites above, run ```pwsh.exe ./Start-LudusMagnus.ps1``` in order to deploy the needed environment. 
Once the deployment is done, your favourite web browser will open up on the web application page that contains the following:
1. The JumpBox IP address you should RDP into.
2. The credentials to use on the JumpBox -  *the JumpBox is your starting point, and the credentials belongs to a user in the domain*.
3. A timer.
4. 10 flag input field to paste in the flags you would obtain - *You won't be able to know if the flags are valid until you finish the test and submit all of them*.
4. a "I'm done" submit button that can be used also if you didn't obtained all the flags.

Once you click the "I'm done" button, the flags you entered will be checked if they are correct, and a grade will be calculated based on:
- How many flags are correct
- The value of each flag (some of them worth more points than others)
- Overall time elapsed from starting the test until clicking the "I'm done" button

**Once again, make sure to tear-down the environment when you are done, or the costs will be billed to your Azure subscription!**

## Costs

This code is open-source, therefore free for private use. The Azure Cloud costs for hosting the environment is based on the Azure pricing (which are subject to change based on Microsoft decision).
While considering that, every new account that signs up for Azure subscriptions receives 200$ for free (Thank you Microsoft!) and currently (Nov 2018) the costs of running this environment for 24 hours is approx. 160$.

#

> Created by Martin Schvartzman (@martin77s) and Roei Sherman (@x_Freedom)
