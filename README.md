# LudusMagnus

LudusMagnus is an automation project for creating CTF (Cpature-The-Flag) and Defend training environments

## Deploy an environment

You need to have:

1. An Azure Subscription (<https://azure.microsoft.com/en-us/free>)
2. PowerShell installed (<https://github.com/PowerShell/PowerShell/releases/tag/v6.1.0>)
3. Azure PowerShell Module installed (<https://www.powershellgallery.com/packages/Az>)

Then, login to your Azure account and select your subscription:

```powershell
Login-AzAccount
Get-AzSubscription
Select-AzSubscription -Subscription '00000000-0000-0000-0000-000000000000'
```

And simply run the Start-PracticeSandboxDeployment.ps1 script:

```powershell
./Start-SandboxDeployment.ps1
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
