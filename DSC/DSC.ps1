 #region Configurations
 
Configuration ADDS {

    [CmdletBinding()]

    param (
		[string] $FlagPrefix = 'Flag',
        [PSCredential] $DomainCreds,
        [PSCredential] $JumpAdminCreds,
        [string] $ADUsersUri,
        [string] $Flag2Value,
        [string] $Flag7Value,
        [string] $Flag9Value,
        [PSCredential] $RunnerUser,
        [PSCredential] $SqlSvc
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xPendingReboot
    Import-DscResource -ModuleName StorageDsc
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    Publish-LudusMagnusModule
    $DomainName = Split-Path $DomainCreds.UserName

    New-Object System.Management.Automation.PSCredential -ArgumentList (
        'NT AUTHORITY\SYSTEM', ("$($FlagPrefix):{$Flag9Value}" | ConvertTo-SecureString -AsPlainText -Force)
    ) | Export-CliXml -Path C:\Windows\Temp\flag9.xml

    node localhost {

        Write-Verbose 'Creating configuration for the LocalConfigurationManager' -Verbose
        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true
            AllowModuleOverwrite = $true
            ActionAfterReboot    = 'ContinueConfiguration'
        }

        Write-Verbose 'Creating configuration for the Windows Features:' -Verbose
        $Features = @(
            'AD-Domain-Services',
            'RSAT-ADDS',
            'RSAT-AD-Tools',
            'RSAT-AD-PowerShell',
            'RSAT-Role-Tools',
            'RSAT-DNS-Server',
            'GPMC',
            'DNS'
        )

        $Features.ForEach( {
                Write-Verbose "`t - $_" -Verbose
                WindowsFeature "$_" {
                    Ensure = 'Present'
                    Name   = $_
                }
            } )

        Write-Verbose 'Creating configuration for ADDSFolder' -Verbose
        File ADDSFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = 'C:\ADDS'
        }

        Write-Verbose 'Creating configuration for CreateUsersCsv' -Verbose
        xRemoteFile CreateADUsersCsv {
            Uri             = $ADUsersUri
            DestinationPath = 'C:\ADDS\ADUsers.csv'
            DependsOn       = '[File]ADDSFolder'
        }


        Write-Verbose 'Creating configuration for CreateForest' -Verbose
        xADDomain CreateForest {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = 'C:\ADDS\NTDS'
            LogPath                       = 'C:\ADDS\NTDS'
            SysvolPath                    = 'C:\ADDS\Sysvol'
            ForestMode                    = 'Win2008R2'
            DomainMode                    = 'Win2008R2'
            DependsOn                     = '[WindowsFeature]AD-Domain-Services', '[xRemoteFile]CreateADUsersCsv', '[File]ADDSFolder'
        }

        Write-Verbose 'Creating configuration for Flag7' -Verbose
        $Flag7Path = 'C:\Users\Default\Pictures\logo.png'
        script CreateFlag7 {

            TestScript = {
                Test-Path -Path $using:Flag7Path
            }

            GetScript  = {
                @{Result = (Get-Item -Path $using:Flag7Path -ErrorAction SilentlyContinue)}
            }

            SetScript  = {
                New-LudusMagnusPngImage -Path $using:Flag7Path -Text "$($using:FlagPrefix):{$($using:Flag7Value)}"
            }
        }


        Write-Verbose 'Creating configuration for CreateUsers' -Verbose
        script CreateADUsers {

            TestScript = {
                Test-Path -Path 'C:\ADDS\ADUsers.flag'
            }

            GetScript  = {
                @{Result = (Get-Content -Path 'C:\ADDS\ADUsers.flag')}
            }

            SetScript  = {
                Set-Content -Path 'C:\ADDS\ADUsers.flag' -Value (Get-Date -Format yyyy-MM-dd-HH-mm-ss-ff)
                Import-LudusMagnusADUsers -CsvPath 'C:\ADDS\ADUsers.csv' -Flag2Value $using:Flag2Value -RunnerUser $using:RunnerUser -SqlSvc $using:SqlSvc
            }
            DependsOn  = '[xRemoteFile]CreateADUsersCsv', '[xADDomain]CreateForest'
        }
    }
}


Configuration JumpBox {

    [CmdletBinding()]

    param (
		[string] $FlagPrefix = 'Flag',
        [PSCredential] $DomainCreds,
        [string] $Flag0Value,
        [string] $Flag1Value,
        [string] $JumpBoxAdmin,
        [PSCredential] $RunnerUser
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName ComputerManagementDsc

    $ComputerName = $env:ComputerName
    $DomainName = Split-Path $DomainCreds.UserName
    $flag1Path = Join-Path -Path 'C:\Users\Default\Documents' -ChildPath 'app.exe'
    $DomainCreds.GetNetworkCredential().password | Out-File -FilePath C:\Windows\Temp\pass.txt

    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true and DHCPEnabled=true' | ForEach-Object {
        $_.InvokeMethod('ReleaseDHCPLease', $null)
        $_.InvokeMethod('RenewDHCPLease', $null)
    }

    node localhost {

        Write-Verbose 'Creating configuration for the LocalConfigurationManager' -Verbose
        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true
            AllowModuleOverwrite = $true
            ActionAfterReboot    = 'ContinueConfiguration'
        }

        Write-Verbose 'Creating configuration for the Windows Features:' -Verbose
        $Features = @(
            'RSAT-AD-PowerShell',
            'Telnet-Client'
        )

        $Features.ForEach( {
                Write-Verbose "`t - $_" -Verbose
                WindowsFeature "$_" {
                    Ensure = 'Present'
                    Name   = $_
                }
            } )

        Write-Verbose 'Creating configuration for DisableLoopbackCheck' -Verbose
        Registry DisableLoopbackCheck {
            Ensure    = 'Present'
            Key       = 'HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\Lsa'
            ValueName = 'DisableLoopbackCheck'
            ValueData = '1'
            ValueType = 'Dword'
        }

        Write-Verbose 'Creating configuration for Flag 0' -Verbose
        File Flag0 {
            Ensure          = 'Present'
            Type            = "File"
            DestinationPath = "C:\Windows\system32\drivers\etc\flag0.txt"
            Contents        = "$($FlagPrefix):{$Flag0Value}"
        }

        Write-Verbose 'Creating configuration for flag 1' -Verbose
        Script Flag1 {
            TestScript = {
                Test-Path $using:flag1Path -PathType Leaf
            }
            SetScript  = {
                $tempFile = 'C:\Windows\flag1.cs'
                @"
using System;
namespace ns {
    class Program {
        static int Main(string[] args) {
		string FlagValue = "$($FlagPrefix):{$using:Flag1Value}";
		Console.WriteLine("Bad command or flag name");
		return 0;
        }
    }
}
"@ | Set-Content -Path $tempFile
                C:\Windows\Microsoft.NET\Framework\v4.0.30319\csc.exe /t:exe /out:"$using:flag1Path" $tempFile /w:1
                Remove-Item -Path $tempFile -Force -ErrorAction SilentlyContinue
            }
            GetScript  = {
                @{Result = (Get-Content -Path $using:flag1Path -Raw -ErrorAction SilentlyContinue)}
            }
        }

        Write-Verbose 'Creating configuration for WaitforDomain' -Verbose
        xWaitForADDomain WaitForDomain {
            DomainName       = $DomainName
            RetryCount       = 60
            RetryIntervalSec = 15
        }

        Write-Verbose 'Creating configuration for DomainJoin' -Verbose
        Computer DomainJoin {
            Name       = $ComputerName
            DomainName = $DomainName
            Credential = $DomainCreds
            DependsOn  = '[xWaitForADDomain]WaitForDomain'
        }

        Write-Verbose 'Assigning configuration for user runner' -Verbose
        Group LocalAdministrators {
            Ensure           = 'Present'
            GroupName        = 'Administrators'
            MembersToInclude = @($JumpBoxAdmin, $RunnerUser.UserName)
            DependsOn        = '[Computer]DomainJoin'
        }

        Write-Verbose 'Assigning configuration for runner task' -Verbose
        ScheduledTask RunnerTask {
            TaskName            = "Custom maintenance tasks"
            ActionExecutable    = "C:\windows\system32\WindowsPowerShell\v1.0\powershell.exe"
            ActionArguments     = "-File `"\\nosuchcomputer\scripts\script.ps1`""
            ScheduleType        = 'Once'
            RepeatInterval      = '00:01:00'
            RepetitionDuration  = 'Indefinitely'
            RunLevel            = 'Highest'
            ExecuteAsCredential = $RunnerUser
            DependsOn           = '[Group]LocalAdministrators'
        }
    }
}


Configuration SQL {

    [CmdletBinding()]

    param (
		[string] $FlagPrefix = 'Flag',
        [PSCredential] $DomainCreds,
        [string] $DatabaseName,
        [string] $Flag5Value,
        [PSCredential] $RunnerUser,
        [PSCredential] $SqlSvc

    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName SqlServerDsc

    Publish-LudusMagnusModule
    $InstanceName = 'MSSQLSERVER'
    $ComputerName = $env:ComputerName
    $DomainName = Split-Path $DomainCreds.UserName
    $NewLocalCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        (Split-Path $DomainCreds.UserName -Leaf), (Initialize-LudusMagnusPassword | ConvertTo-SecureString -AsPlainText -Force)
    )

    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true and DHCPEnabled=true' | ForEach-Object {
        $_.InvokeMethod('ReleaseDHCPLease', $null)
        $_.InvokeMethod('RenewDHCPLease', $null)
    }

    node localhost {

        Write-Verbose 'Creating configuration for the LocalConfigurationManager' -Verbose
        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true
            AllowModuleOverwrite = $true
            ActionAfterReboot    = 'ContinueConfiguration'
        }

        Write-Verbose 'Creating configuration for ChangeLocalAdminPassword' -Verbose
        User ChangeLocalAdminPassword {
            Ensure   = 'Present'
            UserName = $NewLocalCreds.UserName
            Password = $NewLocalCreds
        }

        Write-Verbose 'Creating configuration for the DatabaseEngineFirewallRule' -Verbose
        Firewall DatabaseEngineFirewallRule {
            Direction   = 'Inbound'
            Name        = 'SQL-Server-Database-Engine-TCP-In'
            DisplayName = 'SQL Server Database Engine (TCP-In)'
            Description = 'Inbound rule for SQL Server to allow TCP traffic for the Database Engine.'
            Group       = 'SQL Server'
            Action      = 'Allow'
            Enabled     = 'True'
            Protocol    = 'TCP'
            LocalPort   = '1433'
            Ensure      = 'Present'
        }

        Write-Verbose 'Creating configuration for the SQLConfigPriorityBoost' -Verbose
        SqlServerConfiguration SQLConfigPriorityBoost {
            ServerName     = $ComputerName
            InstanceName   = $InstanceName
            OptionName     = 'priority boost'
            OptionValue    = 1
            RestartService = $false
        }

        Write-Verbose 'Creating configuration for the SqlLogin' -Verbose
        SqlServerLogin SqlLogin {
            Ensure                         = 'Present'
            ServerName                     = $ComputerName
            Name                           = 'SqlLogin'
            LoginType                      = 'SqlLogin'
            InstanceName                   = $InstanceName
            LoginCredential                = $SqlSvc
            LoginMustChangePassword        = $false
            LoginPasswordExpirationEnabled = $true
            LoginPasswordPolicyEnforced    = $true
        }

        Write-Verbose 'Creating configuration for the SqlServerRole' -Verbose
        SqlServerRole SqlServerRole {
            Ensure         = 'Present'
            ServerRoleName = 'sysadmin'
            ServerName     = $ComputerName
            InstanceName   = $InstanceName
            DependsOn      = '[SqlServerLogin]SqlLogin'
        }

        Write-Verbose 'Creating configuration for the CreateDatabase' -Verbose
        SqlDatabase CreateDatabase {
            Ensure       = 'Present'
            ServerName   = $ComputerName
            InstanceName = $InstanceName
            Name         = $DatabaseName
        }

        Write-Verbose 'Creating configuration for the SqlBrowser' -Verbose
        Service SqlBrowser {
            Ensure      = 'Present'
            Name        = 'SQLBrowser'
            StartupType = "Automatic"
            State       = "Running"
            Credential  = $NewLocalCreds
            DependsOn   = '[User]ChangeLocalAdminPassword'
        }

        Write-Verbose 'Creating configuration for Flag 5' -Verbose
        script Flag5 {

            TestScript = {
                $res = ""; $ret = $false
                $Connection = New-Object System.Data.SQLClient.SQLConnection
                $Connection.ConnectionString = 'Integrated Security=SSPI;Persist Security Info=False;Data Source={0}' -f $env:ComputerName
                try {
                    $Connection.Open()
                    $Command = New-Object System.Data.SQLClient.SQLCommand
                    $Command.Connection = $Connection
                    $Command.CommandText = ("SET NOCOUNT ON; USE [{0}]; IF NOT EXISTS (SELECT * FROM sysobjects WHERE name='CTF' AND xtype='U') CREATE TABLE [dbo].[CTF]([flag] [nvarchar](50) NULL) ON [PRIMARY]; SELECT Count([flag]) as [flag] FROM [{0}].[dbo].[CTF]" -f $using:DatabaseName)
                    $adapter = New-Object System.Data.SQLClient.SqlDataAdapter $Command
                    $dataset = New-Object System.Data.DataSet
                    [void] $adapter.Fill($dataSet)
                    $res = $dataSet.Tables | Select-Object -ExpandProperty Rows
                }
                catch {
                    $ret = $false
                }
                finally {
                    if ($Connection.State -eq 'Open') {
                        $Connection.Close()
                    }
                }
                if ($res.flag) {
                    $ret = (1 -eq $res.flag)
                }
                $ret
            }

            GetScript  = {
                $res = ""; $ret = @{Return = $null}
                $Connection = New-Object System.Data.SQLClient.SQLConnection
                $Connection.ConnectionString = 'Integrated Security=SSPI;Persist Security Info=False;Data Source={0}' -f $env:ComputerName
                try {
                    $Connection.Open()
                    $Command = New-Object System.Data.SQLClient.SQLCommand
                    $Command.Connection = $Connection
                    $Command.CommandText = ('USE [{0}]; SET NOCOUNT ON; SELECT TOP 1 [flag] FROM [{0}].[dbo].[CTF]' -f $using:DatabaseName)
                    $adapter = New-Object System.Data.SQLClient.SqlDataAdapter $Command
                    $dataset = New-Object System.Data.DataSet
                    [void] $adapter.Fill($dataSet)
                    $res = $dataSet.Tables | Select-Object -ExpandProperty Rows
                }
                catch {
                    throw 'An error occurred while attempting to open the database connection and execute a command: {0}' -f ($_.Exception.Message)
                }
                finally {
                    if ($Connection.State -eq 'Open') {
                        $Connection.Close()
                    }
                }
                if ($res.flag) {
                    $ret = @{Return = $res.flag}
                }
                $ret
            }

            SetScript  = {
                $CommandText = (
                    "USE [{0}]; INSERT INTO CTF VALUES ('{1}')" -f `
                        $using:DatabaseName, "$($using:FlagPrefix):{$using:Flag5Value}"
                )
                $Connection = New-Object System.Data.SQLClient.SQLConnection
                $Connection.ConnectionString = 'Integrated Security=SSPI;Persist Security Info=False;Data Source={0}' -f $env:ComputerName
                try {
                    $Connection.Open()
                    $Command = New-Object System.Data.SQLClient.SQLCommand
                    $Command.Connection = $Connection
                    $Command.CommandText = $CommandText
                    $Command.ExecuteNonQuery() | Out-Null
                }
                catch {
                    throw 'An error occurred while attempting to open the database connection and execute a command: {0}' -f ($_.Exception.Message)
                }
                finally {
                    if ($Connection.State -eq 'Open') {
                        $Connection.Close()
                    }
                }
            }
            DependsOn  = '[SqlDatabase]CreateDatabase'
        }

        Write-Verbose 'Creating configuration for WaitforDomain' -Verbose
        xWaitForADDomain WaitForDomain {
            DomainName       = $DomainName
            RetryCount       = 60
            RetryIntervalSec = 15
        }

        Write-Verbose 'Creating configuration for DomainJoin' -Verbose
        Computer DomainJoin {
            Name       = $ComputerName
            DomainName = $DomainName
            Credential = $DomainCreds
            DependsOn  = '[xWaitForADDomain]WaitForDomain'
        }

        Write-Verbose 'Assigning configuration for LocalAdministrators' -Verbose
        Group LocalAdministrators {
            Ensure           = 'Present'
            GroupName        = 'Administrators'
            MembersToInclude = @($SqlSvc.UserName, $RunnerUser.UserName)
            DependsOn        = '[Computer]DomainJoin'
        }

    }
}


Configuration IIS {

    [CmdletBinding()]

    param (
		[string] $FlagPrefix = 'Flag',
        [PSCredential] $DomainCreds,
        [string] $Flag8Value
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName xWebAdministration

    $ComputerName = $env:ComputerName
    $DomainName = Split-Path $DomainCreds.UserName
    $NewLocalCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        (Split-Path $DomainCreds.UserName -Leaf), (Initialize-LudusMagnusPassword | ConvertTo-SecureString -AsPlainText -Force)
    )

	$identityPassword = ($FlagPrefix + ':{' + $Flag8Value + '}') 
    $AppPoolIdentity = New-Object System.Management.Automation.PSCredential -ArgumentList (
        'flag8', ( $identityPassword | ConvertTo-SecureString -AsPlainText -Force)
    )

    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true and DHCPEnabled=true' | ForEach-Object {
        $_.InvokeMethod('ReleaseDHCPLease', $null)
        $_.InvokeMethod('RenewDHCPLease', $null)
    }

    node localhost {

        Write-Verbose 'Creating configuration for the LocalConfigurationManager' -Verbose
        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true
            AllowModuleOverwrite = $true
            ActionAfterReboot    = 'ContinueConfiguration'
        }

        Write-Verbose 'Creating configuration for the Web-Server Feature:' -Verbose
        WindowsFeatureSet Web-Server {
            Ensure = 'Present'
            Name   = 'Web-Server', 'Web-Mgmt-Console'
        }

        Write-Verbose 'Creating configuration for WebContent' -Verbose
        File WebContent {
            Ensure          = 'Present'
            Type            = 'File'
            DestinationPath = 'C:\Inetpub\wwwroot\index.htm'
            Contents        = 'Too many permissions on w3wp.exe'
            DependsOn       = "[WindowsFeatureSet]Web-Server"
        }

        Write-Verbose 'Creating configuration for AppPoolIdentity' -Verbose
        User AppPoolIdentity {
            Ensure   = 'Present'
            UserName = $AppPoolIdentity.UserName
            Password = $AppPoolIdentity
        }

        Write-Verbose 'Assigning configuration for AppPoolIdentity Permissions' -Verbose
        Group AppPoolIdentityPermissions {
            Ensure           = 'Present'
            GroupName        = 'Administrators'
            MembersToInclude = @((Split-Path $DomainCreds.UserName -Leaf), $AppPoolIdentity.UserName)
            DependsOn        = '[User]AppPoolIdentity'
        }

        Write-Verbose 'Creating configuration for ApplicationPool' -Verbose
        xWebAppPool Flag8 {
            Ensure       = 'Present'
            Name         = 'AppPool'
            IdentityType = 'SpecificUser'
            Credential   = $AppPoolIdentity
            DependsOn    = '[WindowsFeatureSet]Web-Server', '[User]AppPoolIdentity', '[Group]AppPoolIdentityPermissions'
        }

        Write-Verbose 'Creating configuration for the Default Web Site' -Verbose
        xWebsite DefaultSite {
            Ensure          = 'Present'
            Name            = 'Default Web Site'
            State           = 'Started'
            PhysicalPath    = 'C:\inetpub\wwwroot'
            ApplicationPool = 'AppPool'
            DependsOn       = '[xWebAppPool]Flag8'
        }

        Write-Verbose 'Creating configuration for ChangeLocalAdminPassword' -Verbose
        User ChangeLocalAdminPassword {
            Ensure   = 'Present'
            UserName = $NewLocalCreds.UserName
            Password = $NewLocalCreds
        }

        Write-Verbose 'Creating configuration for WaitforDomain' -Verbose
        xWaitForADDomain WaitForDomain {
            DomainName       = $DomainName
            RetryCount       = 60
            RetryIntervalSec = 15
        }

        Write-Verbose 'Creating configuration for DomainJoin' -Verbose
        Computer DomainJoin {
            Name       = $ComputerName
            DomainName = $DomainName
            Credential = $DomainCreds
            DependsOn  = '[xWaitForADDomain]WaitForDomain', '[xWebAppPool]Flag8'
        }
    }
}


Configuration FS {

    [CmdletBinding()]

    param (
		[string] $FlagPrefix = 'Flag',
        [PSCredential] $DomainCreds,
        [string] $Flag3Value,
        [string] $Flag4Value
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xSmbShare
    Import-DscResource -ModuleName ComputerManagementDsc

    $SharePath = 'C:\Windows\Temp'
    $ComputerName = $env:ComputerName
    $DomainName = Split-Path $DomainCreds.UserName
    $NewLocalCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        (Split-Path $DomainCreds.UserName -Leaf), (Initialize-LudusMagnusPassword | ConvertTo-SecureString -AsPlainText -Force)
    )

    Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter 'IPEnabled=true and DHCPEnabled=true' | ForEach-Object {
        $_.InvokeMethod('ReleaseDHCPLease', $null)
        $_.InvokeMethod('RenewDHCPLease', $null)
    }

    $acl = Get-Acl -Path $SharePath
    $rule = New-Object System.Security.AccessControl.FileSystemAccessRule -ArgumentList (
        'Everyone', [System.Security.AccessControl.FileSystemRights]::FullControl,
        ([System.Security.AccessControl.InheritanceFlags]::ContainerInherit -bor [System.Security.AccessControl.InheritanceFlags]::ObjectInherit),
        [System.Security.AccessControl.PropagationFlags]::None, [System.Security.AccessControl.AccessControlType]::Allow
    )
    $acl.SetAccessRule($rule)
    $acl | Set-Acl -Path $SharePath


    node localhost {

        Write-Verbose 'Creating configuration for the LocalConfigurationManager' -Verbose
        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true
            AllowModuleOverwrite = $true
            ActionAfterReboot    = 'ContinueConfiguration'
        }

        Write-Verbose 'Creating configuration for SalariesFolder' -Verbose
        File SalariesFolder {
            Ensure          = 'Present'
            Type            = 'Directory'
            DestinationPath = $SharePath
        }

        Write-Verbose 'Creating configuration for SalariesShare' -Verbose
        xSmbShare SalariesShare {
            Ensure     = 'Present'
            Name       = 'Salaries'
            Path       = $SharePath
            ReadAccess = 'Everyone'
            DependsOn  = '[File]SalariesFolder'
        }

        Write-Verbose 'Creating configuration for Flag 3' -Verbose
        File Flag3 {
            Ensure          = 'Present'
            Type            = 'File'
            DestinationPath = "$($SharePath)\Salaries.csv"
            Contents        = "CTF,$($FlagPrefix):{$Flag3Value}"
            DependsOn       = '[xSmbShare]SalariesShare'
        }

        Write-Verbose 'Creating configuration for Flag 4' -Verbose
        File Flag4 {
            Ensure          = 'Present'
            Type            = 'File'
            DestinationPath = "$($SharePath)\ADS.md"
            Contents        = "NotRedHerring"
            DependsOn       = '[xSmbShare]SalariesShare'
        }

        Write-Verbose 'Creating configuration for Flag 4' -Verbose
        Script Flag4Stream {
            TestScript = { (Get-Content -Path "$($using:SharePath)\ADS.md" -Stream FLAG4 -ErrorAction SilentlyContinue) -eq $using:Flag4Value }
            GetScript  = { @{ Result = (Get-Content -Path "$($using:SharePath)\ADS.md" -Stream FLAG4 -ErrorAction SilentlyContinue) } }
            SetScript  = { Set-Content -Path "$($using:SharePath)\ADS.md" -Value "$($FlagPrefix):{$($using:Flag4Value)}" -Stream FLAG4 }
            DependsOn  = '[File]Flag4'
        }

        Write-Verbose 'Creating configuration for ChangeLocalAdminPassword' -Verbose
        User ChangeLocalAdminPassword {
            Ensure   = 'Present'
            UserName = $NewLocalCreds.UserName
            Password = $NewLocalCreds
        }

        Write-Verbose 'Creating configuration for WaitforDomain' -Verbose
        xWaitForADDomain WaitForDomain {
            DomainName       = $DomainName
            RetryCount       = 60
            RetryIntervalSec = 15
        }

        Write-Verbose 'Creating configuration for DomainJoin' -Verbose
        Computer DomainJoin {
            Name       = $ComputerName
            DomainName = $DomainName
            Credential = $DomainCreds
            DependsOn  = '[xWaitForADDomain]WaitForDomain'
        }
    }
}

#endregion



#region Helper functions

function Import-LudusMagnusADUsers {
    param(
		[string] $FlagPrefix = 'Flag',
        [string] $CsvPath = 'C:\Windows\Temp\ADUsers.csv',
        [string] $Flag2Value,
        [PSCredential] $RunnerUser,
        [PSCredential] $SqlSvc
    )

    $Domain = Get-ADDomain
    $DomainDN = $Domain.DistinguishedName
    $Forest = $Domain.Forest

    Write-Verbose 'Creating containers' -Verbose
    $ParentOU = New-ADOrganizationalUnit -Name 'Accounts' -Path $DomainDN -Verbose -ErrorAction Stop -PassThru
    $UserOU = New-ADOrganizationalUnit -Name 'Users' -Path $ParentOU.DistinguishedName -Verbose -PassThru -ErrorAction Stop
    $GroupOU = New-ADOrganizationalUnit -Name 'Groups' -Path $ParentOU.DistinguishedName -Verbose -PassThru -ErrorAction Stop

    Write-Verbose 'Initializing password policy' -Verbose
    Set-ADDefaultDomainPasswordPolicy $Forest -ComplexityEnabled $False -MaxPasswordAge '1000' -PasswordHistoryCount 0 -MinPasswordAge 0

    Write-Verbose 'Initializing departments' -Verbose
    $Departments = (
        @{'Name' = 'Accounting'; Positions = ('Manager', 'Accountant', 'Data Entry')},
        @{'Name' = 'Human Resources'; Positions = ('Manager', 'Administrator', 'Officer', 'Coordinator')},
        @{'Name' = 'Sales'; Positions = ('Manager', 'Representative', 'Consultant', 'Senior Vice President')},
        @{'Name' = 'Marketing'; Positions = ('Manager', 'Coordinator', 'Assistant', 'Specialist')},
        @{'Name' = 'Engineering'; Positions = ('Manager', 'Engineer', 'Scientist')},
        @{'Name' = 'Consulting'; Positions = ('Manager', 'Consultant')},
        @{'Name' = 'Information Technology'; Positions = ('Manager', 'Engineer', 'Technician')},
        @{'Name' = 'Planning'; Positions = ('Manager', 'Engineer')},
        @{'Name' = 'Contracts'; Positions = ('Manager', 'Coordinator', 'Clerk')},
        @{'Name' = 'Purchasing'; Positions = ('Manager', 'Coordinator', 'Clerk', 'Purchaser', 'Senior Vice President')}
    )

    Write-Verbose 'Initializing user details' -Verbose
    $Content = Import-CSV -Path $CsvPath -ErrorAction Stop | Sort-Object -Property State
    $Users = $Content |
        Select-Object  @{Name = 'Name'; Expression = {"$($_.GivenName) $($_.Surname)"}},
    @{Name = 'SamAccountName'; Expression = {"$($_.GivenName)$($_.Surname.Substring(0,3))"}},
    @{Name = 'UserPrincipalName'; Expression = {"$($_.GivenName)$($_.Surname.Substring(0,3))@$($Forest)"}},
    @{Name = 'EmailAddress'; Expression = {"$($_.GivenName)$($_.Surname.Substring(0,3))@$($Forest)"}},
    @{Name = 'DisplayName'; Expression = {"$($_.GivenName) $($_.MiddleInitial). $($_.Surname)"}},
    @{Name = 'Department'; Expression = {$Departments[(Get-Random -Maximum $Departments.Count)].Item('Name') | Get-Random -Count 1}},
    @{Name = 'Title'; Expression = {$Departments[(Get-Random -Maximum $Departments.Count)].Item('Positions') | Get-Random -Count 1}},
    @{Name = 'EmployeeID'; Expression = {"$($_.Country)-$((Get-Random -Minimum 0 -Maximum 99999).ToString('000000'))"}},
    @{Name = 'Gender'; Expression = {"$($_.Gender.SubString(0,1).ToUpper())$($_.Gender.Substring(1).ToLower())"}},
    @{Name = 'Enabled'; Expression = {$True}},
    @{Name = 'PostalCode'; Expression = {$_.ZipCode}},
    @{Name = 'OfficePhone'; Expression = {$_.TelephoneNumber}},
    @{Name = 'PasswordNeverExpires'; Expression = {$True}},
    @{Name = 'AccountPassword'; Expression = { (ConvertTo-SecureString -String (Initialize-LudusMagnusPassword -Prefix 'P@5z') -AsPlainText -Force)}},
    @{Name = 'Description'; Expression = { "$($_.Surname), $($_.GivenName) from $($_.Country)" }},
    GivenName, Surname, City, StreetAddress, State, Country, BirthDate

    $segment2 = [int](($Users.Count) / 3)
    $segment3 = [int](($Users.Count) / 3 * 2)

    $iRunner = (Get-Random -Minimum 0 -Maximum $segment2)
    $Users[$iRunner].SamAccountName = Split-Path $RunnerUser.UserName -Leaf
    $Users[$iRunner].AccountPassword = $RunnerUser.Password

    $iSqlSvc = (Get-Random -Minimum ($segment2+1) -Maximum $segment3)
    $Users[$iSqlSvc].SamAccountName = Split-Path $SqlSvc.UserName -Leaf
    $Users[$iSqlSvc].AccountPassword = $SqlSvc.Password

    $Users[(Get-Random -Minimum ($segment3+1) -Maximum $Users.Count)].Description = "$($FlagPrefix):{$Flag2Value}"


    Write-Verbose 'Creating groups' -Verbose
    foreach ($Department In $Departments.Name) {
        $CreateADGroup = @{
            Name            = $Department
            SamAccountName  = $Department
            GroupCategory   = 'Security'
            GroupScope      = 'Global'
            Path            = $GroupOU.DistinguishedName
            Description     = "Security Group for all $Department users"
            OtherAttributes = @{"Mail" = "$($Department.Replace(' ',''))@$($Forest)"}
            Verbose         = $true
        }
        New-ADGroup @CreateADGroup | Out-Null
    }

    Write-Verbose 'Creating Organizational Units and Users' -Verbose
    foreach ($User In $Users) {

        if (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Country)`"" -SearchBase $UserOU.DistinguishedName -ErrorAction SilentlyContinue)) {
            $CountryOU = New-ADOrganizationalUnit -Name $User.Country -Path $UserOU.DistinguishedName -Country $User.Country -Verbose -PassThru
        }
        else {
            $CountryOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Country)`"" -SearchBase $UserOU.DistinguishedName
        }

        if (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -SearchBase $CountryOU.DistinguishedName -ErrorAction SilentlyContinue)) {
            New-ADOrganizationalUnit -Name $User.State -Path $CountryOU.DistinguishedName -State $User.State -Country $User.Country -Verbose | Out-Null
        }

        $DestinationOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -SearchBase $CountryOU.DistinguishedName
        $userObject = $User | Select-Object -Property @{Name = 'Path'; Expression = {$DestinationOU.DistinguishedName}}, * |
            New-ADUser -ErrorAction SilentlyContinue -Verbose -PassThru
        if ($userObject) {
            Add-ADGroupMember -Identity $User.Department -Members $userObject.SamAccountName -ErrorAction SilentlyContinue -Verbose | Out-Null
        }
    }

    Write-Verbose 'Setting department managers' -Verbose
    foreach ($Department In $Departments.Name) {
        $DepartmentManager = Get-ADUser -Filter {(Title -eq 'Manager') -and (Department -eq $Department)} | Sort-Object | Select-Object -First 1
        Get-ADUser -Filter {(Department -eq $Department)} | Set-ADUser -Manager $DepartmentManager -Verbose | Out-Null
    }

    Write-Verbose 'Adding SPNs' -Verbose
    $params = @('-a', "MSSQLSvc/SQL.$Forest", $SqlSvc.UserName, '-u')
    setspn.exe $params

    Write-Verbose 'Setting Domain Admins additional users' -Verbose
    Add-ADGroupMember -Identity 'Domain Admins' -Members $Users[$iSqlSvc].SamAccountName

}


function Initialize-LudusMagnusPassword {
    param([string]$Prefix = '', $Length = 24)
    $Suffix = ([char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) + 0..9 |
            Sort-Object {Get-Random})[0..$Length] -join ''
    ($Prefix + $Suffix).Substring(0, $Length)
}


function Invoke-LudusMagnusSqlNonQuery {
    param ($InstanceName, $CommandText)
    $ConnectionString = 'Integrated Security=SSPI;Persist Security Info=False;Data Source={0}' -f $InstanceName
    $res = 0
    $Connection = New-Object System.Data.SQLClient.SQLConnection
    $Connection.ConnectionString = $ConnectionString
    try {
        $Connection.Open()
        $Command = New-Object System.Data.SQLClient.SQLCommand
        $Command.Connection = $Connection
        $Command.CommandText = $CommandText
        $res = $Command.ExecuteNonQuery()
    }
    catch {
        throw 'An error occurred while attempting to open the database connection and execute a command: {0}' -f ($_.Exception.Message)
    }
    finally {
        if ($Connection.State -eq 'Open') {
            $Connection.Close()
        }
    }
    'Records affected: {0}' -f $res
}


function Invoke-LudusMagnusSqlQuery {
    param ($InstanceName, $CommandText)
    $ConnectionString = 'Integrated Security=SSPI;Persist Security Info=False;Data Source={0}' -f $InstanceName
    $Connection = New-Object System.Data.SQLClient.SQLConnection
    $Connection.ConnectionString = $ConnectionString
    try {
        $Connection.Open()
        $Command = New-Object System.Data.SQLClient.SQLCommand
        $Command.Connection = $Connection
        $Command.CommandText = $CommandText
        $adapter = New-Object System.Data.SQLClient.SqlDataAdapter $Command
        $dataset = New-Object System.Data.DataSet
        [void] $adapter.Fill($dataSet)
        $results = $dataSet.Tables | Select-Object -ExpandProperty Rows
        $results
    }
    catch {
        throw 'An error occurred while attempting to open the database connection and execute a command: {0}' -f ($_.Exception.Message)
    }
    finally {
        if ($Connection.State -eq 'Open') {
            $Connection.Close()
        }
    }
}


function New-LudusMagnusPngImage {
    param($Path, $Text)
    Add-Type -AssemblyName System.Drawing
    $bmp = New-Object -TypeName System.Drawing.Bitmap -ArgumentList 480,60
    $font = New-Object -TypeName System.Drawing.Font -ArgumentList Consolas, 12
    $brushBg = [System.Drawing.Brushes]::Black
    $brushFg = [System.Drawing.Brushes]::Green
    $graphics = [System.Drawing.Graphics]::FromImage($bmp)
    $graphics.FillRectangle($brushBg, 0, 0, $bmp.Width, $bmp.Height)
    $graphics.DrawString($Text, $font ,$brushFg, 10, 10)
    $graphics.Dispose()
    $bmp.Save($Path)
}


function Publish-LudusMagnusModule {
    $psm1Content = ''
    $hash = @{}
    Get-Command -Name *-LudusMagnus* | ForEach-Object {
        if ($_.Name -ne $MyInvocation.MyCommand) {
            if (-not ($hash.ContainsKey($_.Name))) {
                $hash.Add($_.Name, 0)
                $psm1Content += "$($_.CommandType) $($_.Name) {$($_.Definition)}"
                $psm1Content += [System.Environment]::NewLine
            }
        }
    }

    $modulePath = Join-Path -Path (
        (($env:PSModulePath -split ';') -match [regex]::Escape($env:ProgramFiles) + '.*PowerShell\\Modules')[0]
    ) -ChildPath LudusMagnus
    New-Item -Path $modulePath -ItemType Directory -Force | Out-Null
    New-Item -Path $modulePath -ItemType File -Name LudusMagnus.psm1 -Value $psm1Content -Force | Out-Null
    New-ModuleManifest -Path $modulePath\LudusMagnus.psd1 -RootModule .\LudusMagnus.psm1 -ModuleVersion ('{0:yyMM}.{0:dd}.{0:HH}.{0:mm}' -f (Get-Date))
}

#endregion

