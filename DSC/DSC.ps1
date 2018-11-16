Configuration ADDS {

    [CmdletBinding()]

    param (
        [string] $DomainName,
        [PSCredential] $UserCredential,
        [string] $Flag9Value
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xPendingReboot
    Import-DscResource -ModuleName StorageDsc
    Import-DscResource -ModuleName NetworkingDsc

    $interfaceAlias = Get-NetAdapter | Where-Object { $_.Name -Like 'Ethernet*' } | Select-Object -First 1 -ExpandProperty Name
    $DomainCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ('{0}\{1}' -f $DomainName, $UserCredential.UserName), $UserCredential.Password
    )

    New-Object System.Management.Automation.PSCredential -ArgumentList (
        'NT AUTHORITY\SYSTEM', ($Flag9Value | ConvertTo-SecureString -AsPlainText -Force)
    ) | Export-CliXml -Path C:\Windows\Temp\flag9.xml

    node localhost {

        Write-Verbose 'Creating configuration for the LocalConfigurationManager' -Verbose
        LocalConfigurationManager {
            RebootNodeIfNeeded   = $true
            AllowModuleOverwrite = $true
            ActionAfterReboot    = 'ContinueConfiguration'
        }

        Write-Verbose 'Creating configuration for Disk2' -Verbose
        WaitforDisk Disk2 {
            DiskId           = 2
            RetryIntervalSec = 5
            RetryCount       = 3
        }

        Write-Verbose 'Creating configuration for ADDataDisk' -Verbose
        Disk ADDataDisk {
            DiskId      = 2
            DriveLetter = "F"
            DependsOn   = "[WaitForDisk]Disk2"
        }

        Write-Verbose 'Creating configuration for the Windows Features:' -Verbose
        $Features = @(
            'RSAT-ADDS',
            'RSAT-AD-Tools',
            'RSAT-AD-PowerShell',
            'RSAT-AD-AdminCenter',
            'RSAT-Role-Tools',
            'GPMC',
            'DNS',
            'RSAT-DNS-Server'
        )

        $Features.ForEach( {
            Write-Verbose "`t - $_" -Verbose
            WindowsFeature "$_" {
                Ensure = 'Present'
                Name   = $_
            }
        } )

        Write-Verbose 'Creating configuration for ADDS_Install' -Verbose
        WindowsFeature ADDS_Install {
            Ensure = 'Present'
            Name   = 'AD-Domain-Services'
        }

        User ChangeDomainAdminPassword {
            Ensure   = 'Present'
            UserName = $UserCredential.UserName
            Password = $DomainCreds
        }

        Write-Verbose 'Creating configuration for CreateForest' -Verbose
        xADDomain CreateForest {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = "F:\ADDS\NTDS"
            LogPath                       = "F:\ADDS\NTDS"
            SysvolPath                    = "F:\ADDS\Sysvol"
            DependsOn                     = '[WindowsFeature]ADDS_Install', '[Disk]ADDataDisk', '[User]ChangeDomainAdminPassword'
        }

        Write-Verbose 'Creating configuration for DnsServerAddress' -Verbose
        DnsServerAddress DnsServerAddress {
            Address        = '127.0.0.1'
            InterfaceAlias = $interfaceAlias
            AddressFamily  = 'IPv4'
            DependsOn      = "[WindowsFeature]DNS"
        }
    }
}


Configuration JumpBox {

    [CmdletBinding()]

    param (
        [string] $DomainName,
        [string] $ComputerName,
        [PSCredential] $UserCredential,
        [string] $Flag0Value
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName ComputerManagementDsc

    $DomainCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ('{0}\{1}' -f $DomainName, $UserCredential.UserName), $UserCredential.Password
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

        Write-Verbose 'Creating configuration for Flag 0' -Verbose
        File Flag0 {
            Ensure          = 'Present'
            Type            = "File"
            DestinationPath = "C:\Windows\system32\drivers\etc\flag0.txt"
            Contents        = "flag0:{$Flag0Value}"
        }

        Write-Verbose 'Creating configuration for WaitforDomain' -Verbose
        xWaitForADDomain WaitForDomain {
            DomainName       = $DomainName
            RetryCount       = 60
            RetryIntervalSec = 30
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


Configuration SQL {

    [CmdletBinding()]

    param (

        [string] $DomainName,
        [string] $ComputerName,
        [PSCredential] $UserCredential,
        [PSCredential] $SQLAuthCreds,
        [string] $DatabaseName,
        [string] $Flag5Value
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName SqlServerDsc

    $InstanceName = 'MSSQLSERVER'
    $DomainCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ('{0}\{1}' -f $DomainName, $UserCredential.UserName), $UserCredential.Password
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
        SqlServerLogin SqlLogin        {
            Ensure                         = 'Present'
            ServerName                     = $ComputerName
            Name                           = 'SqlLogin'
            LoginType                      = 'SqlLogin'
            InstanceName                   = $InstanceName
            LoginCredential                = $SQLAuthCreds
            LoginMustChangePassword        = $false
            LoginPasswordExpirationEnabled = $true
            LoginPasswordPolicyEnforced    = $true
        }

        Write-Verbose 'Creating configuration for the SqlServerRole' -Verbose
        SqlServerRole SqlServerRole         {
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

        Service SqlBrowser {
            Ensure      = 'Present'
            Name        = 'SQLBrowser'
            StartupType = "Automatic"
            State       = "Running"
            Credential  = $SQLAuthCreds
        }

        Write-Verbose 'Creating configuration for Flag 5' -Verbose
        SqlScriptQuery Flag5 {

            ServerInstance = ('{0}\{1}' -f $ComputerName, $InstanceName)
            QueryTimeout = 30
            DependsOn    = '[SqlDatabase]CreateDatabase'
            TestQuery    = @"
                IF (SELECT Count([flag]) FROM [$($DatabaseName)].[dbo].[CTF]) = 0
                BEGIN; RAISERROR ('Flag not ready on [$($DatabaseName)]', 16, 1); END
                ELSE BEGIN; PRINT 'True'; END
"@
            GetQuery     = "SELECT TOP 1 [flag] FROM [$DatabaseName].[dbo].[CTF] FOR JSON AUTO"
            SetQuery     = "USE [$DatabaseName]; CREATE TABLE [dbo].[CTF]([flag] [nvarchar](50) NULL) ON [PRIMARY]; INSERT INTO CTF VALUES ('$Flag5Value');"

        }

        Write-Verbose 'Creating configuration for WaitforDomain' -Verbose
        xWaitForADDomain WaitForDomain {
            DomainName       = $DomainName
            RetryCount       = 60
            RetryIntervalSec = 30

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


Configuration IIS {

    [CmdletBinding()]

    param (
        [string] $DomainName,
        [string] $ComputerName,
        [PSCredential] $UserCredential,
        [PSCredential] $Flag8Value
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName ComputerManagementDsc
    Import-DscResource -ModuleName xWebAdministration

    $DomainCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ('{0}\{1}' -f $DomainName, $UserCredential.UserName), $UserCredential.Password
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
        File WebContent  {
			Ensure          = 'Present'
			Type            = 'File'
			DestinationPath = 'C:\Inetpub\wwwroot\index.htm'
            Contents        = 'Too many permissions on w3wp.exe'
			DependsOn       = "[WindowsFeatureSet]Web-Server"
		}

        Write-Verbose 'Creating configuration for Flag 8' -Verbose
        xWebAppPool Flag8 {
            Ensure     = 'Present'
            Name       = 'AppPool'
            Credential = $Flag8Value
            DependsOn  = '[WindowsFeatureSet]Web-Server'
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


        Write-Verbose 'Creating configuration for WaitforDomain' -Verbose
        xWaitForADDomain WaitForDomain {
            DomainName       = $DomainName
            RetryCount       = 60
            RetryIntervalSec = 30
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


Configuration FS {

    [CmdletBinding()]

    param (
        [string] $DomainName,
        [string] $ComputerName,
        [PSCredential] $UserCredential,
        [string] $Flag4Value
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xSmbShare
    Import-DscResource -ModuleName ComputerManagementDsc

    $SharePath = 'C:\Windows\IdentityCRL\production'
    $DomainCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ('{0}\{1}' -f $DomainName, $UserCredential.UserName), $UserCredential.Password
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

        Write-Verbose 'Creating configuration for SalariesFolder' -Verbose
        File SalariesFolder {
            Ensure = 'Present'
            Type = 'Directory'
            DestinationPath = $SharePath
        }

        Write-Verbose 'Creating configuration for SalariesShare' -Verbose
        xSmbShare SalariesShare {
            Ensure = 'Present'
            Name   = 'Salaries'
            Path = $SharePath
            ReadAccess = 'Everyone'
            DependsOn = '[File]SalariesFolder'
        }

        Write-Verbose 'Creating configuration for Flag 4' -Verbose
        File Flag4 {
            Ensure          = 'Present'
            Type            = 'File'
            DestinationPath = "$($SharePath)\flag4.csv"
            Contents        = "flag4,{$Flag4Value}"
            DependsOn = '[xSmbShare]SalariesShare'
        }

        Write-Verbose 'Creating configuration for WaitforDomain' -Verbose
        xWaitForADDomain WaitForDomain {
            DomainName       = $DomainName
            RetryCount       = 60
            RetryIntervalSec = 30
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
