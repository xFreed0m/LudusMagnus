#region Configurations
Configuration ADDS {

    [CmdletBinding()]

    param (
        [string] $DomainName,
        [PSCredential] $UserCredential,
        [string] $Flag9Value,
        [string] $ADUsersUri
    )

    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -ModuleName xActiveDirectory
    Import-DscResource -ModuleName xPendingReboot
    Import-DscResource -ModuleName StorageDsc
    Import-DscResource -ModuleName NetworkingDsc
    Import-DscResource -ModuleName xPSDesiredStateConfiguration

    $interfaceAlias = Get-NetAdapter | Where-Object { $_.Name -Like 'Ethernet*' } | Select-Object -First 1 -ExpandProperty Name
    $DomainCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ('{0}\{1}' -f $DomainName, $UserCredential.UserName), ($UserCredential.Password)
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

        Write-Verbose 'Creating configuration for CreateUsersCsv' -Verbose
        xRemoteFile CreateADUsersCsv {
            Uri             = $ADUsersUri
            DestinationPath = 'C:\Windows\Temp\ADUsers.csv'
        }

        Write-Verbose 'Creating configuration for DnsServerAddress' -Verbose
        DnsServerAddress DnsServerAddress {
            Address        = '127.0.0.1'
            InterfaceAlias = $interfaceAlias
            AddressFamily  = 'IPv4'
            DependsOn      = '[WindowsFeature]DNS', '[xRemoteFile]CreateADUsersCsv'
        }

        Write-Verbose 'Creating configuration for CreateForest' -Verbose
        xADDomain CreateForest {
            DomainName                    = $DomainName
            DomainAdministratorCredential = $DomainCreds
            SafemodeAdministratorPassword = $DomainCreds
            DatabasePath                  = 'F:\ADDS\NTDS'
            LogPath                       = 'F:\ADDS\NTDS'
            SysvolPath                    = 'F:\ADDS\Sysvol'
            DependsOn                     = '[WindowsFeature]AD-Domain-Services', '[Disk]ADDataDisk', '[xRemoteFile]CreateADUsersCsv'
        }

        Write-Verbose 'Creating configuration for CreateUsers' -Verbose
        script CreateADUsers {

            TestScript = {
                Test-Path -Path 'C:\Windows\Temp\ADUsers.flag'
            }

            GetScript = {
                @{Result = (Get-Content -Path 'C:\Windows\Temp\ADUsers.flag' -Value (Get-Date))}
            }

            SetScript = {
                Create-ADUsers -CsvPath 'C:\Windows\Temp\ADUsers.csv'
                Set-Content -Path 'C:\Windows\Temp\ADUsers.flag' -Value (Get-Date)
            }
            DependsOn = '[xRemoteFile]CreateADUsersCsv', '[xADDomain]CreateForest'
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
    $NewLocalCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ($UserCredential.UserName), (Generate-Password | ConvertTo-SecureString -AsPlainText -Force)
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

        Write-Verbose 'Creating configuration for ChangeLocalAdminPassword' -Verbose
        User ChangeLocalAdminPassword {
            Ensure   = 'Present'
            UserName = $UserCredential.UserName
            Password = $NewLocalCreds
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

    $InstanceName = '(local)'
    $DomainCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ('{0}\{1}' -f $DomainName, $UserCredential.UserName), $UserCredential.Password
    )
    $NewLocalCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ($UserCredential.UserName), (Generate-Password | ConvertTo-SecureString -AsPlainText -Force)
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

        Write-Verbose 'Creating configuration for ChangeLocalAdminPassword' -Verbose
        User ChangeLocalAdminPassword {
            Ensure   = 'Present'
            UserName = $UserCredential.UserName
            Password = $NewLocalCreds
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
    $NewLocalCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ($UserCredential.UserName), (Generate-Password | ConvertTo-SecureString -AsPlainText -Force)
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

        Write-Verbose 'Creating configuration for ChangeLocalAdminPassword' -Verbose
        User ChangeLocalAdminPassword {
            Ensure   = 'Present'
            UserName = $UserCredential.UserName
            Password = $NewLocalCreds
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
        [string] $Flag3Value,
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
    $NewLocalCreds = New-Object System.Management.Automation.PSCredential -ArgumentList (
        ($UserCredential.UserName), (Generate-Password | ConvertTo-SecureString -AsPlainText -Force)
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
            Ensure     = 'Present'
            Name       = 'Salaries'
            Path       = $SharePath
            ReadAccess = 'Everyone'
            DependsOn  = '[File]SalariesFolder'
        }

        Write-Verbose 'Creating configuration for Flag 3' -Verbose
        File Flag4 {
            Ensure          = 'Present'
            Type            = 'File'
            DestinationPath = "$($SharePath)\Salaries.csv"
            Contents        = "CTF,flag3:{$Flag3Value}"
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
            TestScript = { (Get-Content -Path "$($SharePath)\ADS.md" -Stream DATA) -eq $using:Flag4Value }
            GetScript = { @{ Result = (Get-Content -Path "$($SharePath)\ADS.md" -Stream DATA) } }
            SetScript = { Set-Content -Path "$($SharePath)\ADS.md" -Value $using:Flag4Value -Stream DATA }
            DependsOn = '[File]Flag4'
        }

        Write-Verbose 'Creating configuration for ChangeLocalAdminPassword' -Verbose
        User ChangeLocalAdminPassword {
            Ensure   = 'Present'
            UserName = $UserCredential.UserName
            Password = $NewLocalCreds
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
#endregion

#region Helper functions
function Generate-Password {
    param([string]$Prefix = '', $Length = 24)
    $Suffix = ([char[]]([char]33..[char]95) + ([char[]]([char]97..[char]126)) + 0..9 |
        Sort-Object {Get-Random})[0..$Length] -join ''
    ($Prefix + $Suffix).Substring(0,$Length)
}


function Create-ADUsers {
    param(
        $CsvPath = 'C:\Windows\Temp\ADUsers.csv'
    )

    $Domain   = Get-ADDomain
    $DomainDN = $Domain.DistinguishedName
    $Forest   = $Domain.Forest
    $ParentOU = New-ADOrganizationalUnit -Name 'Accounts' -Path $DomainDN -Verbose -ErrorAction Stop -PassThru
    $UserOU   = New-ADOrganizationalUnit -Name 'Users' -Path $ParentOU.DistinguishedName -Verbose -PassThru -ErrorAction Stop
    $GroupOU  = New-ADOrganizationalUnit -Name 'Groups' -Path $ParentOU.DistinguishedName -Verbose -PassThru -ErrorAction Stop
    $Content  = Import-CSV -Path $CsvPath -ErrorAction Stop | Sort-Object -Property State

    Set-ADDefaultDomainPasswordPolicy $Forest -ComplexityEnabled $False -MaxPasswordAge '1000' -PasswordHistoryCount 0 -MinPasswordAge 0

    $Departments =  (
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

    $Users = $Content |
        Select-Object  @{Name='Name';Expression={"$($_.GivenName) $($_.Surname)"}},
            @{Name='SamAccountName'; Expression={"$($_.GivenName)$($_.Surname.Substring(0,3))"}},
            @{Name='UserPrincipalName'; Expression={"$($_.GivenName)$($_.Surname.Substring(0,3))@$($Forest)"}},
            @{Name='EmailAddress'; Expression={"$($_.GivenName)$($_.Surname.Substring(0,3))@$($Forest)"}},
            @{Name='GivenName'; Expression={$_.GivenName}},
            @{Name='Surname'; Expression={$_.Surname}},`
            @{Name='DisplayName'; Expression={"$($_.GivenName) $($_.MiddleInitial). $($_.Surname)"}},
            @{Name='City'; Expression={$_.City}},
            @{Name='StreetAddress'; Expression={$_.StreetAddress}},
            @{Name='State'; Expression={$_.State}},
            @{Name='Country'; Expression={$_.Country}},
            @{Name='PostalCode'; Expression={$_.ZipCode}},
            @{Name='OfficePhone'; Expression={$_.TelephoneNumber}},
            @{Name='Department'; Expression={$Departments[(Get-Random -Maximum $Departments.Count)].Item('Name') | Get-Random -Count 1}},
            @{Name='Title'; Expression={$Departments[(Get-Random -Maximum $Departments.Count)].Item('Positions') | Get-Random -Count 1}},
            @{Name='EmployeeID'; Expression={"$($_.Country)-$((Get-Random -Minimum 0 -Maximum 99999).ToString('000000'))"}},
            @{Name='BirthDate'; Expression={$_.Birthday}},
            @{Name='Gender'; Expression={"$($_.Gender.SubString(0,1).ToUpper())$($_.Gender.Substring(1).ToLower())"}},
            @{Name='Enabled'; Expression={$True}},
            @{Name='AccountPassword'; Expression={ (ConvertTo-SecureString -String (Generate-Password -Prefix 'P@5z') -AsPlainText -Force)}},
            @{Name='PasswordNeverExpires'; Expression={$True}}

    foreach ($Department In $Departments.Name) {
        $CreateADGroup = @{
            Name = $Department
            SamAccountName  = $Department
            GroupCategory   = 'Security'
            GroupScope      = 'Global'
            Path            = $GroupOU.DistinguishedName
            Description     = "Security Group for all $Department users"
            OtherAttributes = @{"Mail"="$($Department.Replace(' ',''))@$($Forest)"}
            Verbose         = $true
        }
        New-ADGroup @CreateADGroup | Out-Null
    }

    foreach ($User In $Users) {

        if (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Country)`"" -SearchBase $UserOU.DistinguishedName -ErrorAction SilentlyContinue)) {
            $CountryOU = New-ADOrganizationalUnit -Name $User.Country -Path $UserOU.DistinguishedName -Country $User.Country -Verbose -PassThru
        } else {
            $CountryOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.Country)`""
        }

        if (!(Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -SearchBase $CountryOU.DistinguishedName -ErrorAction SilentlyContinue)) {
            $StateOU = New-ADOrganizationalUnit -Name $User.State -Path $CountryOU.DistinguishedName -State $User.State -Country $User.Country -Verbose -PassThru
        } else {
            $StateOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`""
        }

        $DestinationOU = Get-ADOrganizationalUnit -Filter "Name -eq `"$($User.State)`"" -SearchBase $CountryOU.DistinguishedName
        $CreateADUser = $User | Select-Object -Property @{Name='Path'; Expression={$DestinationOU.DistinguishedName}}, * | New-ADUser -Verbose -PassThru
        $AddADUserToGroup = Add-ADGroupMember -Identity $User.Department -Members $User.SamAccountName -Verbose
    }

    foreach ($Department In $Departments.Name) {
        $DepartmentManager = Get-ADUser -Filter {(Title -eq 'Manager') -and (Department -eq $Department)} | Sort-Object | Select-Object -First 1
        $SetDepartmentManager = Get-ADUser -Filter {(Department -eq $Department)} | Set-ADUser -Manager $DepartmentManager -Verbose
    }

}
#endregion