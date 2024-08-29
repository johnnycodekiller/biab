
<#

This DSC script takes the inputs under the param section and sets the IP address, default gateway, DNS server, disables IPv6, renames the server, updates the computer description, and sets the time zone to GMT and adds it to the $Domain.test doamin created with the ADDS script. It then installs SQL Server.
This example is allowing storage of credentials in plain text by setting PSDscAllowPlainTextPassword to $true.
Storing passwords in plain text is not a good practice and is presented only for simplicity and demonstration purposes.

Follow these steps:
Create a new VM with Windows Server 2016/2019 OS. If you want to install SQL on another drive it must be created, formatted and added to the VM before the script runs.

Make sure the following DSC modules from https://www.powershellgallery.com/ are copied to C:\Program Files\WindowsPowerShell\Modules
    Import-DscResource -ModuleName xPSDesiredStateConfiguration
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -Module NetworkingDsc
	Import-DscResource -Module ComputerManagementDsc
	Import-DscResource -Module xNetworking
	Import-DSCResource -ModuleName xDnsServer
    Import-DscResource -ModuleName SqlServerDsc
    Import-DscResource -ModuleName xSqlServer
	
Create a folder called C:\TEMP

Copy the file Wrk.NameTimeIP.InstallDB.Accnts.SQL.v2.ps1 to C:\TEMP

Open PowerShell ISE

Run the following command: Set-ExecutionPolicy -ExecutionPolicy Unrestricted

Open C:\Temp\Wrk.NameTimeIP.InstallDB.Accnts.SQL.v2.ps1 inside PowerShell ISE

Validate there are no errors in the script ~~~~~ Red Squiggley Lines are Bad

Run the script within PowerShell ISE

PowerShell ISE will prompt you for 4 credentials: Domain Admin, Network Share Access, $Domain\SQL.Install, and the $Domain\SQL.Services

The machine will reboot multiple times

If you want to change the Name, Default Log location, etc from the default in the script just update the corresponding Parameter String in the Account Credential and Variable Region at the top of the script

#>



sleep(240)

Set-ExecutionPolicy -ExecutionPolicy Unrestricted

if (-not (Test-Path "c:\DSC")) {
    try {
        New-Item -Path "c:\" -Name "DSC" -ItemType 'directory'
        }
    catch {
        Write-Error -Message "oops" -ErrorAction Stop
        }
    "Success"
    }
else {
     cd c:\DSC
     Remove-Item *.txt
     }

<# Change to C:\DSC directory #>
	cd C:\DSC



# Mount Drive on deploy share

if (test-path -path "deploy:"){

    write-output "exists"
}
else {
    New-PSDrive -Name 'deploy' -PSProvider 'Filesystem' -Root "\\192.168.10.21\Deploy\Deploy Scripts\DEV\reference-files"
}

<# Determine Name of the Network Adapter in this OS #>
	$NetAdapterName = Get-NetAdapter -Name "Ethernet*"
	$NetAdapterName = $NetAdapterName.ifAlias

<# Get Domain name from txt file #>


$domainfromtxt = get-content deploy:\domain.txt
$domainfromtxtsplit = $domainfromtxt.split('.')

$1Domain = $domainfromtxtsplit[0]
$1TopLevelDomain = $domainfromtxtsplit[1]


<# Copy Network resources to local machine #>

    copy-item '\\192.168.10.21\Files\Software\DotNET\sources\sxs' 'E:\DotNet35' -recurse -force
    copy-item '\\192.168.10.21\Files\Software\SQLISO' 'E:\SQL2016Binaries' -recurse -force



	
<# Account Credentials #>

<# Account Credentials from file#>

    $credarray = get-content "deploy:\dacredz.txt"
    $credarraysplit = $credarray.split(',')
    $Credentialusername = $credarraysplit[0]
    $Credentialpassword = convertto-securestring -string $credarraysplit[1] -asplaintext -force
  
    $Credential = new-object -typename system.management.automation.pscredential -argumentlist $Credentialusername,$Credentialpassword


    $ADJoinCredential = $Credential









		
        $SqlShareCredential = $Credential

        $SqlInstallCredential =  new-object -typename system.management.automation.pscredential -argumentlist "$1Domain\SQL.Install",$Credentialpassword
   
        $SqlAdministratorCredential = $SqlInstallCredential, # Sets the SQL Admin credential to the SQL Install Credential called for in the previous line
   
        $SqlServiceCredential = new-object -typename system.management.automation.pscredential -argumentlist "$1Domain\SQL.Services",$Credentialpassword
   
        $SqlAgentServiceCredential = $SqlServiceCredential	# Sets the SQL Agent Service credential to the SQL Service Credential called for in the previous line
		
		
		
Configuration Wrk.NameTimeIP.InstallDB.Accnts.SQL
{


<# Account Credential and Variable Region #>

    param
    (
<# Server Name #>	
        [Parameter()]
        [String]
        $Name = 'SQLSRV',

<# Server Description #>		
		[Parameter()]
        [String]
        $ComputerDescription = 'SQL Database Server',

<# Server IP Address #>		
		[Parameter()]
        [String]
        $IPAddress = '192.168.10.217',

<# Server Default Gateway #>		
		[Parameter()]
        [String]
        $DefaultGateway = '192.168.10.254',

<# DNS Server IP Address #>		
		[Parameter()]
        [String]
        $DNS = '192.168.10.215',

<# FQDN = HostName.DomainName.TopLevelDomainName example = server.'$Domain'.$TopLevelDomain #>
<# Domain Name #>		
	[Parameter()]
        [String]
	$Domain = $1Domain,
		
<# FQDN = HostName.DomainName.TopLevelDomainName example = server.dev2.'TEST' #>
<# Top Level Domain Name #>		
	[Parameter()]
        [String]
	$TopLevelDomain = $1TopLevelDomain,
		
<# Share Containing .NET Framework 3.5 #>
		[Parameter()]
        [String]		
		$NetFramework35Share = "\\192.168.10.215\dscFiles\sxs", #"\\192.168.10.21\Files\Software\DotNET\sources\sxs",

<# Share Containing SQL2016 Binaries Extracted from ISO #>
		[Parameter()]
        [String]		
		$SQL2016BinariesSource = '\\192.168.10.215\dscFiles\SQLISO', #'\\192.168.10.21\Files\Software\SQLISO',

<# Local Folder to Hold the SQL2016 Binaries #>
		[Parameter()]
        [String]		
		$SQL2016BinariesDestination = 'E:\SQL2016Binaries',

<# Location for Shared Directory #>
		[Parameter()]
        [String]			
		$InstallSharedDir = 'E:\Program Files\Microsoft SQL Server',

<# Location for Shared WOW Directory #>		
		[Parameter()]
        [String]			
		$InstallSharedWOWDir  = 'E:\Program Files (x86)\Microsoft SQL Server',

<# Location for the SQL Instace #>		
		[Parameter()]
        [String]			
		$InstanceDir = 'E:\Program Files\Microsoft SQL Server',

<# Location for SQL Data Directory #>		
		[Parameter()]
        [String]			
		$InstallSQLDataDir = 'E:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data',

<# Location for SQL User DB #>		
		[Parameter()]
        [String]			
		$SQLUserDBDir = 'E:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data',

<# Location for SQL DB Log #>		
		[Parameter()]
        [String]			
		$SQLUserDBLogDir = 'E:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data',

<# Location for the SQL TEMP DB #>		
		[Parameter()]
        [String]			
		$SQLTempDBDir = 'E:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data',

<# Location for SQL TEMP DB Log #>		
		[Parameter()]
        [String]			
		$SQLTempDBLogDir = 'E:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Data',

<# Location for SQL Backups #>		
		[Parameter()]
        [String]			
		$SQLBackupDir = 'E:\Program Files\Microsoft SQL Server\MSSQL13.MSSQLSERVER\MSSQL\Backup',		

<# Section for MSOLAP Settings, If not using OLAP Feature This Section is NOT used #>
<# Location for SQL OLAP Config #>
		[Parameter()]
        [String]		
		$ConfigDir = 'E:\MSOLAP\Config',

<# Location for SQL OLAP Data #>
		[Parameter()]
        [String]
		$DataDir = 'E:\MSOLAP\Data',

<# Location for SQL OLAP Log #>		
		[Parameter()]
        [String]		
		$LogDir = 'E:\MSOLAP\Log',

<# Location for SQL OLAP Backup #>		
		[Parameter()]
        [String]		
		$BackupDir = 'E:\MSOLAP\Backup',

<# Location for SQL OLAP TEMP #>		
		[Parameter()]
        [String]		
		$TempDir = 'E:\MSOLAP\Temp'

    )

<# DSC Module Region #>
    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName xPSDesiredStateConfiguration
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -Module NetworkingDsc
	Import-DscResource -Module ComputerManagementDsc
	Import-DscResource -Module Networkingdsc
	Import-DSCResource -ModuleName xDnsServer
    Import-DscResource -ModuleName SqlServerDsc
    Import-DscResource -ModuleName SqlServerdsc	


<# DSC Node Region #>
	
	Node $AllNodes.NodeName
    {
 	 	 	
        File Started_File
        {
            DestinationPath = 'C:\DSC\Started.txt'
            Ensure = "Present"
            Contents = 'Computer not configured, not added to domain, and SQL not installed.'
        }

		NetAdapterBinding DisableIPv6
        {
            InterfaceAlias = $NetAdapterName
            ComponentId    = 'ms_tcpip6'
            State          = 'Disabled'
        } 

        Registry PrioritizeIPv4overIPv6
        {
            Key = 'HKLM:\SYSTEM\CurrentControlSet\Services\Tcpip6\Parameters'
            Ensure = 'Present'
            ValueName = 'DisabledComponents'
            ValueType = 'DWord'
            ValueData = '32'
            Force = $true
        }

		IPAddress SetIPAddress
        {
            IPAddress      = $IPAddress
            InterfaceAlias = $NetAdapterName
            AddressFamily  = 'IPV4'
			#DependsOn	   = '[NetAdapterBinding]DisableIPv6'
        }

		DnsServerAddress SetDnsServerAddress
        {
            Address        = $DNS
            InterfaceAlias = $NetAdapterName
            AddressFamily  = 'IPv4'
            #DependsOn	   = '[IPAddress]SetIPAddress'
        }

         DefaultGatewayAddress SetDefaultGateway
        {
            Address        = $DefaultGateway
            InterfaceAlias = $NetAdapterName
            AddressFamily  = 'IPv4'
            #DependsOn	   = '[DnsServerAddress]SetDnsServerAddress'
        }
		
		TimeZone SetTimeZoneToGMT
        {
            IsSingleInstance 	= 'Yes'
            TimeZone         	= 'GMT Standard Time' # Must be a valid Microsoft Time Zone
			#DependsOn	   		= '[DefaultGatewayAddress]SetDefaultGateway'
        }


# Disable IEEsc - Attempt to fix the cant find'/copy the SXS Net35 issue - Logan
        IEEnhancedSecurityConfiguration Kill-IEEsc-Administrators
        {
            Role = 'Administrators'
            Enabled = $false
        }

        IEEnhancedSecurityConfiguration Kill-IEEsc-Users
        {
            Role = 'Users'
            Enabled = $false
        }

        Computer JoinDomain
        {
            Name          	= $Name
            Description 	= $ComputerDescription
			DomainName 		= $Domain
            Credential 		= $Credential # Credential to join to domain
			#DependsOn	   	= '[TimeZone]SetTimeZoneToGMT'
        }
        		
		PendingReboot JoinDomain
        {
            Name                        = 'JoinDomain'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            #DependsOn                   = '[Computer]JoinDomain'
        }


<# SQL Accounts Group in Local Admin Region #>

		Group SQLAccounts
        {
            GroupName            = 'Administrators'
            Ensure		         = 'Present'
            MembersToInclude	 = "$Domain\SQLAccounts"
			Credential 		 	 = $Credential
			PsDscRunAsCredential = $Credential
			#DependsOn	   		 = '[Computer]JoinDomain'
        }

<# SQL Prerequisites for SQL Server Region #>
        <# File NETSource 
         {
            Type = "directory"
            DestinationPath = "C:\sxs"
            Ensure = "Present"         
         }
        
         File MoveDotNet35Locally
         {
            DestinationPath = "C:\sxs\microsoft-windows-netfx3-ondemand-package.cab"
            SourcePath = "$NetFramework35Share\microsoft-windows-netfx3-ondemand-package.cab"
            Type = "File"
            Ensure = "Present"
            #DependsOn = "[File]NETSource"        
         }
        #>

        # Discable Windows Firewall and allow inbound and outbound connections for SQL connectivity
        FirewallProfile Turn_Off_Domain
        {
        Name = 'Domain'
        Enabled =   'False'
        }

        # Discable Windows Firewall and allow inbound and outbound connections for SQL connectivity
        FirewallProfile Turn_Off_Public
        {
        Name = 'Public'
        Enabled =   'False'
        }
        
        # Discable Windows Firewall and allow inbound and outbound connections for SQL connectivity
        FirewallProfile Turn_Off_Private
        {
        Name = 'Private'
        Enabled =   'False'
        }
          	 	 	
        File Started_File_NetFrame35
        {
            DestinationPath = 'C:\DSC\NetFrame35Share.txt'
            Ensure = "Present"
            Contents =$NetFramework35Share # 'Computer not configured, not added to domain, and SQL not installed.'
        }

         WindowsFeature Copy_NetFramework35
        {
            Name   					= 'NET-Framework-Core'
            Source 					=  "E:\DotNet35\sxs" # Assumes built-in Everyone has read permission to the share and path.
            #Source                  = $NetFramework35Share
            Ensure 					= 'Present'
			PsDscRunAsCredential   	= $Credential
            #DependsOn 				= '[Group]SQLAccounts'
        }

        WindowsFeature Install_NetFramework45
        {
            Name  		= 'NET-Framework-45-Core'
            Ensure 		= 'Present'
			#DependsOn 	= '[WindowsFeature]Copy_NetFramework35'
        }

        <# File Copy_SQL2016BinariesSource
        {
            Ensure 					= 'Present' # Ensure the directory is Present on the target node.
            Type 					= 'Directory' # The default is File.
            Recurse 				= $true # Recursively copy all subdirectories.
            SourcePath 				= $SQL2016BinariesSource
            DestinationPath 		= $SQL2016BinariesDestination
			PsDscRunAsCredential   	= $Credential
			#DependsOn 				= '[WindowsFeature]Install_NetFramework45'
        }#>



<# Install SQL Server Region #>


        SqlSetup Install_Default_Instance
        {
            InstanceName           = 'MSSQLSERVER'
            Features               = 'SQLENGINE'
            SQLCollation           = 'SQL_Latin1_General_CP1_CI_AS'
            SQLSvcAccount          = $SqlServiceCredential
            AgtSvcAccount          = $SqlAgentServiceCredential
            ASSvcAccount           = $SqlServiceCredential
            SQLSysAdminAccounts    = "$Domain\administrator", $SqlAdministratorCredential.UserName
            ASSysAdminAccounts     = "$Domain\administrator", $SqlAdministratorCredential.UserName
            InstallSharedDir       = $InstallSharedDir   
            InstallSharedWOWDir    = $InstallSharedWOWDir
            InstanceDir            = $InstanceDir        
            InstallSQLDataDir      = $InstallSQLDataDir  
            SQLUserDBDir           = $SQLUserDBDir       
            SQLUserDBLogDir        = $SQLUserDBLogDir    
            SQLTempDBDir           = $SQLTempDBDir       
            SQLTempDBLogDir        = $SQLTempDBLogDir    
            SQLBackupDir           = $SQLBackupDir       
            ASServerMode           = 'TABULAR'
            ASConfigDir            = $ConfigDir
            ASDataDir              = $DataDir
            ASLogDir               = $LogDir 
            ASBackupDir            = $BackupDir
            ASTempDir              = $TempDir 
            SourcePath             = $SQL2016BinariesDestination # This is the location the files are copied to in the File 'DirectoryCopy' section
            UpdateEnabled          = 'False'
            ForceReboot            = $false

            PsDscRunAsCredential   = $SqlInstallCredential

            #DependsOn              = '[WindowsFeature]Copy_NetFramework35', '[WindowsFeature]Install_NetFramework45', '[File]Copy_SQL2016BinariesSource'
        }

		PendingReboot Post_Install_Default_Instance
        {
            Name                        = 'PostInstall'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            #DependsOn 					= '[SqlSetup]Install_Default_Instance'
        }
		

<# Set Max DOP to 1 #>
	
        SqlMaxDop Set_SQLServer_MaxDop_ToOne
        {
            Ensure               = 'Present'
            DynamicAlloc         = $false
            MaxDop               = '1'
            ServerName           = 'localhost'
            InstanceName         = 'MSSQLSERVER'
            PsDscRunAsCredential = $SqlInstallCredential
            #DependsOn 			 = '[SqlSetup]Install_Default_Instance'
         }
		
		PendingReboot Post_Set_SQLServer_MaxDop_ToOne
        {
            Name                        = 'PostInstall'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            #DependsOn 					= '[SqlMaxDop]Set_SQLServer_MaxDop_ToOne'
        }
		


<# SQL Accounts Group in Local Admin Region #>

		SqlLogin 'SP.Setup'
        {
            Ensure               = 'Present'
            Name                 = "$Domain\SP.Setup"
            LoginType            = 'WindowsUser'
            ServerName           = 'localhost'
            InstanceName         = 'MSSQLSERVER'
            PsDscRunAsCredential = $SqlInstallCredential
        }
        
        SqlLogin 'SP.Farm'
        {
            Ensure               = 'Present'
            Name                 = "$Domain\SP.Farm"
            LoginType            = 'WindowsUser'
            ServerName           = "$Name.$Domain.$TopLevelDomain"
            InstanceName         = 'MSSQLSERVER'
			
            PsDscRunAsCredential = $SqlInstallCredential
        }
		
		# Section that adds user accounts to SQL Server Roles
		# must add single quotes before and after each user account and a comma between each account on the Members line
		
        SqlRole Add_SP.Setup_ServerRole_ServerAdmin
        {
            Ensure               = 'Present'
            ServerRoleName       = 'serveradmin'
            Members              = "$Domain\sp.setup","$Domain\sp.farm"
            ServerName           = "$Name.$Domain.$TopLevelDomain"
            InstanceName         = 'MSSQLSERVER'
            PsDscRunAsCredential = $SqlInstallCredential
        }

        SqlRole Add_SP.Setup_ServerRole_SetupAdmin
        {
            Ensure               = 'Present'
            ServerRoleName       = 'SetupAdmin'
            Members              = "$Domain\sp.setup","$Domain\sp.farm"
            ServerName           = "$Name.$Domain.$TopLevelDomain"
            InstanceName         = 'MSSQLSERVER'
            PsDscRunAsCredential = $SqlInstallCredential
        }			

        SqlRole Add_SP.Setup_ServerRole_DBCreator
        {
            Ensure               = 'Present'
            ServerRoleName       = 'DBCreator'
            Members              = "$Domain\sp.setup","$Domain\sp.farm"
            ServerName           = "$Name.$Domain.$TopLevelDomain"
            InstanceName         = 'MSSQLSERVER'
            PsDscRunAsCredential = $SqlInstallCredential
        }
		
        SqlRole Add_SP.Setup_ServerRole_securityadmin
        {
            Ensure               = 'Present'
            ServerRoleName       = 'securityadmin'
            Members              = "$Domain\sp.setup","$Domain\sp.farm"
            ServerName           = "$Name.$Domain.$TopLevelDomain"
            InstanceName         = 'MSSQLSERVER'
            PsDscRunAsCredential = $SqlInstallCredential
        }
		
        SqlRole Add_SP.Setup_ServerRole_processadmin
        {
            Ensure               = 'Present'
            ServerRoleName       = 'processadmin'
            Members              = "$Domain\sp.setup","$Domain\sp.farm"
            ServerName           = "$Name.$Domain.$TopLevelDomain"
            InstanceName         = 'MSSQLSERVER'
            PsDscRunAsCredential = $SqlInstallCredential
        }
		
        SqlRole Add_SP.Setup_ServerRole_bulkadmin
        {
            Ensure               = 'Present'
            ServerRoleName       = 'bulkadmin'
            Members              = "$Domain\sp.setup","$Domain\sp.farm"
            ServerName           = "$Name.$Domain.$TopLevelDomain"
            InstanceName         = 'MSSQLSERVER'
            PsDscRunAsCredential = $SqlInstallCredential
        }
		
        SqlRole Add_SP.Setup_ServerRole_diskadmin
        {
            Ensure               = 'Present'
            ServerRoleName       = 'diskadmin'
            Members              = "$Domain\sp.setup","$Domain\sp.farm"
            ServerName           = "$Name.$Domain.$TopLevelDomain"
            InstanceName         = 'MSSQLSERVER'
            PsDscRunAsCredential = $SqlInstallCredential
        }

        File Finished_File
        {
            DestinationPath = 'C:\DSC\Finished.txt'
            Ensure = "Present"
            Contents = 'Computer configured, added to domain, and SQL Installed'
        }
	
			
     }
}

$cd = @{
    AllNodes = @(
        @{
            NodeName 					= 'localhost'
            PsDscAllowDomainUser 		= $true
            PsDscAllowPlainTextPassword = $true
            ActionAfterReboot 			= 'ContinueConfiguration';
            RebootNodeIfNeeded 			= $true;
        }
    )
}

[DSCLocalConfigurationManager()]
Configuration LCMConfig
{
    Node 'localhost'
    {
        Settings
        {
            ActionAfterReboot 	= 'ContinueConfiguration';
            RebootNodeIfNeeded 	= $true;
			RefreshMode = 'Push'
        }
    }
}
LCMConfig
Set-DscLocalConfigurationManager LCMConfig -Force -Verbose

Wrk.NameTimeIP.InstallDB.Accnts.SQL -ConfigurationData $cd

Start-DscConfiguration Wrk.NameTimeIP.InstallDB.Accnts.SQL -Force -Wait -Verbose
