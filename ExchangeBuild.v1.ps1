<#

This DSC script takes the inputs under the param section and sets the IP address, default gateway, DNS server, disables IPv6, renames the server, updates the computer description, and sets the time zone to GMT and adds it to the DEV2.test doamin created with the ADDS script. It then installs SQL Server.
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

PowerShell ISE will prompt you for 4 credentials: Domain Admin, Network Share Access, $1Domain\SQL.Install, and the $1Domain\SQL.Services

The machine will reboot multiple times

If you want to change the Name, Default Log location, etc from the default in the script just update the corresponding Parameter String in the Account Credential and Variable Region at the top of the script

#>


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

<# Change to c:\DSC directory #>
	cd C:\DSC

<# Determine Name of the Network Adapter in this OS #>
	$NetAdapterName = Get-NetAdapter -Name "Ethernet*"
	$NetAdapterName = $NetAdapterName.ifAlias


<# Account Credentials #>
    
    # Domain name for this install
    $1Domain = (read-host 'Please enter first part of domain name. EX: bilat.mil would be bilat.')

    # Top level domain for this install
    $1TopLevelDomain = (read-host 'Please enter top level part of domain name. EX: bilat.mil would be mil.')
 
    # Service Account for SharePoint Farm
    $ExchangeAdminCredential = Get-Credential -UserName "$1Domain\EX.Admin" -Message "Exchange Admin Account and Password"

    # Account for accessing file share that is not in the domain so that DSC does not use NT Authority Account Creds    
    $FileAccessAccount = Get-Credential -UserName "$1Domain\administrator" -Message "File Share Account and Password"
   


Configuration SPInstall
{
    param 
	(
        
        [Parameter()]
        [String]
        $Name = 'ExchangeSrv',
		
		[Parameter()]
        [String]
        $ComputerDescription = 'Exchange Server',
		
		[Parameter()]
        [String]
        $IPAddress = '192.168.10.221',
		
		[Parameter()]
        [String]
        $DefaultGateway = '192.168.10.254',
		
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

<# Combined AD Domain Name #>
    [Parameter()]
    [String]
    $DomainFQDN = $Domain + '.' + $TopLevelDomain,

<# Share Containing SharePoint2016 Binaries Extracted from ISO #>
	[Parameter()]
    [String]		
	$ExInstallFiles = "\\192.168.10.21\Files\Software\SPISO",

<# Local Folder to Hold the SharePoint2016 Binaries #>
	[Parameter()]
    [String]		
	$ExInstallFilesDestination = 'E:\SPISO',

<# Share Containing SharePoint2016 Binaries Extracted from ISO #>
	[Parameter()]
    [String]		
	$ExPReReqFiles = "\\192.168.10.21\Files\Software\SPPreReq",

<# Local Folder to Hold the SharePoint2016 Binaries #>
	[Parameter()]
    [String]		
	$ExPreReqFilesDestination = 'E:\SPPreReq',

<# Local Folder to Hold the SharePoint2016 Binaries #>
	[Parameter()]
    [String]
    $ExInstallArguments = '/mode:Install /role:XYZ /Iacceptexchangeserverlicenseterms',



<# SHAREPOINT Stuff - trying to reuse #>
<# URL for the SharePoint Main Site #>
	[Parameter()]
    [String]		
	$SharePointSitesPort = '80',

<# PORT for the SharePoint Centeral Administration Site #>
	[Parameter()]
    [String]		
	$SPCentAdminPort = '22222',

<# PORT for the SharePoint Centeral Administration Site #>
	[Parameter()]
    [String]		
	$UsageLogLocation = 'E:\UsageLogs',

<# PORT for the SharePoint Centeral Administration Site #>
	[Parameter()]
    [String]		
	$LogPath = 'E:\ULS',

<# PORT for the SharePoint Centeral Administration Site #>
	[Parameter()]
    [String]		
	$WebAppUrl = 'http://portal.' + $DomainFQDN,

<# PORT for the SharePoint Centeral Administration Site #>
	[Parameter()]
    [String]		
	$HostHeader =  'portal.' + $DomainFQDN,

<# PORT for the SharePoint Centeral Administration Site #>
	[Parameter()]
    [String]		
	$TeamSiteURL = '$WebAppUrl',

<# PORT for the SharePoint Centeral Administration Site #>
	[Parameter()]
    [String]		
	$TeamSiteName = 'DSC Demo SharePoint Site',

<# SQL Server that will hold SP Databases #>
	[Parameter()]
    [String]		
	$SQLServerFQDN = 'SQLSRV' + '.' + $DomainFQDN



    )

<# NEED TO VARIABLIZE


#>
########################################################
# DSC Module Region
########################################################

    Import-DscResource -ModuleName xPSDesiredStateConfiguration
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -Module NetworkingDsc
	Import-DscResource -Module ComputerManagementDsc
    Import-DscResource -ModuleName SharePointDsc
    Import-DscResource -ModuleName xexchange
	
########################################################
# DSC Node Region
########################################################
	
    node $AllNodes.NodeName
    {
 	
        File Started_File
        {
            DestinationPath = 'C:\DSC\Started.txt'
            Ensure = "Present"
            Contents = 'Computer not configured, not added to domain, and SharePoint not installed.'
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
			DependsOn	   = '[NetAdapterBinding]DisableIPv6'
        }

		DnsServerAddress SetDnsServerAddress
        {
            Address        = $DNS
            InterfaceAlias = $NetAdapterName
            AddressFamily  = 'IPv4'
            DependsOn	   = '[IPAddress]SetIPAddress'
        }

         DefaultGatewayAddress SetDefaultGateway
        {
            Address        = $DefaultGateway
            InterfaceAlias = $NetAdapterName
            AddressFamily  = 'IPv4'
            DependsOn	   = '[DnsServerAddress]SetDnsServerAddress'
        }
		
		TimeZone SetTimeZoneToGMT
        {
            IsSingleInstance 	= 'Yes'
            TimeZone         	= 'GMT Standard Time'
			DependsOn	   		= '[DefaultGatewayAddress]SetDefaultGateway'
        }

		PendingReboot PreJoinDomain
        {
            Name                        = 'PreJoinDomain'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[TimeZone]SetTimeZoneToGMT'
        }

		Computer JoinDomain
        {
            Name          	= $Name
            Description 	= $ComputerDescription
			DomainName 		= $DomainFQDN
            Credential 		= $FileAccessAccount  # Credential to join to domain
			DependsOn	   	= '[TimeZone]SetTimeZoneToGMT'
        }

		PendingReboot JoinDomain
        {
            Name                        = 'JoinDomain'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[Computer]JoinDomain'
        }


###############################################################################################
# Disable Windows Firewall
###############################################################################################

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
          
        

###############################################################################################
# Add Domain Users to Local Admin Group
###############################################################################################

		Group AddADUserToLocalAdminGroup 
		{
		GroupName='Administrators'
		Ensure= 'Present'
		MembersToInclude= "$1Domain\ExchangeAccounts"
		PsDscRunAsCredential = $FileAccessAccount
		}

###############################################################################################
# Copy Exchange Files
###############################################################################################

         File ExPreReqFiles_DirectoryCopy
        {
            Ensure                 = 'Present' # Ensure the directory is Present on the target node.
            Type                   = 'Directory' # The default is File.
            Recurse                = $true # Recursively copy all subdirectories.
            SourcePath             = $ExPReReqFiles
            DestinationPath        = $ExPReReqFilesDestination
			Credential             = $FileAccessAccount
            PsDscRunAsCredential   = $FileAccessAccount
        }

         File ExInstallFiles_DirectoryCopy
        {
            Ensure                 = 'Present' # Ensure the directory is Present on the target node.
            Type                   = 'Directory' # The default is File.
            Recurse                = $true # Recursively copy all subdirectories.
            SourcePath             = $ExInstallFiles
            DestinationPath        = $ExInstallFilesDestination
			Credential             = $FileAccessAccount
            PsDscRunAsCredential   = $FileAccessAccount
            DependsOn              = '[File]ExPreReqFiles_DirectoryCopy'
        }

		PendingReboot DirectoryCopy
        {
            Name                        = 'DirectoryCopy'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[File]ExInstallFiles_DirectoryCopy'
        }
		
###############################################################################################
# Install Exchange Prerequisites
###############################################################################################

         WindowsFeature Copy_NetFramework35
        {
            Name   					= 'NET-Framework-Core'
            Source 					= $SPPreReqFilesDestination # Assumes built-in Everyone has read permission to the share and path.
            Ensure 					= 'Present'
			PsDscRunAsCredential   	= $FileAccessAccount
            DependsOn 				= '[PendingReboot]DirectoryCopy'
        }


		PendingReboot InstallPrereqs
        {
            Name                        = 'InstallPrereqs'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[SPInstallPrereqs]InstallPrereqs'
        }
				
###############################################################################################
# Install Exchange
###############################################################################################		

        xExchInstall InstallExchange
        {
        Path = $ExInstallFilesDestination
        Arguments = $ExInstallArguments
        Credential = $ExchangeAdminCredential
        }





		PendingReboot SearchServiceApp
        {
            Name                        = 'SearchServiceApp'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[SPSearchServiceApp]SearchServiceApp'
        }


        File Finished_File
        {
            DestinationPath = 'C:\DSC\Finished.txt'
            Ensure = "Present"
            Contents = 'Computer configured, added to domain, and SharePoint installed.'
        }
		


    }
}

$cd = @{
    AllNodes = @(
        @{
            NodeName = 'localhost'
            PsDscAllowDomainUser = $true
            PsDscAllowPlainTextPassword = $true
            ActionAfterReboot = 'ContinueConfiguration';
            RebootNodeIfNeeded = $true;
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
            ActionAfterReboot = 'ContinueConfiguration';
            RebootNodeIfNeeded = $true;
        }
    }
}

LCMConfig
Set-DscLocalConfigurationManager LCMConfig -Force -Verbose

SPInstall -ConfigurationData $cd

Start-DscConfiguration SPInstall -Force -Wait -Verbose

dir
cd\

#Stop-DscConfiguration