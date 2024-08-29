<#

This DSC script takes the inputs under the param section and sets the IP address, default gateway, DNS server, disables IPv6, renames the server, updates the computer description, and sets the time zone to GMT
This example is allowing storage of credentials in plain text by setting PSDscAllowPlainTextPassword to $true.
Storing passwords in plain text is not a good practice and is presented only for simplicity and demonstration purposes.

Follow these steps:
Create a new VM with Windows Server 2016/2019 OS and determine the name of the NIC

Make sure the following DSC modules from https://www.powershellgallery.com/ are copied to C:\Program Files\WindowsPowerShell\Modules
ActiveDirectoryDsc
ComputerManagementDsc
NetworkingDsc
PSDesiredStateConfiguration
xDnsServer

Create a folder called C:\Temp

Copy the file Wrk.NameTimeIP.InstallAD.Accounts.ADDS.v4.ps1 to C:\Temp

Open PowerShell ISE

Run the following command: Set-ExecutionPolicy -ExecutionPolicy Unrestricted

Open C:\Temp\Wrk.NameTimeIP.InstallAD.Accounts.ADDS.v4.ps1 inside PowerShell ISE

Validate there are no errors in the script ~~~~~ Red Squiggley Lines are Bad

Run the script within PowerShell ISE

PowerShell ISE will prompt you for 3 credentials: Domain Admin, Domain Safe Mode, and the Service Account

The Service Account credential will only use the password to set all the passwords for the Service Accounts so it does not matter what user name you type in but the password does

The machine will reboot multiple times

If you want to change the Name, Description, IP Address, Default Gateway, DNS from the default in the script just update the corresponding Parameter String in the Account Credential and Variable Region at the top of the script

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



if (test-path -path "deploy:"){

    write-output "exists"
}
else {
    New-PSDrive -Name 'deploy' -PSProvider 'Filesystem' -Root "\\192.168.10.21\Deploy\Deploy Scripts\DEV\reference-files"
}

<# Change to c:\DSC directory #>
	cd C:\DSC




<# Determine Name of the Network Adapter in this OS #>
	$NetAdapterName = Get-NetAdapter -Name "Ethernet*"
	$NetAdapterName = $NetAdapterName.ifAlias



	
<# Account Credentials #>



  <# Account Credentials from file#>


    $key = [byte]1..16
    $credarray = get-content "deploy:\dacredz.txt"
    $credarraysplit = $credarray.split(',')
    $Credentialusername = $credarraysplit[0]
    $Credentialpassword = convertto-securestring -string $credarraysplit[1] -asplaintext -force
  
    $Credential = new-object -typename system.management.automation.pscredential -argumentlist $Credentialusername,$Credentialpassword
    
	$SafeModePassword = $Credential
    $ServiceAccountPassword = $Credential
    
	#$ServiceAccountPassword = Get-Credential -UserName 'administrator' -Message "New Default Service Account Password"




<#get domain from txt file #>

$domainfromtxt = get-content deploy:\domain.txt
$domainfromtxtsplit = $domainfromtxt.split('.')

<# Start of DSC Configuration Section #>

Configuration Wrk.NameTimeIP.InstallAD.Accounts.ADDS
{

<# 
	Account Credential and Variable Region 
#>

    param
    (
	
	<# Computer Variables #>

<# Server Name #>	
        [Parameter()]
        [String]
        $Name = 'ADsrvr',

<# Server Description #>		
	[Parameter()]
        [String]
        $ComputerDescription = 'Active Directory Server',

<# Server IP Address #>			
 	[Parameter()]
        [String]
        $IPAddress = '192.168.10.215',

<# Server Default Gateway #>		
	[Parameter()]
        [String]
        $DefaultGateway = '192.168.10.254',

<# DNS Server IP Address #>					
	[Parameter()]
        [String]
        $DNS = '192.168.10.215',
		
<# AD Database Location #>
        [Parameter()]
        [String]
        $DatabasePath = 'C:\Windows\NTDS',

<# AD Log Location #>
        [Parameter()]
        [String]
        $LogPath = 'C:\Windows\Logs',

<# AD Sysvol Location #>
        [Parameter()]
        [String]
        $SysvolPath = 'C:\Windows\SYSVOL',

<# FQDN = HostName.DomainName.TopLevelDomainName example = server.'DEV2'.test #>
#Get Domain from file#


<# Domain Name #>		
	[Parameter()]
        [String]
	$Domain = $domainfromtxtsplit[0],
		
<# FQDN = HostName.DomainName.TopLevelDomainName example = server.dev2.'TEST' #>
<# Top Level Domain Name #>		
	[Parameter()]
        [String]
	$TopLevelDomain = $domainfromtxtsplit[1],
	
<# Combined AD Domain Name #>
	[Parameter()]
        [String]
	$DomainFQDN = $Domain + '.' + $TopLevelDomain,
	
<# LDAP Path for Users #>
	[Parameter()]
        [String]
	$UserPath = 'CN=' + 'Users' + ',DC=' + $Domain + ',DC=' + $TopLevelDomain, 

<# LDAP Path for OUs #>
	[Parameter()]
        [String]
	$OUPath = 'DC=' + $Domain + ',DC=' + $TopLevelDomain, 

<# LDAP Path for Groups #>
	[Parameter()]
        [String]
	$GroupPath = 'OU=' + 'Service Accounts' + ',DC=' + $Domain + ',DC=' + $TopLevelDomain 
		
    )

<# NEED to Variablize

	xDnsRecord 'sites.dev3.test.1'
	    Target 	= '192.168.87.221'
 
#>
<# DSC Module Region #>

    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -Module NetworkingDsc
    Import-DscResource -Module ComputerManagementDsc
    Import-DSCResource -ModuleName xDnsServer

<# 	DSC Node Region #>
	
    Node $AllNodes.NodeName
    {
		 	
     File Started_File
        {
            DestinationPath = 'C:\DSC\Started.txt'
            Ensure = "Present"
            Contents = 'Computer not configured, not added to domain, and Active Directory not installed.'
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
            IsSingleInstance = 'Yes'
            TimeZone         = 'GMT Standard Time'
	    DependsOn	     = '[DefaultGatewayAddress]SetDefaultGateway'
        }

	Computer SetNewNameAndDescription
        {
            Name          	= $Name
            Description 	= $ComputerDescription
	    DependsOn	   	= '[TimeZone]SetTimeZoneToGMT'
        }
		
           		
	PendingReboot SetNewNameAndDescription
        {
            Name                        = 'SetNewNameAndDescription'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn = '[Computer]SetNewNameAndDescription'
        }

<# Reboot #>

<# 	Active Directory Region #>

        WindowsFeature 'ADDS'
        {
            Name   = 'AD-Domain-Services'
            Ensure = 'Present'
            #DependsON = '[WindowsFeature]DNS'
        }

        WindowsFeature 'RSATADPowerShell'
        {
            Name      = 'RSAT-AD-PowerShell'
	    Ensure    = 'Present'
            DependsOn = '[WindowsFeature]ADDS'
        }

        WindowsFeature 'RSAT-ADDS'
        {
            Name      = 'RSAT-ADDS'
	    Ensure    = 'Present'
            DependsOn = '[WindowsFeature]RSATADPowerShell'
        }
		
        WindowsFeature 'RSAT-AD-AdminCenter'
        {
            Name      = 'RSAT-AD-AdminCenter'
	    Ensure    = 'Present'
            DependsOn = '[WindowsFeature]RSAT-ADDS'
        }
		
        WindowsFeature 'RSAT-ADDS-Tools'
        {
            Name      = 'RSAT-ADDS-Tools'
	    Ensure    = 'Present'
            DependsOn = '[WindowsFeature]RSAT-AD-AdminCenter'
        }
        #WindowsFeature DNS
        #{
        #    Name = "DNS"
        #    Ensure = "Present"
        #    
       # 
       # 
       # }
					
        ADDomain 'InstallADDS'
        {
	        DomainName                    = $DomainFQDN
            #DomainNetBiosName             = $Domain
            Credential                    = $Credential
            SafeModeAdministratorPassword = $SafeModePassword
            DatabasePath                  = $DatabasePath
            LogPath                       = $LogPath
            SysvolPath                    = $SysvolPath
            DependsOn                     = '[WindowsFeature]RSATADPowerShell'			
        }
		
	PendingReboot AD2
        {
            Name                        = 'AD2'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn 			= '[ADDomain]InstallADDS'
        }
		
<# Reboot #>
		
<# 	User Creation Region #>

        WaitForADDomain 'WaitForestAvailability'
        {
            DomainName = $DomainFQDN
            Credential = $Credential
            DependsOn  = '[PendingReboot]AD2'
        }

<# 	SQL Creation Region #>
		
        ADUser 'SQL.Install'
        {
            Ensure              = 'Present'
            UserName            = 'SQL.Install'
            Password            = $ServiceAccountPassword
            PasswordNeverResets = $true
            DomainName          = $DomainFQDN
            Path                = $UserPath
	    DependsOn 		= '[WaitForADDomain]WaitForestAvailability'
        }

        ADUser 'SQL.Services'
        {
            Ensure              = 'Present'
            UserName            = 'SQL.Services'
            Password            = $ServiceAccountPassword
            PasswordNeverResets = $true
            DomainName          = $DomainFQDN
            Path                = $UserPath
	    DependsOn 		= '[ADUser]SQL.Install'
        }

<# 	SharePoint Creation Region #>
			
        ADUser 'SP.Farm'
        {
            Ensure              = 'Present'
            UserName            = 'SP.Farm'
            Password            = $ServiceAccountPassword
            PasswordNeverResets = $true
            DomainName          = $DomainFQDN
            Path                = $UserPath
	    DependsOn 		= '[ADUser]SQL.Services'
        }
		
        ADUser 'SP.Setup'
        {
            Ensure              = 'Present'
            UserName            = 'SP.Setup'
            Password            = $ServiceAccountPassword
            PasswordNeverResets = $true
            DomainName          = $DomainFQDN
            Path                = $UserPath
	    DependsOn 		= '[ADUser]SP.Farm'
        }
		
        ADUser 'SP.WebPool'
        {
            Ensure              = 'Present'
            UserName            = 'SP.WebPool'
            Password            = $ServiceAccountPassword
            PasswordNeverResets = $true
            DomainName          = $DomainFQDN
            Path                = $UserPath
	    DependsOn		= '[ADUser]SP.Setup'
        }
		
        ADUser 'SP.ServicePool'
        {
            Ensure              = 'Present'
            UserName            = 'SP.ServicePool'
            Password            = $ServiceAccountPassword
            PasswordNeverResets = $true
            DomainName          = $DomainFQDN
            Path                = $UserPath
	    DependsOn 		= '[ADUser]SP.WebPool'
        }

<# 	Exchange Creation Region #>
		
        ADUser 'EX.Admin'
        {
            Ensure              = 'Present'
            UserName            = 'EX.Admin'
            Password            = $ServiceAccountPassword
            PasswordNeverResets = $true
            DomainName          = $DomainFQDN
            Path                = $UserPath
	    DependsOn 		= '[ADUser]SP.ServicePool'
        }
		
		
<# OU Region #>		
		
	ADOrganizationalUnit 'Service Accounts OU'
        {
            Name                            = 'Service Accounts'
            Path                            = $OUPath
            ProtectedFromAccidentalDeletion = $true
            Description                     = 'Service Account OU'
            Ensure                          = 'Present'
	    DependsOn 			    = '[ADUser]SP.ServicePool'
        }
		
<# Groups Region #>

<# 	SharePoint Creation Region #>

        ADGroup 'SharePointAccountsGroup'
        {
            GroupName  	= 'SharePointAccounts'
            GroupScope 	= 'DomainLocal'
	    Description = 'SharePoint Service Accounts'
	    Path 	= $GroupPath
            Members    	= 'SP.Farm', 'SP.Setup', 'SP.WebPool', 'SP.ServicePool'
	    DependsOn 	= '[ADUser]SP.Farm','[ADUser]SP.Setup','[ADUser]SP.WebPool','[ADUser]SP.ServicePool'
        }

<# 	SQL Creation Region #>
		
        ADGroup 'SQLAccountsGroup'
        {
            GroupName  	= 'SQLAccounts'
            GroupScope 	= 'DomainLocal'
	    Description = 'SQL Service Accounts'
	    Path 	= $GroupPath
            Members    	= 'SQL.Install', 'SQL.Services'
	    DependsOn 	= '[ADUser]SQL.Install','[ADUser]SQL.Services'
        }

<# 	Exchange Creation Region #>
		
        ADGroup 'ExchangeAccountsGroup'
        {
            GroupName  	= 'ExchangeAccounts'
            GroupScope 	= 'DomainLocal'
	    Description = 'Exchange Service Accounts'
	    Path 	= $GroupPath
            Members    	= 'EX.Admin'
	    DependsOn 	= '[ADUser]EX.Admin'
        }


 
<# DNS Entry Region #>

<# The next section create a round robin DNS configuration for the SharePoint site #>
	xDnsRecord 'sites.dev3.test.1'
	{
	    Name        = 'portal'
	    Target 	= '192.168.10.219' # IP Address of the first SharePoint Server
	    Zone 	= $DomainFQDN
        Type   	= 'ARecord'
        Ensure 	= 'Present'
	    DependsOn 	= '[ADGroup]SQLAccountsGroup' 		
	} 
<#
	xDnsRecord 'sites.dev3.test.2'
	{
	    Name 	= 'portal'
	    Target 	= '192.168.10.219'# IP Address of the second SharePoint Server
	    Zone 	= $DomainFQDN
        Type   	= 'ARecord'
        Ensure 	= 'Present'
	    DependsOn 	= '[xDnsRecord]sites.dev3.test.1'
		}
#>	
        File Finished_File
        {
            DestinationPath = 'C:\DSC\Finished.txt'
            Ensure = "Present"
            Contents = 'Computer configured, domain created, accounts and groups created'
        }
		
 
    }
}

$cd = @{
    AllNodes = @(
        @{
            NodeName 			= 'localhost'
            PsDscAllowDomainUser	= $true
            PsDscAllowPlainTextPassword = $true
            ActionAfterReboot 		= 'ContinueConfiguration';
            RebootNodeIfNeeded 		= $true;
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
	    RefreshMode         = 'Push'
        }
    }
}
LCMConfig
Set-DscLocalConfigurationManager LCMConfig -Force -Verbose

Wrk.NameTimeIP.InstallAD.Accounts.ADDS -ConfigurationData $cd

Start-DscConfiguration Wrk.NameTimeIP.InstallAD.Accounts.ADDS -Force -Wait -Verbose
