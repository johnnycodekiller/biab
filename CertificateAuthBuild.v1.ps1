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

Copy the file ADCSCertAuth.Install.Config.v4.ps1 to C:\Temp

Open PowerShell ISE

Run the following command: Set-ExecutionPolicy -ExecutionPolicy Unrestricted

Open C:\Temp\ADCSCertAuth.Install.Config.v4.ps1 inside PowerShell ISE

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

<# Change to c:\DSC directory #>
	cd C:\DSC

<# Determine Name of the Network Adapter in this OS #>
	$NetAdapterName = Get-NetAdapter -Name "Ethernet*"
	$NetAdapterName = $NetAdapterName.ifAlias

	

	
	
<# Account Credentials #>

    $Credential = Get-Credential -UserName 'administrator' -Message "New Domain Admin User Name and Password"
    $ADJoinCredential = get-credential -message "Join Domain with what Credential?"

<# Start of DSC Configuration Section #>

Configuration ADCSCertAuth.Install.Config
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
        $Name = 'CERTDEV',

<# Server Description #>		
	[Parameter()]
        [String]
        $ComputerDescription = 'Certificate Authority',

<# Server IP Address #>			
 	[Parameter()]
        [String]
        $IPAddress = '192.168.10.216',

<# Server Default Gateway #>		
	[Parameter()]
        [String]
        $DefaultGateway = '192.168.10.254',

<# DNS Server IP Address #>					
	[Parameter()]
        [String]
        $DNS = '192.168.10.215',
		

<# FQDN = HostName.DomainName.TopLevelDomainName example = server.'DEV2'.test #>
<# Domain Name #>		
	[Parameter()]
        [String]
	$Domain = (read-host 'Please enter first part of domain name. EX: bilat.mil would be bilat.'),
		
<# FQDN = HostName.DomainName.TopLevelDomainName example = server.dev2.'TEST' #>
<# Top Level Domain Name #>		
	[Parameter()]
        [String]
	$TopLevelDomain = (read-host 'Please enter top level part of domain name. EX: bilat.mil would be mil.'),
	
<# Combined AD Domain Name #>
	[Parameter()]
        [String]
	$DomainFQDN = $Domain + '.' + $TopLevelDomain
		
    )

<# DSC Module Region #>

    Import-DscResource -ModuleName ActiveDirectoryDsc
    Import-DscResource -ModuleName PSDesiredStateConfiguration
    Import-DscResource -Module NetworkingDsc
    Import-DscResource -Module ComputerManagementDsc
    Import-DSCResource -ModuleName xDnsServer
    Import-DSCResource -Module ActiveDirectoryCSDsc

<# 	DSC Node Region #>
	
    Node $AllNodes.NodeName
    {
		 	
     File Started_File
        {
            DestinationPath = 'C:\DSC\CA-Started.txt'
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

	#Computer SetNewNameAndDescription
    #   {
    #        Name          	= $Name
    #        Description 	= $ComputerDescription
	#   DependsOn	   	= '[TimeZone]SetTimeZoneToGMT'
    #    }
    WaitForADDomain WaitForestAvailability
        {
            DomainName = $DomainFQDN
            Credential = $Credential
            DependsOn  = '[TimeZone]SetTimeZoneToGMT'
        }
        
        Computer JoinDomain
        {
            Name          	= $Name
			DomainName 		= $Domain
            Credential 		= $ADJoinCredential # Credential to join to domain
			DependsOn	   	= '[WaitForADDomain]WaitForestAvailability'
        }
        
           		
	PendingReboot SetNewNameAndDescription
        {
            Name                        = 'SetNewNameAndDescription'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn = '[Computer]JoinDomain'
        }

<# Reboot #>

<# 	Certificate Authority Installation #>

        WindowsFeature ADCS-Cert-Authority
        {
            Name   = 'ADCS-Cert-Authority'
            Ensure = 'Present'
            Dependson ='[PendingReboot]SetNewNameAndDescription'
        }

        WindowsFeature ADSC-Web-Enrollment
        {
            Name = 'ADCS-Web-Enrollment'
            Ensure = 'Present'
            Dependson ='[WindowsFeature]ADCS-Cert-Authority'
        }
        
        WindowsFeature ADCS-Enroll-Web-Pol
        {
            Name = 'ADCS-Enroll-Web-Pol'
            Ensure = 'Present'
            Dependson ='[WindowsFeature]ADCS-Cert-Authority'
        
        }
		
	#PendingReboot Post-Feature-Install
    #    {
    #        Name                        = 'Post-Feature-Install'
    #        SkipComponentBasedServicing = $false
    #        SkipWindowsUpdate           = $false
    #        SkipPendingFileRename       = $false
    #        SkipPendingComputerRename   = $false
    #        SkipCcmClientSDK            = $false
    #        DependsOn 			= '[WindowsFeature]ADCS-Enroll-Web-Pol'
    #    }
		
<# Reboot #>

    AdcsCertificationAuthority CertificateAuthority
    {
        IsSingleInstance      = 'yes'
        Ensure                = 'Present'
        Credential            = $ADJoinCredential
        CAType                = 'EnterpriseRootCA'
        DependsOn             = '[WindowsFeature]ADCS-Cert-Authority'
    
    }


    #AdcsWebEnrollment WebEncrollment 
    #{
    #    Ensure                 = 'Present'
    #    IsSingleInstance       = 'Yes'
    #    Credential             = $ADJoinCredential
    #    DependsOn              = '[PendingReboot]Post-Feature-Install'
    #}



			PendingReboot Post-Feature-Config
        {
            Name                        = 'Post-Feature-Config'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn 			= '[AdcsCertificationAuthority]CertificateAuthority'
        }

 




        File Finished_File
        {
            DestinationPath = 'C:\DSC\CA-Finished.txt'
            Ensure = "Present"
            Contents = 'Computer configured, domain created, accounts and groups created'
            DependsOn = '[PendingReboot]Post-Feature-Config'
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

ADCSCertAuth.Install.Config -ConfigurationData $cd

Start-DscConfiguration ADCSCertAuth.Install.Config -Force -Wait -Verbose
