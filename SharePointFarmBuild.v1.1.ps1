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
    $FarmAccount = Get-Credential -UserName "$1Domain\SP.Farm" -Message "SP Farm Account and Password"
	
    # Service Account for SharePoint Setup	
    $SPSetupAccount = Get-Credential -UserName "$1Domain\SP.Setup" -Message "SP Setup Account and Password"

    # Service Account for SharePoint Web/App Pool Management
    $WebPoolManagedAccount = Get-Credential -UserName "$1Domain\SP.WebPool" -Message "SP Webpool Account and Password"
   
    # Service Account for SharePoint Service Pool Management
    $ServicePoolManagedAccount = Get-Credential -UserName "$1Domain\SP.ServicePool" -Message "SP ServicePool Account and Password"
    
    # Pass Phrase for the SharePoint Farm    
    $Passphrase = Get-Credential -UserName "$1Domain\administrator" -Message "SP Passphrase"
    
    # Account for accessing file share that is not in the domain so that DSC does not use NT Authority Account Creds    
    $FileAccessAccount = Get-Credential -UserName "$1Domain\administrator" -Message "File Share Account and Password"
   


Configuration SPInstall
{
    param 
	(
        
        [Parameter()]
        [String]
        $Name = 'Shpntsrv',
		
		[Parameter()]
        [String]
        $ComputerDescription = 'SharePoint Server',
		
		[Parameter()]
        [String]
        $IPAddress = '192.168.10.219',
		
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
	$SPInstallFiles = "\\192.168.10.21\Files\Software\SPISO",

<# Local Folder to Hold the SharePoint2016 Binaries #>
	[Parameter()]
    [String]		
	$SPInstallFilesDestination = 'E:\SPISO',

<# Share Containing SharePoint2016 Binaries Extracted from ISO #>
	[Parameter()]
    [String]		
	$SPPReReqFiles = "\\192.168.10.21\Files\Software\SPPreReq",

<# Local Folder to Hold the SharePoint2016 Binaries #>
	[Parameter()]
    [String]		
	$SPPreReqFilesDestination = 'E:\SPPreReq',

<# Port for the SharePoint Main Site #>
	[Parameter()]
    [String]		
	$SharePointSitesPort = '80',

<# SSL Port for the SharePoint Main Site #>
	[Parameter()]
    [String]		
	$SharePointSitesPortSSL = '443',

<# PORT for the SharePoint Centeral Administration Site #>
	[Parameter()]
    [String]		
	$SPCentAdminPort = '22222',

<# PORT for the SharePoint Centeral Administration Site #>
	[Parameter()]
    [String]		
	$UsageLogLocation = 'E:\UsageLogs',

<# Location for the ULS Logs #>
	[Parameter()]
    [String]		
	$LogPath = 'E:\ULS',

<# Port URL for the Portal #>
	[Parameter()]
    [String]		
	$WebAppUrl80 = 'http://portal.' + $DomainFQDN,

<# SSL Port URL for the Portal #>
	[Parameter()]
    [String]		
	$WebAppUrlSSL = 'https://portal.' + $DomainFQDN,


<# Host Header for Portal #>
	[Parameter()]
    [String]		
	$HostHeader =  'portal.' + $DomainFQDN,

<# Set the URL to use Port 80 or Port 443 #>
	[Parameter()]
    [String]		
	$TeamSiteURL = $WebAppUrlSSL,

<# PORT for the SharePoint Centeral Administration Site #>
	[Parameter()]
    [String]		
	$TeamSiteName = 'DSC Demo SharePoint Site',

<# SQL Server that will hold SP Databases #>
	[Parameter()]
    [String]		
	$SQLServerFQDN = 'SQLSRV' + '.' + $DomainFQDN,


<# SharePoint Service Application Pool Name #>
	[Parameter()]
    [String]		
	$serviceAppPoolName = "SharePoint Service Applications",

<# SharePoint Web Application  Name #>
	[Parameter()]
    [String]
    $SPWebApplicationName = "Portal",


<# SharePoint Web Application Pool Name #>
	[Parameter()]
    [String]
    $SPWebApplicationApplicationPool = "Portal",

<# SSL Certificate Thumbprint #>
	[Parameter()]
    [String]
    $CertificateImportThumbprint   = 'c81b94933420221a7ac004a90242d8b1d3e5070d',

<# URI For Path to SSL Certificate to Import #>
	[Parameter()]
    [String]
    $CertificateImportPath         = '\\Server\Share\Certificates\MyTrustedRoot.cer',


<# SSL Certificate Friendly Name #>
	[Parameter()]
    [String]
    $CertificateImportFriendlyName = 'Portal'


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
    Import-DscResource -ModuleName xWebAdministration
    Import-DscResource -ModuleName CertificateDsc
	
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
		MembersToInclude= "$1Domain\SharePointAccounts"
		PsDscRunAsCredential = $FileAccessAccount
		}

###############################################################################################
# Copy SharePoint Binaries
###############################################################################################

         File SPPreReqFiles_DirectoryCopy
        {
            Ensure                 = 'Present' # Ensure the directory is Present on the target node.
            Type                   = 'Directory' # The default is File.
            Recurse                = $true # Recursively copy all subdirectories.
            SourcePath             = $SPPReReqFiles
            DestinationPath        = $SPPReReqFilesDestination
			Credential             = $FileAccessAccount
            PsDscRunAsCredential   = $FileAccessAccount
        }

         File SPInstallFiles_DirectoryCopy
        {
            Ensure                 = 'Present' # Ensure the directory is Present on the target node.
            Type                   = 'Directory' # The default is File.
            Recurse                = $true # Recursively copy all subdirectories.
            SourcePath             = $SPInstallFiles
            DestinationPath        = $SPInstallFilesDestination
			Credential             = $FileAccessAccount
            PsDscRunAsCredential   = $FileAccessAccount
            DependsOn                   = '[File]SPPreReqFiles_DirectoryCopy'
        }

		PendingReboot DirectoryCopy
        {
            Name                        = 'DirectoryCopy'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[File]SPInstallFiles_DirectoryCopy'
        }
		
###############################################################################################
# SharePoint Prerequisites
###############################################################################################

         WindowsFeature Copy_NetFramework35
        {
            Name   					= 'NET-Framework-Core'
            Source 					= $SPPreReqFilesDestination # Assumes built-in Everyone has read permission to the share and path.
            Ensure 					= 'Present'
			PsDscRunAsCredential   	= $FileAccessAccount
            DependsOn 				= '[PendingReboot]DirectoryCopy'
        }

        SPInstallPrereqs InstallPrereqs {
            IsSingleInstance  = "Yes"
            Ensure            = "Present"
            InstallerPath     = "$SPInstallFilesDestination\prerequisiteinstaller.exe" # attempt to variablize
            OnlineMode        = $false
            SQLNCli = "$SPPreReqFilesDestination\sqlncli.msi"
            SXSpath = "$SPPreReqFilesDestination\microsoft-windows-netfx3-ondemand-package.cab"
            Sync = "$SPPreReqFilesDestination\Synchronization.msi"
            AppFabric = "$SPPreReqFilesDestination\WindowsServerAppFabricSetup_x64.exe"
            IDFX11 = "$SPPreReqFilesDestination\MicrosoftIdentityExtensions-64.msi"
            MSIPCClient = "$SPPreReqFilesDestination\setup_msipc_x64.exe"
            WCFDataServices56 = "$SPPreReqFilesDestination\WcfDataServices.exe"
            MSVCRT11 = "$SPPreReqFilesDestination\vcredist_x64 (2012).exe"
            KB3092423 = "$SPPreReqFilesDestination\AppFabric-KB3092423-x64-ENU.exe"
            DotNet472 = "$SPPreReqFilesDestination\ndp472-kb4054530-x86-x64-allos-enu.exe"
            MSVCRT141 = "$SPPreReqFilesDestination\VC_redist.x64 (2017).exe"
            DependsOn = '[WindowsFeature]Copy_NetFramework35'
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
# Install SharePoint
###############################################################################################		
        SPInstall InstallSharePoint 
        {
            IsSingleInstance  = "Yes"
            Ensure            = "Present"
            BinaryDir         = "$SPInstallFilesDestination"
            ProductKey         = "7G7R6-N6QJC-JFPJX-CK8WX-66QW4"
            DependsOn         = "[SPInstallPrereqs]InstallPrereqs"
        }

		PendingReboot InstallSharePoint
        {
            Name                        = 'InstallSharePoint'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[SPInstall]InstallSharePoint'
        }

		SPConfigWizard RunConfigWizard
		{
			IsSingleInstance     	= "Yes"
			Ensure					= 'Present'
			PsDscRunAsCredential 	= $SPSetupAccount
            DependsOn               = '[SPInstall]InstallSharePoint'			
		}
        
		PendingReboot InstallKB4011244
        {
            Name                        = 'InstallKB4011244'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[SPConfigWizard]RunConfigWizard'
        }

		

        #**********************************************************
        # Basic farm configuration
        #
        # This section creates the new SharePoint farm object, and
        # provisions generic services and components used by the
        # whole farm
        #**********************************************************
        		
        SPFarm CreateSPFarm
        {
            IsSingleInstance         = "Yes"
            Ensure                   = "Present"
            DatabaseServer           = $SQLServerFQDN # Need to Variablize
            FarmConfigDatabaseName   = "SP_Config"
            Passphrase               = $Passphrase
            FarmAccount              = $FarmAccount
            PsDscRunAsCredential     = $SPSetupAccount
            AdminContentDatabaseName = "SP_AdminContent"
            RunCentralAdmin          = $true
            CentralAdministrationPort= $SPCentAdminPort
            DependsOn                = "[SPInstall]InstallSharePoint"
        }

        SPManagedAccount ServicePoolManagedAccount
        {
            AccountName          = $ServicePoolManagedAccount.UserName
            Account              = $ServicePoolManagedAccount
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPManagedAccount WebPoolManagedAccount
        {
            AccountName          = $WebPoolManagedAccount.UserName
            Account              = $WebPoolManagedAccount
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPDiagnosticLoggingSettings ApplyDiagnosticLogSettings
        {
            IsSingleInstance                            = "Yes"
            PsDscRunAsCredential                        = $SPSetupAccount
            LogPath                                     = $LogPath
            LogSpaceInGB                                = 5
            AppAnalyticsAutomaticUploadEnabled          = $false
            CustomerExperienceImprovementProgramEnabled = $true
            DaysToKeepLogs                              = 7
            DownloadErrorReportingUpdatesEnabled        = $false
            ErrorReportingAutomaticUploadEnabled        = $false
            ErrorReportingEnabled                       = $false
            EventLogFloodProtectionEnabled              = $true
            EventLogFloodProtectionNotifyInterval       = 5
            EventLogFloodProtectionQuietPeriod          = 2
            EventLogFloodProtectionThreshold            = 5
            EventLogFloodProtectionTriggerPeriod        = 2
            LogCutInterval                              = 15
            LogMaxDiskSpaceUsageEnabled                 = $true
            ScriptErrorReportingDelay                   = 30
            ScriptErrorReportingEnabled                 = $true
            ScriptErrorReportingRequireAuth             = $true
            DependsOn                                   = "[SPFarm]CreateSPFarm"
        }

        SPUsageApplication UsageApplication
        {
            Name                  = "Usage Service Application"
            DatabaseName          = "SP_Usage"
            UsageLogCutTime       = 5
            UsageLogLocation      = $UsageLogLocation
            UsageLogMaxFileSizeKB = 1024
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = "[SPFarm]CreateSPFarm"
        }

        SPStateServiceApp StateServiceApp
        {
            Name                 = "State Service Application"
            DatabaseName         = "SP_State"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPDistributedCacheService EnableDistributedCache
        {
            Name                 = "AppFabricCachingService"
            Ensure               = "Present"
            CacheSizeInMB        = 1024
            ServiceAccount       = $ServicePoolManagedAccount.UserName
            PsDscRunAsCredential = $SPSetupAccount
            CreateFirewallRules  = $true
            DependsOn            = @('[SPFarm]CreateSPFarm','[SPManagedAccount]ServicePoolManagedAccount')
        }

		PendingReboot EnableDistributedCache
        {
            Name                        = 'EnableDistributedCache'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[SPDistributedCacheService]EnableDistributedCache'
        }
		  
        #**********************************************************
        # Web applications
        #
        # This section creates the web applications in the
        # SharePoint farm, as well as managed paths and other web
        # application settings
        #**********************************************************

        SPWebApplication SharePointPortal
        {
            Name                   = $SPWebApplicationName
            ApplicationPool        = $SPWebApplicationApplicationPool
            ApplicationPoolAccount = $WebPoolManagedAccount.UserName
            AllowAnonymous         = $false
            DatabaseName           = "SP_Content"
            WebAppUrl              = $WebAppUrlSSL
            HostHeader             = $HostHeader
            Port                   = $SharePointSitesPortSSL
            PsDscRunAsCredential   = $SPSetupAccount
            DependsOn              = "[SPManagedAccount]WebPoolManagedAccount"
        }

###############################################################################################	
# SSL Cert Import using CertificateDsc
###############################################################################################
	
        CertificateImport PortlSSLCert
        {
            Thumbprint   = $CertificateImportThumbprint
            Location     = 'LocalMachine'
            Store        = 'Root'
            Path         = $CertificateImportPath
            FriendlyName = $CertificateImportFriendlyName
        }
        # End SSL Cert Import using CertificateDsc

        # SSL Cert Binding using xWebAdministration
        xWebSite    SSLWebAppSharePointPortal
        {
            Ensure = 'Present'
            Name = $SPWebApplicationName
            BindingInfo = @(
                    Msft_xwebBindingInformation
                    {
                        Protocol = 'https'
                        IPAddress = '*' # already is a variable but want to see it work first
                        Port = $SharePointSitesPortSSL
                        CertificateThumbprint = $CertificateImportThumbprint
                        CertificateStoreName = 'My' # what store is this?
                        HostName = $HostHeader
                        SslFlags = 1
                    }
                    )
        }

        # End SSL Cert Binding using xWebAdministration
###############################################################################################	

        SPCacheAccounts WebAppCacheAccounts
        {
            WebAppUrl              = $WebAppUrlSSL
            SuperUserAlias         = "$1Domain\sp.farm"
            SuperReaderAlias       = "$1Domain\sp.farm"
            PsDscRunAsCredential   = $SPSetupAccount
            DependsOn              = "[SPWebApplication]SharePointPortal"
        }

        SPSite TeamSite
        {
            Url                      = $TeamSiteURL
            OwnerAlias               = "$1Domain\sp.farm"
            Name                     = $TeamSiteName
            Template                 = "STS#0"
            CreateDefaultGroups      = $true
            AdministrationSiteType   = 'None'
            PsDscRunAsCredential     = $SPSetupAccount
            DependsOn                = "[SPWebApplication]SharePointPortal"
        }

		PendingReboot TeamSite
        {
            Name                        = 'TeamSite'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[SPSite]TeamSite'
        }

        #**********************************************************
        # Service instances
        #
        # This section describes which services should be running
        # and not running on the server
        #**********************************************************

        SPServiceInstance ClaimsToWindowsTokenServiceInstance
        {
            Name                 = "Claims to Windows Token Service"
            Ensure               = "Present"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance SecureStoreServiceInstance
        {
            Name                 = "Secure Store Service"
            Ensure               = "Present"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance ManagedMetadataServiceInstance
        {
            Name                 = "Managed Metadata Web Service"
            Ensure               = "Present"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance BCSServiceInstance
        {
            Name                 = "Business Data Connectivity Service"
            Ensure               = "Present"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPServiceInstance SearchServiceInstance
        {
            Name                 = "SharePoint Server Search"
            Ensure               = "Present"
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

		PendingReboot SearchServiceInstance
        {
            Name                        = 'SearchServiceInstance'
            SkipComponentBasedServicing = $false
            SkipWindowsUpdate           = $false
            SkipPendingFileRename       = $false
            SkipPendingComputerRename   = $false
            SkipCcmClientSDK            = $false
            DependsOn                   = '[SPServiceInstance]SearchServiceInstance'
        }
	
        #**********************************************************
        # Service applications
        #
        # This section creates service applications and required
        # dependencies
        #**********************************************************

        #$serviceAppPoolName = "SharePoint Service Applications"
        SPServiceAppPool MainServiceAppPool
        {
            Name                 = $serviceAppPoolName
            ServiceAccount       = $ServicePoolManagedAccount.UserName
            PsDscRunAsCredential = $SPSetupAccount
            DependsOn            = "[SPFarm]CreateSPFarm"
        }

        SPSecureStoreServiceApp SecureStoreServiceApp
        {
            Name                  = "Secure Store Service Application"
            ApplicationPool       = $serviceAppPoolName
            AuditingEnabled       = $true
            AuditlogMaxSize       = 30
            DatabaseName          = "SP_SecureStore"
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
        }

        SPManagedMetaDataServiceApp ManagedMetadataServiceApp
        {
            Name                 = "Managed Metadata Service Application"
            PsDscRunAsCredential = $SPSetupAccount
            ApplicationPool      = $serviceAppPoolName
            DatabaseName         = "SP_MMS"
            DependsOn            = "[SPServiceAppPool]MainServiceAppPool"
        }

        SPBCSServiceApp BCSServiceApp
        {
            Name                  = "BCS Service Application"
            ApplicationPool       = $serviceAppPoolName
            DatabaseName          = "SP_BCS"
			DatabaseServer		  = $SQLServerFQDN
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = @('[SPServiceAppPool]MainServiceAppPool', '[SPSecureStoreServiceApp]SecureStoreServiceApp')
        }

        SPSearchServiceApp SearchServiceApp
        {
            Name                  = "Search Service Application"
            DatabaseName          = "SP_Search"
            ApplicationPool       = $serviceAppPoolName
            PsDscRunAsCredential  = $SPSetupAccount
            DependsOn             = "[SPServiceAppPool]MainServiceAppPool"
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

Remove-DscConfigurationDocument -Stage Current
#Stop-DscConfiguration