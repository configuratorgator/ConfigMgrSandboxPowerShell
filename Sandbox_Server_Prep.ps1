<#

.SYNOPSIS
Author: Brian Gade (@Configur8rGator, www.configuratorgator.com)

.DESCRIPTION
Prepares the servers in a sandbox environment.
    1) Installs and configures the Domain Controller
    2) Installs and configures SQL Server
    3) Installs the Windows ADK
    4) Installs an MECM Technical Preview standalone primary site
    5) Optionally installs the prerequisites for any additional MECM servers
    6) Optionally installs and configures a WSUS server
        This does NOT link the WSUS server to MECM as a SUP, it only prepares it to be a SUP.

Once you've run the script for each of the required pieces, you should have a basic, functional MECM TP environment.
Because this is a sandbox environment, it does NOT follow best practices for security.
There are several defaults that can be changed in the script's variables block if you so desire.  This includes
things like the domain name, IP addressing, service account name, sandbox-wide password, and WSUS selections.

PREREQUISITES:
1) The NIC that should communicate with the domain has been renamed to "LAN".  For machines with only
   one NIC, it will automatically be renamed.
2) The necessary CABs for .NET 3.5 for the correct version of Windows Server are in the same folder as the script
3) The SQL Server ISO is in the same folder as the script and is named something like "SQL Server ####.iso"
4) The SSMS installer is in the same folder as the script and has the default name of SSMS-Setup-ENU.exe
5) The Windows ADK folder is in the same folder as the script and is named something like "ADK_####"
6) The Windows ADK folder contains two subfolders named "Core" and "WinPE", which each contain the offline
   Windows ADK installers for their respective components
7) A folder named ADCSTemplate is in the same folder as the script and contains the ADCSTemplate PowerShell module

RECOMMENDED ENVIRONMENT:
Use VMware Workstation to create two Windows Server 2016 (or newer) VMs for the core environment.
Hyper-V can also be used but the network configuration within the hypervisor will be a bit different.
You can create additional VMs as desired for additional MECM roles (SUP, additional/remote DP, etc.).
VM1 - Sandbox Domain Controller (Required)
    CPU: 2
    RAM: 4GB
    Disk1: 50GB
    NIC1: LAN Segment
        Rename the NIC in the OS to "LAN"
    Computer Name: DC01
VM2 - Sandbox Configuration Manager (Required)
    CPU: 4
    RAM: 16GB
    Disk1: 100GB
    Disk2: 100GB
    NIC1: LAN Segment
        In the OS, rename the NIC to "LAN"
    NIC2: NAT
        In the OS, rename the NIC to "WAN"
    Computer Name: CM01
VM3 - Sandbox WSUS/SUP (Optional)
VM4 - Sandbox Remote DP (Optional)

.PARAMETER DomainController
Switch.  Select to configure the Domain Controller server.

.PARAMETER DC_Name
String.  The name to assign to the Domain Controller server.

.PARAMETER DC_IPAddress
String.  The IP Address to assign to the Domain Controller server.

.PARAMETER DC_Phase
String.  The installation phase to process.  Uses a ValidateSet with phases numbered in the order they should be run.

.PARAMETER ConfigMgrPrimaryServer
Switch.  Select to configure the primary Configuration Manager server.

.PARAMETER CMPrimary_CMName
String.  The name to assign to the primary Configuration Manager server.

.PARAMETER CMPrimary_DCName
String.  The name of the existing Domain Controller server.

.PARAMETER CMPrimary_IPAddress
String.  The IP Address to assign to the primary Configuration Manager server.

.PARAMETER CMPrimary_Phase
String.  The installation phase to process.  Uses a ValidateSet with phases numbered in the order they should be run.

.PARAMETER ConfigMgrAdditionalServer
Switch.  Select to configure an additional Configuration Manager server.

.PARAMETER CMAdditional_CMName
String.  The name to assign to the additional Configuration Manager server.

.PARAMETER CMAdditional_DCName
String.  The name of the existing Domain Controller server.

.PARAMETER CMAdditional_IPAddress
String.  The IP Address to assign to the additional Configuration Manager server.

.PARAMETER CMAdditional_Phase
String.  The installation phase to process.  Uses a ValidateSet with phases numbered in the order they should be run.

.PARAMETER ConfigMgrSUPServer
Switch.  Select to configure a WSUS/SUP server.

.PARAMETER CMSUP_SUPName
String.  The name to assign to the WSUS/SUP server.

.PARAMETER CMSUP_CMName
String.  The name of the existing primary Configuration Manager server.

.PARAMETER CMSUP_DCName
String.  The name of the existing Domain Controller server.

.PARAMETER CMSUP_IPAddress
String.  The IP Address to assign to the WSUS/SUP server.

.PARAMETER CMSUP_Phase
String.  The installation phase to process.  Uses a ValidateSet with phases numbered in the order they should be run.

.EXAMPLE
1) On the Domain Controller server:
    .\Sandbox_Server_Prep.ps1 -DomainController -DC_Name DC01 -DC_IPAddress 10.10.10.1 -DC_Phase 1_ServerPrep
    Wait for reboot
    .\Sandbox_Server_Prep.ps1 -DomainController -DC_Name DC01 -DC_IPAddress 10.10.10.1 -DC_Phase 2_DomainControllerInstall
    Wait for reboot
    .\Sandbox_Server_Prep.ps1 -DomainController -DC_Name DC01 -DC_IPAddress 10.10.10.1 -DC_Phase 3_DomainControllerConfig
2) On the Configuration Manager primary server:
    .\Sandbox_Server_Prep.ps1 -ConfigMgrPrimaryServer -CMPrimary_CMName CM01 -CMPrimary_DCName DC01 -CMPrimary_IPAddress 10.10.10.2 -CMPrimary_Phase 1_ServerPrep
    Wait for reboot
    .\Sandbox_Server_Prep.ps1 -ConfigMgrPrimaryServer -CMPrimary_CMName CM01 -CMPrimary_DCName DC01 -CMPrimary_IPAddress 10.10.10.2 -CMPrimary_Phase 2_ConfigMgrPrep
    Wait for reboot
    .\Sandbox_Server_Prep.ps1 -ConfigMgrPrimaryServer -CMPrimary_CMName CM01 -CMPrimary_DCName DC01 -CMPrimary_IPAddress 10.10.10.2 -CMPrimary_Phase 3_ConfigMgrPrereqs
    Wait for reboot
    .\Sandbox_Server_Prep.ps1 -ConfigMgrPrimaryServer -CMPrimary_CMName CM01 -CMPrimary_DCName DC01 -CMPrimary_IPAddress 10.10.10.2 -CMPrimary_Phase 4_ConfigMgrInstall
3) OPTIONAL: On the WSUS/SUP server:
    .\Sandbox_Server_Prep.ps1 -ConfigMgrSUPServer -CMSUP_SUPName SUP01 -CMSUP_CMName CM01 -CMSUP_DCName DC01 -CMSUP_IPAddress 10.10.10.3 -CMSUP_Phase 1_ServerPrep
    Wait for reboot
    .\Sandbox_Server_Prep.ps1 -ConfigMgrSUPServer -CMSUP_SUPName SUP01 -CMSUP_CMName CM01 -CMSUP_DCName DC01 -CMSUP_IPAddress 10.10.10.3 -CMSUP_Phase 2_SUPPrep
    Wait for reboot
    .\Sandbox_Server_Prep.ps1 -ConfigMgrSUPServer -CMSUP_SUPName SUP01 -CMSUP_CMName CM01 -CMSUP_DCName DC01 -CMSUP_IPAddress 10.10.10.3 -CMSUP_Phase 3_SUPInstall
4) OPTIONAL: On any additional Configuration Manager server(s):
    .\Sandbox_Server_Prep.ps1 -ConfigMgrAdditionalServer -CMAdditional_CMName CM01 -CMAdditional_DCName DC01 -CMAdditional_IPAddress 10.10.10.2 -CMAdditional_Phase 1_ServerPrep
    Wait for reboot
    .\Sandbox_Server_Prep.ps1 -ConfigMgrAdditionalServer -CMAdditional_CMName CM01 -CMAdditional_DCName DC01 -CMAdditional_IPAddress 10.10.10.2 -CMAdditional_Phase 2_ConfigMgrPrep
    Wait for reboot

.NOTES
Change log:
v1.0.0, Brian Gade, 11/8/19 - Original Version

#>
# DEFINE PARAMETERS ----------------------------------------------
Param(
    [Parameter(ParameterSetName="DomainController")]
        [switch] $DomainController,
    [Parameter(ParameterSetName="DomainController",Mandatory=$True)]
        [string] $DC_Name,
    [Parameter(ParameterSetName="DomainController",Mandatory=$True)]
        [string] $DC_IPAddress,
    [Parameter(ParameterSetName="DomainController",Mandatory=$True)][ValidateSet("1_ServerPrep","2_DomainControllerInstall","3_DomainControllerConfig")]
        [string] $DC_Phase,

    [Parameter(ParameterSetName="ConfigMgrPrimaryServer")]
        [switch] $ConfigMgrPrimaryServer,
    [Parameter(ParameterSetName="ConfigMgrPrimaryServer",Mandatory=$True)]
        [string] $CMPrimary_CMName,
    [Parameter(ParameterSetName="ConfigMgrPrimaryServer",Mandatory=$True)]
        [string] $CMPrimary_DCName,
    [Parameter(ParameterSetName="ConfigMgrPrimaryServer",Mandatory=$True)]
        [string] $CMPrimary_IPAddress,
    [Parameter(ParameterSetName="ConfigMgrPrimaryServer",Mandatory=$True)][ValidateSet("1_ServerPrep","2_ConfigMgrPrep","3_ConfigMgrPrereqs","4_ConfigMgrInstall")]
        [string] $CMPrimary_Phase,

    [Parameter(ParameterSetName="ConfigMgrAdditionalServer")]
        [switch] $ConfigMgrAdditionalServer,
    [Parameter(ParameterSetName="ConfigMgrAdditionalServer",Mandatory=$True)]
        [string] $CMAdditional_CMName,
    [Parameter(ParameterSetName="ConfigMgrAdditionalServer",Mandatory=$True)]
        [string] $CMAdditional_DCName,
    [Parameter(ParameterSetName="ConfigMgrAdditionalServer",Mandatory=$True)]
        [string] $CMAdditional_IPAddress,
    [Parameter(ParameterSetName="ConfigMgrAdditionalServer",Mandatory=$True)][ValidateSet("1_ServerPrep","2_ConfigMgrPrep")]
        [string] $CMAdditional_Phase,

    [Parameter(ParameterSetName="ConfigMgrSUPServer")]
        [switch] $ConfigMgrSUPServer,
    [Parameter(ParameterSetName="ConfigMgrSUPServer",Mandatory=$True)]
        [string] $CMSUP_SUPName,
    [Parameter(ParameterSetName="ConfigMgrSUPServer",Mandatory=$True)]
        [string] $CMSUP_CMName,
    [Parameter(ParameterSetName="ConfigMgrSUPServer",Mandatory=$True)]
        [string] $CMSUP_DCName,
    [Parameter(ParameterSetName="ConfigMgrSUPServer",Mandatory=$True)]
        [string] $CMSUP_IPAddress,
    [Parameter(ParameterSetName="ConfigMgrSUPServer",Mandatory=$True)][ValidateSet("1_ServerPrep","2_SUPPrep","3_SUPInstall")]
        [string] $CMSUP_Phase
)
# END DEFINE PARAMETERS ------------------------------------------
# START TRANSCRIPTING --------------------------------------------
$TranscriptLogFile = '.\ServerPrepTranscript.log'
Start-Transcript -Path $TranscriptLogFile -Append -NoClobber
# DEFINE VARIABLES -----------------------------------------------

# These variables can be edited to change the domain name, service account name, and environment-wide password
$DHCPStartIP = "10.10.10.100"
$DHCPEndIP = "10.10.10.200"
$DHCPSubnetMask = "255.255.255.0"
$DHCPDNSServers = "10.10.10.1" # This should be the same IP as the one assigned to the domain controller server
$DHCPRouter = "10.10.10.1" # This should be the same IP as the one assigned to the domain controller server
$DomainCADisplayName = "Sandbox CA"
$DomainFQDN = "sandbox.local"
$DomainNetbios = "sandbox"
$DomainLDAP = "DC=sandbox,DC=local"
$DomainServiceAccountName = "sndsvc"
$DomainServiceAccountDisplayName = "Service Account"
$PasswordPlainText = 'Pa$$w0rd'
$MECMAdminsGroupName = "MECM Admins"
$MECMServersGroupName = "MECM Servers"
$SQLAdminsGroupName = "SQL Admins"
$SQLMemoryLimitMB = 8192
$WSUSClassificationsToSync = "Critical Updates","Definition Updates","Feature Packs","Security Updates","Service Packs","Update Rollups","Updates"
$WSUSProductsToSync = "Windows 10","Windows 10, version 1903 and later"

# These variables should not be modified
$DCName = $DC_Name + $CMPrimary_DCName + $CMAdditional_DCName + $CMSUP_DCName
$IPAddress = $DC_IPAddress + $CMPrimary_IPAddress + $CMAdditional_IPAddress + $CMSUP_IPAddress
$NICs = @()
$PasswordSecure = $PasswordPlainText | ConvertTo-SecureString -AsPlainText -Force
$Phase = $DC_Phase + $CMPrimary_Phase + $CMAdditional_Phase + $CMSUP_Phase
$PrereqFailureReason = @()
$CMName = $CMPrimary_CMName + $CMAdditional_CMName + $CMSUP_CMName

$Roles_CertificateAuthority = "ADCertificateServicesManagementTools",
"ADCertificateServicesRole",
"CertificateServices",
"CertificateServicesManagementTools"

$Roles_DomainController = "ActiveDirectory-PowerShell",
"DHCPServer",
"DHCPServer-Tools",
"DirectoryServices-DomainController",
"DirectoryServices-DomainController-Tools",
"DNS-Server-Full-Role",
"DNS-Server-Tools",
"RSAT-ADDS-Tools-Feature",
"RSAT-AD-Tools-Feature"

$Roles_ConfigMgr = "ActiveDirectory-PowerShell",
"BITS",
"BITSExtensions-AdminPack",
"BITSExtensions-Upload",
"CoreFileServer",
"Dedup-Core",
"File-Services",
"IIS-ApplicationDevelopment",
"IIS-ASPNET",
"IIS-ASPNET45",
"IIS-CGI",
"IIS-CommonHttpFeatures",
"IIS-DefaultDocument",
"IIS-DigestAuthentication",
"IIS-DirectoryBrowsing",
"IIS-HealthAndDiagnostics",
"IIS-HttpCompressionDynamic",
"IIS-HttpCompressionStatic",
"IIS-HttpErrors",
"IIS-HttpLogging",
"IIS-HttpRedirect",
"IIS-HttpTracing",
"IIS-IIS6ManagementCompatibility",
"IIS-ISAPIExtensions",
"IIS-ISAPIFilter",
"IIS-LoggingLibraries",
"IIS-ManagementConsole",
"IIS-ManagementScriptingTools",
"IIS-ManagementService",
"IIS-Metabase",
"IIS-NetFxExtensibility",
"IIS-NetFxExtensibility45",
"IIS-Performance",
"IIS-RequestFiltering",
"IIS-RequestMonitor",
"IIS-Security",
"IIS-StaticContent",
"IIS-WebServer",
"IIS-WebServerManagementTools",
"IIS-WebServerRole",
"IIS-WindowsAuthentication",
"IIS-WMICompatibility",
"MSRDC-Infrastructure",
"NetFx3",
"NetFx3ServerFeatures",
"NetFx4Extended-ASPNET45",
"RSAT-AD-Tools-Feature",
"ServerManager-Core-RSAT",
"ServerManager-Core-RSAT-Feature-Tools",
"ServerManager-Core-RSAT-Role-Tools",
"WAS-ConfigurationAPI",
"WAS-ProcessModel",
"WAS-WindowsActivationService",
"WCF-HTTP-Activation45"

$Roles_ConfigMgrSUP = "IIS-ApplicationDevelopment",
"IIS-ASPNET45",
"IIS-CommonHttpFeatures",
"IIS-DefaultDocument",
"IIS-HttpCompressionDynamic",
"IIS-IIS6ManagementCompatibility",
"IIS-ISAPIExtensions",
"IIS-ISAPIFilter",
"IIS-ManagementConsole",
"IIS-Metabase",
"IIS-NetFxExtensibility45",
"IIS-Performance",
"IIS-RequestFiltering",
"IIS-Security",
"IIS-StaticContent",
"IIS-WebServer",
"IIS-WebServerManagementTools",
"IIS-WebServerRole",
"IIS-WindowsAuthentication",
"UpdateServices",
"UpdateServices-API",
"UpdateServices-Database",
"UpdateServices-RSAT",
"UpdateServices-Services",
"UpdateServices-UI"

$ScriptRoot = (Get-Location).Path
$SQL_Memory_Query = "USE master
EXEC sp_configure 'show advanced options', 1
RECONFIGURE WITH OVERRIDE
GO
USE master
EXEC sp_configure 'max server memory (MB)', $SQLMemoryLimitMB
RECONFIGURE WITH OVERRIDE
GO"

$WSUS_IIS_SSL_Roots =  "APIRemoting30","ClientWebService","DSSAuthWebService","ServerSyncWebService","SimpleAuthWebService"

# END DEFINE VARIABLES -------------------------------------------
# DEFINE FUNCTIONS -----------------------------------------------

Function MECMWebServerCertificate_CSR{
    param(

    [Parameter(Mandatory = $true)]
    [String]$FQDN,

    [Parameter(Mandatory = $false)]
    [ValidateSet(1024,2048,4096)]
    [int]$KeyLength = 2048,

    [Parameter(Mandatory = $false)]
    [ValidateSet('True','False')]
    [string]$Exportable = 'False',

    [Parameter(Mandatory = $false)]
    [ValidateSet('Microsoft RSA SChannel Cryptographic Provider',`
    'Microsoft Enhanced DSS and Diffie-Hellman Cryptographic Provider')]
    [string]$EncryptionAlgorithm = 'Microsoft RSA SChannel Cryptographic Provider',

    [Parameter(Mandatory=$false)]
    [object]$Aliases,

    [Parameter(Mandatory=$true)]
    [string]$DestinationFilePath

    )

    #region checking_parameters

    #Check if the FQDN matches valid syntax
    if ($FQDN -notMatch '\w{1,}\.\w{1,}\.?[\w.]*') {
        Write-Warning -Message "The FQDN: $($FQDN) seems to be invalid.`n The expected syntax is host.domain.<optional>"
        exit
    }

    #Check if aliases match valid syntax
    if ($Aliases -notMatch '[\w\.\s,]{1,}') {
        Write-Warning -Message "Aliases: $($Aliases) don't seem to be valid. Use a comma ',' to separate multiple aliases."
        exit
    }

    #Check if the destination file path exists
    if (-not (Test-Path -Path $DestinationFilePath)) {
        Write-Warning -Message "Path: $($DestinationFilePath) does not exist. Please specify a valid path."
        exit
    }

    #Check if the specified file path has a training backslash; if not, add it.
    if ($DestinationFilePath.Substring($DestinationFilePath.Length -1,1) -eq '\') {
        $DestinationFilePath = $DestinationFilePath + $FQDN + '.csr'
    } else {
        $DestinationFilePath = $DestinationFilePath + '\' + $FQDN + '.csr'
    }

    #endregion checking_parameters

    #region program_main

    <#
        If a comma occurs in an aliases value, 'split' will convert the string
        to an array. Building a valid extensions section requires a loop.
        In case only one value is specified as an alias value, the script will embed it into the required information.
        [System.Environment]::NewLine ensures one alias per line.
    #>

    if ($Aliases -match ',') {
        $tmpAliases = $Aliases -split ','
        foreach($itmAlias in $tmpAliases) {
            $dnsAliases += '_continue_ = "DNS=' + $itmAlias + '&"' + [System.Environment]::NewLine
        }
    } else {
        $dnsAliases = '_continue_ = "DNS=' + $Aliases + '&"' + [System.Environment]::NewLine
    }

    $certificateINF = @"
[Version]
Signature= '`$Windows NT$'

[NewRequest]
Subject = "CN=${FQDN},O=Sandbox,OU=Sandbox,L=Madison,ST=WI,C=US"
KeySpec = 1
KeyLength = ${KeyLength}
Exportable = ${Exportable}
MachineKeySet = TRUE
ProviderName = ${EncryptionAlgorithm}
RequestType = PKCS10
KeyUsage = 0xa0

[RequestAttributes]
CertificateTemplate="MECMWebServerCertificate"

[EnhancedKeyUsageExtension]
OID=1.3.6.1.5.5.7.3.1

[Extensions]
2.5.29.17 = "{text}"
_continue_ = "DNS=${FQDN}&"
${dnsAliases}
"@

    <#
    [System.IO.Path]::GetTmpFileName() creates a temporary file to store the information of the
    certificateINF variable. The operating system will automatically drop it.
    #>
    $tmpFile        = [System.IO.Path]::GetTempFileName()
    $certificateINF | Out-File $tmpFile

    & certreq.exe -new $tmpFile $DestinationFilePath

    #endregion program_main
}

# END DEFINE FUNCTIONS -------------------------------------------
# SCRIPT BODY ----------------------------------------------------

# Set the ComputerName variable based on the group type
If($DomainController)
{
    $ComputerName = $DCName
}
ElseIf($ConfigMgrPrimaryServer -or $ConfigMgrAdditionalServer)
{
    $ComputerName = $CMName
}
ElseIf($ConfigMgrSUPServer)
{
    $ComputerName = $CMSUP_SUPName
}

# Process groups/phases based on input
If($Phase -eq "1_ServerPrep")
{
    # Check prerequisites for this phase

    # Make sure ComputerName is not null
    If($Null -eq $ComputerName)
    {
        $PrereqFailureReason += "Computer name was not provided"
    }

    # Make sure IPAddress is not null
    If($Null -eq $IPAddress)
    {
        $PrereqFailureReason += "IP address was not provided"
    }

    # If there is only one NIC, rename it to LAN
    $NICs += Get-NetAdapter
    If($NICs.Count -eq 1)
    {
        Write-Host "Renaming the NIC..." -ForegroundColor Green
        Rename-NetAdapter -Name $NICs[0].Name -NewName "LAN"
    }
    ElseIf($NICs.InterfaceAlias -notcontains "LAN")
    {
        $PrereqFailureReason += "Multiple NICs were detected and none of them are named 'LAN'"
    }

    # If all checks passed, set the variable accordingly
    If($PrereqFailureReason.Count -eq 0)
    {
        $PrereqCheckPassed = $True
    }
    Else
    {
        $PrereqCheckPassed = $False
    }

    # If prerequisite checks passed, continue
    If($PrereqCheckPassed -eq $True)
    {
        # Set the local Administrator password to never expire
        Write-Host "Setting the local Administrator account password to never expire..." -ForegroundColor Green
        Set-LocalUser -Name Administrator -PasswordNeverExpires $True

        # Disable Server Manager auto-launch
        Write-Host "Disabling Server Manager auto-launch..." -ForegroundColor Green
        Get-ScheduledTask -TaskName ServerManager | Disable-ScheduledTask

        # Disable IPv6 on all NICs
        Write-Host "Disabling IPv6..." -ForegroundColor Green
        ForEach($NIC in (Get-NetAdapter | Select-Object -Expand InterfaceAlias))
        {
            Disable-NetAdapterBinding -InterfaceAlias $NIC -ComponentID ms_tcpip6
        }

        # Set Static IP for the LAN interface
        Write-Host "Setting the static IP..." -ForegroundColor Green
        ipconfig /release
        New-NetIPAddress -InterfaceAlias "LAN" -IPAddress $IPAddress -PrefixLength 24 -DefaultGateway $DHCPRouter
        Set-DnsClientServerAddress -InterfaceAlias "LAN" -ServerAddresses $DHCPDNSServers

        # Disable the firewall by creating rules that allow all traffic
        New-NetFirewallRule -Name "_Sandbox - Global Allow - Inbound" -DisplayName "_Sandbox - Global Allow - Inbound" -Direction Inbound -Action Allow
        New-NetFirewallRule -Name "_Sandbox - Global Allow - Outbound" -DisplayName "_Sandbox - Global Allow - Outbound" -Direction Outbound -Action Allow

        # Set the computer name
        Write-Host "Renaming the computer..." -ForegroundColor Green
        Rename-Computer -NewName $ComputerName -Force

        # Restart the computer
        Write-Host "Rebooting..." -ForegroundColor Green
        Restart-Computer -Force
    }
    Else
    {
        Write-Host "Prerequisite check failed because:" -ForegroundColor Red
        Write-Host $PrereqFailureReason -ForegroundColor Red
    }
}
ElseIf($DomainController)
{
    # Check prerequisites for this grouping

    # Check for the ADCSTemplate PowerShell module folder
    If((Test-Path .\ADCSTemplate) -eq $False)
    {
        $PrereqFailureReason += "ADCSTemplate module not found"
    }

    # Check for extadsch.exe
    $SchemaEXEPath = (Get-ChildItem -Recurse | Where-Object{$_.Name -eq "extadsch.exe"} | Select-Object -Expand PSParentPath).Substring(38)
    If($Null -eq $SchemaEXEPath)
    {
        $PrereqFailureReason += "Extadsch.exe not found"
    }
    
    # If all checks passed, set the variable accordingly
    If($PrereqFailureReason.Count -eq 0)
    {
        $PrereqCheckPassed = $True
    }
    Else
    {
        $PrereqCheckPassed = $False
    }

    # If prerequisite checks passed, continue
    If($PrereqCheckPassed -eq $True)
    {
        If($Phase -eq "2_DomainControllerInstall")
        {
            Write-Host "Verifying the server does NOT have internet connectivity..." -ForegroundColor Green
            If((Test-NetConnection google.com).PingSucceeded -eq $False)
            {
                # Install Windows Server roles/features
                # Domain Services, DHCP, DNS
                Write-Host "Installing Windows Server roles/features..." -ForegroundColor Green
                Enable-WindowsOptionalFeature -Online -FeatureName $Roles_DomainController -All -NoRestart

                # Configure the DHCP server
                Write-Host "Configuring the DHCP server..." -ForegroundColor Green
                Add-DhcpServerV4Scope -Name "Sandbox Network" -StartRange $DHCPStartIP -EndRange $DHCPEndIP -SubnetMask $DHCPSubnetMask
                Set-DhcpServerV4OptionValue -DnsServer $DHCPDNSServers -Router $DHCPRouter -Force
                Set-DhcpServerV4Scope -ScopeId $DHCPRouter -LeaseDuration 1.00:00:00
                
                # Make sure the server is ready to become a domain controller
                Write-Host "Checking if the server is ready to become a Domain Controller..." -ForegroundColor Green
                $DC_Test_Result = Test-ADDSForestInstallation -DomainName $DomainFQDN -SafeModeAdministratorPassword $PasswordSecure

                # If the pre-req check passed, install the domain controller
                # This will cause a reboot
                If($DC_Test_Result.Status -eq "Success")
                {
                    Write-Host "Promoting the server to a Domain Controller, which will cause a reboot..." -ForegroundColor Green
                    Install-ADDSForest -DomainName $DomainFQDN -DomainNetbiosName $DomainNetbios -SafeModeAdministratorPassword $PasswordSecure -Force
                }
                Else
                {
                    Write-Host $DC_Test_Result.Message -ForegroundColor Red
                    Throw "Prerequisite test for Domain Controller role failed!"
                }
            }
            Else
            {
                Throw "Computer is connected to internet.  Sandbox domain controller should not have network access!"
            }
        }
        ElseIf($Phase -eq "3_DomainControllerConfig")
        {
            # Authorize the DHCP server
            Write-Host "Authorizing and restarting the DHCP server..." -ForegroundColor Green
            Add-DhcpServerInDC -DnsName ($ENV:ComputerName + "." + $DomainFQDN) -IPAddress (Get-NetIPAddress -InterfaceAlias LAN -AddressFamily IPv4 | Select -Expand IPAddress)
            Restart-Service DhcpServer

            # Install Windows Server roles/features
            # Certification Authority
            Write-Host "Installing the CA..." -ForegroundColor Green
            Enable-WindowsOptionalFeature -Online -FeatureName $Roles_CertificateAuthority -All -NoRestart
            Install-AdcsCertificationAuthority -CAType EnterpriseRootCA -CACommonName "$DomainCADisplayName" -Force

            # Import the Active Directory module
            Write-Host "Loading the Active Directory module..." -ForegroundColor Green
            Import-Module ActiveDirectory

            # Create the OU structure, groups, service account
            # Add the service account to the right groups
            Write-Host "Configuring Active Directory OUs, groups, and accounts..." -ForegroundColor Green
            New-ADOrganizationalUnit -Path "$DomainLDAP" -Name "_Sandbox" 
            New-ADOrganizationalUnit -Path "OU=_Sandbox,$DomainLDAP" -Name "Computers"
            New-ADOrganizationalUnit -Path "OU=_Sandbox,$DomainLDAP" -Name "Groups"
            New-ADOrganizationalUnit -Path "OU=_Sandbox,$DomainLDAP" -Name "Servers"
            New-ADOrganizationalUnit -Path "OU=_Sandbox,$DomainLDAP" -Name "Users"
            New-ADGroup -Path "OU=Groups,OU=_Sandbox,$DomainLDAP" -GroupScope Global -Name $MECMAdminsGroupName
            New-ADGroup -Path "OU=Groups,OU=_Sandbox,$DomainLDAP" -GroupScope Global -Name $MECMServersGroupName
            New-ADGroup -Path "OU=Groups,OU=_Sandbox,$DomainLDAP" -GroupScope Global -Name $SQLAdminsGroupName
            New-ADUser -GivenName Service -Surname Account -DisplayName $DomainServiceAccountDisplayName -Description $DomainServiceAccountDisplayName -UserPrincipalName sndsvc -AccountPassword $PasswordSecure -ChangePasswordAtLogon $False -PasswordNeverExpires $True -Path "OU=Users,OU=_Sandbox,$DomainLDAP" -Name $DomainServiceAccountName -Enabled $True
            Add-ADGroupMember -Members $DomainServiceAccountName -Identity "Domain Admins"
            Add-ADGroupMember -Members $DomainServiceAccountName -Identity $MECMAdminsGroupName
            Add-ADGroupMember -Members $DomainServiceAccountName -Identity $SQLAdminsGroupName

            # Create and permission the container required by MECM
            Write-Host "Creating and permissioning the System Management container..." -ForegroundColor Green
            New-ADObject -Name "System Management" -Path "CN=System,$DomainLDAP" -Type Container
            $MECM_Admins_Group_SID = Get-ADGroup $MECMAdminsGroupName | Select -Expand SID
            $MECM_Servers_Group_SID = Get-ADGroup $MECMServersGroupName | Select -Expand SID
            Set-Location AD:\
            $ACL = Get-ACL -Path "CN=System Management,CN=System,$DomainLDAP"
            $ACL_Attributes1 = $MECM_Admins_Group_SID,[System.DirectoryServices.ActiveDirectoryRights]"GenericAll",[System.Security.AccessControl.AccessControlType]"Allow",[System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $ACL_Attributes2 = $MECM_Servers_Group_SID,[System.DirectoryServices.ActiveDirectoryRights]"GenericAll",[System.Security.AccessControl.AccessControlType]"Allow",[System.DirectoryServices.ActiveDirectorySecurityInheritance]"All"
            $ACL_Rule1 = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $ACL_Attributes1
            $ACL_Rule2 = New-Object -TypeName System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $ACL_Attributes2
            $ACL.AddAccessRule($ACL_Rule1)
            $ACL.AddAccessRule($ACL_Rule2)
            Set-ACL -ACLObject $ACL -Path "AD:\CN=System Management,CN=System,$DomainLDAP" -Passthru
            Set-Location $ScriptRoot

            # Extend the AD schema for MECM
            Write-Host "Extending the AD schema for MECM..." -ForegroundColor Green
            Set-Location $SchemaEXEPath
            $SchemaResult = .\extadsch.exe
            If(-not ($SchemaResult -like "*Successfully extended the Active Directory schema*"))
            {
                Write-Host $SchemaResult
                Throw "Failed to extend the schema for MECM!"
            }
            Set-Location $ScriptRoot

            # Prepare for working with certificates
            Write-Host "Loading the ADCSTemplate module..." -ForegroundColor Green
            $ConfigContext = ([ADSI]"LDAP://RootDSE").ConfigurationNamingContext 
            Import-Module .\ADCSTemplate

            # Create and permission the MECM Client Certificate template
            Write-Host "Creating the MECM Client certificate template..." -ForegroundColor Green
            New-ADCSTemplate -DisplayName "MECM Client Certificate" -JSON (Export-ADCSTemplate -DisplayName "Workstation Authentication")
            Set-ADCSTemplateACL -DisplayName "MECM Client Certificate" -Type Allow -Identity "$DomainNetbios\Domain Computers" -Enroll -AutoEnroll

            # Create and permission the MECM Distribution Point Certificate template, then mark the private key exportable
            Write-Host "Creating the MECM Distribution Point certificate template..." -ForegroundColor Green
            New-ADCSTemplate -DisplayName "MECM Distribution Point Certificate" -JSON (Export-ADCSTemplate -DisplayName "Workstation Authentication")
            Set-ADCSTemplateACL -DisplayName "MECM Distribution Point Certificate" -Type Allow -Identity "$DomainNetbios\$MECMServersGroupName" -Enroll -AutoEnroll
            $DPTemplate = [ADSI]"LDAP://CN=MECMDistributionPointCertificate,CN=Certificate Templates,CN=Public Key Services,CN=Services,CN=Configuration,$DomainLDAP"
            $DPTemplate.Put("msPKI-Private-Key-Flag","101056528")
            $DPTemplate.SetInfo()
            
            # Create and permission the MECM Web Server Certificate template
            Write-Host "Creating the MECM Web Server certificate template..." -ForegroundColor Green
            New-ADCSTemplate -DisplayName "MECM Web Server Certificate" -JSON (Export-ADCSTemplate -DisplayName "Web Server")
            Set-ADCSTemplateACL -DisplayName "MECM Web Server Certificate" -Type Allow -Identity "$DomainNetbios\$MECMServersGroupName" -Enroll

            # Deploy the certificate templates
            Write-Host "Unloading the ADCSTemplate module..." -ForegroundColor Green
            Remove-Module ADCSTemplate
            Write-Host "Waiting for the new certificates to publish to Active Directory..." -ForegroundColor Green
            Write-Host "The Certificate Templates Console will open and close..." -ForegroundColor Green
            Write-Host "This could take some time..." -ForegroundColor Green
            certtmpl.msc # Launch the template manager to enforce a refresh of the templates
            Start-Sleep -Seconds 10 # Wait for the templates to refresh
            Get-Process | ?{$_.MainWindowTitle -eq "Certificate Templates Console"} | Stop-Process -Force # Close the template manager
            $Published = $False
            While($Published -eq $False)
            {
                Add-CATemplate -Name MECMClientCertificate -Force -ErrorAction SilentlyContinue
                If($? -eq $True)
                {
                    Write-Host "Successfully published the MECM Client Certificate template..." -ForegroundColor Green
                    $Published = $True
                }
                Else
                {
                    For($i=30; $i -gt 1; $i --){Write-Progress -Activity "Failed to publish the MECM Client Certificate template.  Trying again in 30 seconds..." -SecondsRemaining $i; Start-Sleep 1}
                }
            }
            $Published = $False
            While($Published -eq $False)
            {
                Add-CATemplate -Name MECMDistributionPointCertificate -Force -ErrorAction SilentlyContinue
                If($? -eq $True)
                {
                    Write-Host "Successfully published the MECM Distribution Point Certificate template..." -ForegroundColor Green
                    $Published = $True
                }
                Else
                {
                    For($i=30; $i -gt 1; $i --){Write-Progress -Activity "Failed to publish the MECM Distribution Point Certificate template.  Trying again in 30 seconds..." -SecondsRemaining $i; Start-Sleep 1}
                }
            }
            $Published = $False
            While($Published -eq $False)
            {
                Add-CATemplate -Name MECMWebServerCertificate -Force -ErrorAction SilentlyContinue
                If($? -eq $True)
                {
                    Write-Host "Successfully published the MECM Web Server Certificate template..." -ForegroundColor Green
                    $Published = $True
                }
                Else
                {
                    For($i=30; $i -gt 1; $i --){Write-Progress -Activity "Failed to publish the MECM Web Server Certificate template.  Trying again in 30 seconds..." -SecondsRemaining $i; Start-Sleep 1}
                }
            }

            # Create and deploy a GPO to enable certificate autoenrollment
            Write-Host "Creating and deploying the GPO for certificate auto-enrollment..." -ForegroundColor Green
            New-GPO -Name "comp-CertificateAutoEnrollment"
            Set-GPRegistryValue -Name "comp-CertificateAutoEnrollment" -Key "HKLM\SOFTWARE\Policies\Microsoft\Cryptography\AutoEnrollment" -ValueName AEPolicy -Type DWORD -Value 7
            New-GPLink -Name "comp-CertificateAutoEnrollment" -Target "OU=_Sandbox,$DomainLDAP"
            New-GPLink -Name "comp-CertificateAutoEnrollment" -Target "OU=Domain Controllers,$DomainLDAP"
        }
    }
    Else
    {
        Write-Host "Prerequisite check failed because:" -ForegroundColor Red
        Write-Host $PrereqFailureReason -ForegroundColor Red
    }
}
ElseIf($ConfigMgrPrimaryServer -or $ConfigMgrAdditionalServer)
{
    # Check prerequisites for this grouping
    
    # Check for the .NET 3.5 CAB files
    $NetFx3CABs = Get-ChildItem -Filter "*.cab"
    If($NetFx3CABs.Count -lt 2)
    {
        $PrereqFailureReason += ".NET 3.5 CAB files not found"
    }

    # Check for the Windows ADK files
    $ADK_Root = Get-ChildItem | Where-Object{$_.Name -like "ADK_*"} | Select-Object -Expand FullName
    If($Null -eq $ADK_Root)
    {
        $PrereqFailureReason += "Windows ADK files not found"
    }

    # Check for cmtrace.exe
    $CMTracePath = (Get-ChildItem -Recurse | Where-Object{$_.FullName -like "*\x64\cmtrace.exe"} | Select-Object -Expand PSParentPath).Substring(38)
    If($Null -eq $CMTracePath)
    {
        $PrereqFailureReason += "CMTrace.exe not found"
    }

    # Check for D drive having at least 10GB free
    $DriveDFreeSpace = (Get-PSDrive -Name D -PSProvider FileSystem | Select -Expand Free)/1024/1024/1024
    If($DriveDFreeSpace -lt 10)
    {
        $PrereqFailureReason += "Drive D does not have at least 10GB of free space"
    }
    
    # Check for the MECM setup exe
    $SetupPath = (Get-ChildItem -Recurse | Where-Object{$_.FullName -like "*\SMSSETUP\BIN\X64\setup.exe"} | Select-Object -Expand PSParentPath).Substring(38)
    If($Null -eq $SetupPath)
    {
        $PrereqFailureReason += "MECM setup files not found"
    }
    
    # Check for the SQL Server ISO
    $SQL_ISO = Get-ChildItem | Where-Object{$_.Name -like "*SQL*Server*.iso"} | Select-Object -Expand FullName
    If($Null -eq $SQL_ISO)
    {
        $PrereqFailureReason += "SQL Server ISO not found"
    }

    # If all checks passed, set the variable accordingly
    If($PrereqFailureReason.Count -eq 0)
    {
        $PrereqCheckPassed = $True
    }
    Else
    {
        $PrereqCheckPassed = $False
    }

    # If prerequisite checks passed, continue
    If($PrereqCheckPassed -eq $True)
    {
        If($Phase -eq "2_ConfigMgrPrep")
        {
            # Install Windows Server roles/features
            Write-Host "Enabling the required Windows Server roles/features..." -ForegroundColor Green
            Enable-WindowsOptionalFeature -Online -FeatureName $Roles_ConfigMgr -Source .\ -All -NoRestart

            # Join domain
            Write-Host "Joining the domain..." -ForegroundColor Green
            $Creds = New-Object System.Management.Automation.PSCredential("$DomainNetbios\Administrator",$PasswordSecure)
            Add-Computer -DomainCredential $Creds -DomainName sandbox.local -OUPath "OU=Servers,OU=_Sandbox,$DomainLDAP" -Force
            
            # Add the computer to the MECM Servers group
            Write-Host "Adding the computer to the $MECMServersGroupName group in Active directory..." -ForegroundColor Green
            Invoke-Command -ComputerName ($DCName + "." + $DomainFQDN) -Credential $Creds -ScriptBlock{Import-Module ActiveDirectory; $MachineToAdd = Get-ADComputer -Identity $Using:CMName; Add-ADGroupMember -Identity $Using:MECMServersGroupName -Members $MachineToAdd}

            # Restart computer
            Write-Host "Rebooting..." -ForegroundColor Green
            Restart-Computer -Force
        }
        ElseIf($Phase -eq "3_ConfigMgrPreReqs")
        {
            # Create the folder structure and share for the MECM source data
            New-Item -ItemType Directory -Path "D:\" -Name "_Source"
            New-Item -ItemType Directory -Path "D:\_Source" -Name "Applications"
            New-Item -ItemType Directory -Path "D:\_Source" -Name "OSD"
            New-Item -ItemType Directory -Path "D:\_Source\OSD" -Name "Boot Images"
            New-Item -ItemType Directory -Path "D:\_Source\OSD" -Name "Drivers"
            New-Item -ItemType Directory -Path "D:\_Source\OSD" -Name "Language Packs"
            New-Item -ItemType Directory -Path "D:\_Source\OSD" -Name "OS Images"
            New-Item -ItemType Directory -Path "D:\_Source\OSD" -Name "OSD Scripts"
            New-Item -ItemType Directory -Path "D:\_Source" -Name "Packages"
            New-Item -ItemType Directory -Path "D:\_Source" -Name "SUP"
            New-SmbShare -Name "Source" -Path "D:\_Source" -FullAccess "$DomainNetbios\$MECMAdminsGroupName","$DomainNetbios\$MECMServersGroupName" -ReadAccess "Everyone"

            # Mount the SQL ISO
            Write-Host "Mounting the SQL ISO..." -ForegroundColor Green
            $MountResult = Mount-DiskImage $SQL_ISO -Passthru
            $SQL_Drive = ($MountResult | Get-Volume | Select-Object -Expand DriveLetter) + ":"

            # Install SQL
            Write-Host "Installing SQL..." -ForegroundColor Green
            & $SQL_Drive\setup.exe /Action=Install /Features=SQL /IAcceptSQLServerLicenseTerms /IndicateProgress /InstanceName=MSSQLSERVER /PID=B9GQY-GBG4J-282NY-QRG4X-KQBCR /QuietSimple /SQLSVCAccount="$DomainNetbios\$DomainServiceAccountName" /SQLSVCPassword="$PasswordPlainText" /SQLSysAdminAccounts="$DomainNetbios\$SQLAdminsGroupName" /UpdateEnabled=False

            # Unmount the SQL ISO
            Write-Host "Unmounting the SQL ISO..." -ForegroundColor Green
            Dismount-DiskImage -InputObject $MountResult

            # Install SSMS
            Write-Host "Installing SSMS..." -ForegroundColor Green
            .\SSMS-Setup-ENU.exe /install /passive /norestart | Out-String

            # Install WinADK and WinPE
            Write-Host "Installing the Windows ADK and Windows PE..." -ForegroundColor Green
            & $ADK_Root\Core\adksetup.exe /features OptionId.DeploymentTools OptionId.ImagingAndConfigurationDesigner OptionId.ICDConfigurationDesigner OptionId.UserStateMigrationTool /norestart /quiet /ceip off | Out-String
            & $ADK_Root\WinPE\adkwinpesetup.exe /features OptionId.WindowsPreinstallationEnvironment /norestart /quiet /ceip off | Out-String

            # Restart computer
            Write-Host "Rebooting..." -ForegroundColor Green
            Restart-Computer -Force
        }
        ElseIf($Phase -eq "4_ConfigMgrInstall")
        {
            # Verify we're running as a domain account
            $LoggedInUser = whoami
            If($LoggedInUser -notlike "$DomainNetbios\*")
            {
                Throw "You must be logged in as a domain account with MECM/SQL admin access for this phase."
            }
            
            # Configure SQL memory limit
            Write-Host "Configuring the SQL memory limit..." -ForegroundColor Green
            $SQLCMD_ParentPath = (Get-ChildItem -Path "C:\Program Files\Microsoft SQL Server" -Recurse | Where-Object{$_.Name -eq "sqlcmd.exe"} | Select-Object -Expand PSParentPath).Substring(38)
            "exit" | & $SQLCMD_ParentPath\sqlcmd.exe -E -q "$SQL_Memory_Query"

            # Obtain an MECM Web Server Certificate
            Write-Host "Obtaining an MECM Web Server certificate..." -ForegroundColor Green
            MECMWebServerCertificate_CSR -FQDN "$($CMName).$($DomainFQDN)" -Aliases $CMName -DestinationFilePath .\ -KeyLength 2048 -Exportable $False -EncryptionAlgorithm 'Microsoft RSA SChannel Cryptographic Provider'
            $CSR_Path = "$ScriptRoot\" + "$($CMName).$($DomainFQDN)" + ".csr"
            $CER_Path = "$ScriptRoot\" + "$($CMName).$($DomainFQDN)" + ".cer"
            certreq.exe -config "$($DCName).$($DomainFQDN)\$($DomainCADisplayName)" -submit $CSR_Path $CER_Path
            Import-Certificate -FilePath $CER_Path -CertStoreLocation Cert:\LocalMachine\My
            $WebServerCertThumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CER_Path).Thumbprint

            # Configure IIS for HTTPS
            Write-Host "Configuring IIS for HTTPS..." -ForegroundColor Green
            $IIS_GUID = [GUID]::NewGuid().ToString("B")
            netsh http add sslcert HostNamePort=($ENV:ComputerName + "." + $DomainFQDN + ":443") CertHash=$WebServerCertThumbprint CertStoreName=My
            New-WebBinding -Name "Default Web Site" -IP "*" -Port 443 -Protocol https
            Set-Location IIS:\SslBindings
            Get-Item Cert:\LocalMachine\My\$WebServerCertThumbprint | New-Item 0.0.0.0!443
            Set-Location $ScriptRoot
            
            # Install MECM
            Write-Host "Installing MECM..." -ForegroundColor Green
            Write-Host "This could take a while..." -ForegroundColor Green
            New-Item -ItemType Directory -Path D:\ -Name MECM_Setup_Downloads
            & $CMTracePath\cmtrace.exe C:\ConfigMgrSetup.log
            & $SetupPath\setup.exe /NoUserInput /Script $ScriptRoot\MECM_Setup_Script.ini | Out-String
        }
    }
    Else
    {
        Write-Host "Prerequisite check failed because:" -ForegroundColor Red
        Write-Host $PrereqFailureReason -ForegroundColor Red
    }
}
ElseIf($ConfigMgrSUPServer)
{
    # Check prerequisites for this grouping

    # If all checks passed, set the variable accordingly
    If($PrereqFailureReason.Count -eq 0)
    {
        $PrereqCheckPassed = $True
    }
    Else
    {
        $PrereqCheckPassed = $False
    }

    # If prerequisite checks passed, continue
    If($PrereqCheckPassed -eq $True)
    {
        If($Phase -eq "2_SUPPrep")
        {
            # Install Windows Server roles/features
            Write-Host "Enabling the required Windows Server roles/features..." -ForegroundColor Green
            Enable-WindowsOptionalFeature -Online -FeatureName $Roles_ConfigMgrSUP -Source .\ -All -NoRestart

            # Join domain and reboot
            Write-Host "Joining the domain..." -ForegroundColor Green
            $Creds = New-Object System.Management.Automation.PSCredential("$DomainNetbios\Administrator",$PasswordSecure)
            Add-Computer -DomainCredential $Creds -DomainName sandbox.local -OUPath "OU=Servers,OU=_Sandbox,$DomainLDAP" -Force
            
            # Add the computer to the MECM Servers group
            Write-Host "Adding the computer to the $MECMServersGroupName group in Active directory..." -ForegroundColor Green
            Invoke-Command -ComputerName ($DCName + "." + $DomainFQDN) -Credential $Creds -ScriptBlock{Import-Module ActiveDirectory; $MachineToAdd = Get-ADComputer -Identity $Using:CMSUP_SUPName; Add-ADGroupMember -Identity $Using:MECMServersGroupName -Members $MachineToAdd}
            
            # Restart computer
            Write-Host "Rebooting..." -ForegroundColor Green
            Restart-Computer -Force
        }
        ElseIf($Phase -eq "3_SUPInstall")
        {
            # Verify we're running as a domain account
            $LoggedInUser = whoami
            If($LoggedInUser -notlike "$DomainNetbios\*")
            {
                Throw "You must be logged in as a domain account with MECM/SQL admin access for this phase."
            }

            # Obtain an MECM Web Server Certificate
            Write-Host "Obtaining an MECM Web Server certificate..." -ForegroundColor Green
            MECMWebServerCertificate_CSR -FQDN "$($CMSUP_SUPName).$($DomainFQDN)" -Aliases $CMSUP_SUPName -DestinationFilePath .\ -KeyLength 2048 -Exportable $False -EncryptionAlgorithm 'Microsoft RSA SChannel Cryptographic Provider'
            $CSR_Path = "$ScriptRoot\" + "$($CMSUP_SUPName).$($DomainFQDN)" + ".csr"
            $CER_Path = "$ScriptRoot\" + "$($CMSUP_SUPName).$($DomainFQDN)" + ".cer"
            certreq.exe -config "$($DCName).$($DomainFQDN)\$($DomainCADisplayName)" -submit $CSR_Path $CER_Path
            Import-Certificate -FilePath $CER_Path -CertStoreLocation Cert:\LocalMachine\My
            $WebServerCertThumbprint = (New-Object System.Security.Cryptography.X509Certificates.X509Certificate2 $CER_Path).Thumbprint

            # WSUS initial configuration
            Write-Host "Performing WSUS initial configuration..." -ForegroundColor Green
            New-Item -ItemType Directory -Path C:\ -Name WSUS
            & "C:\Program Files\Update Services\Tools\wsusutil.exe" postinstall CONTENT_DIR="C:\WSUS" SQL_INSTANCE_NAME="$($CMSUP_CMName).$($DomainFQDN)"
            $WSUS = Get-WSUSServer
            $WSUSConfig = $WSUS.GetConfiguration()
            Set-WsusServerSynchronization -SyncFromMU
            $WSUSConfig.AllUpdateLanguagesEnabled = $False
            $WSUSConfig.SetEnabledUpdateLanguages("en")
            $WSUSConfig.Save()
            $WSUSSubscription = $WSUS.GetSubscription()

            # Perform the initial WSUS sync
            Write-Host "Starting initial WSUS sync..." -ForegroundColor Green
            $WSUSSubscription.StartSynchronizationForCategoryOnly()
            While($WSUSSubscription.GetSynchronizationStatus() -ne "NotProcessing")
            {
                Write-Host "Waiting for WSUS sync to finish. This could take a while. Checking again in 30 seconds..." -ForegroundColor Green
                Start-Sleep -Seconds 30
            }

            # Set the WSUS Products
            Get-WsusProduct | Where-Object{$_.Product.Title -in $WSUSProductsToSync} | Set-WsusProduct

            # Set the WSUS Classifications
            Get-WsusClassification | Where-Object{$_.Classification.Title -in $WSUSClassificationsToSync} | Set-WsusClassification

            # Configure WSUS for SSL
            # IIS tasks
            # Configure IIS for HTTPS
            Write-Host "Configuring IIS for HTTPS..." -ForegroundColor Green
            $IIS_GUID = [GUID]::NewGuid().ToString("B")
            netsh http add sslcert HostNamePort=($ENV:ComputerName + "." + $DomainFQDN + ":8531") CertHash=$WebServerCertThumbprint CertStoreName=My AppID=$IIS_GUID
            Import-Module WebAdministration
            Set-Location IIS:\SslBindings
            Get-Item Cert:\LocalMachine\My\$WebServerCertThumbprint | New-Item 0.0.0.0!8531
            Set-Location $ScriptRoot
            Set-WebConfiguration -PSPath "IIS:\Sites" -Filter "/system.applicationHost/applicationPools/add[@name='WsusPool']/recycling/periodicRestart/@privateMemory" -Value 0
            ForEach($IIS_Root in $WSUS_IIS_SSL_Roots)
            {
                Set-WebConfigurationProperty -PSPath "IIS:\Sites" -Filter 'system.webserver/security/access' -Location "WSUS Administration/$($IIS_Root)" -Name sslFlags -Value 8
            }
            & "C:\Program Files\Update Services\Tools\wsusutil.exe" configuressl ($ENV:ComputerName + "." + $DomainFQDN)
            iisreset
        }
    }
    Else
    {
        Write-Host "Prerequisite check failed because:" -ForegroundColor Red
        Write-Host $PrereqFailureReason -ForegroundColor Red
    }
}

# END SCRIPT BODY ------------------------------------------------
# STOP TRANSCRIPTING ---------------------------------------------
Stop-Transcript
# END SCRIPT -----------------------------------------------------
# SIGNATURE ------------------------------------------------------