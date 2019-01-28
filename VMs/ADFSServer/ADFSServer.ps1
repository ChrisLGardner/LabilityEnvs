# Domain member ADFS server

# Stop the script if a fatal error occurs
$ErrorActionPreference = 'Stop'

Configuration ADFSServer {

    param (
        [ValidateNotNull()]
        [System.Management.Automation.PSCredential]$Credential,

        [string]$EnvPrefix,

        [bool]$IsAzure = $false,

        [Int]$RetryCount = 100,
        [Int]$RetryIntervalSec = 30
    )

    Import-DscResource -ModuleName @{ModuleName="xNetworking";ModuleVersion="3.2.0.0"}
    Import-DscResource -ModuleName @{ModuleName="xPSDesiredStateConfiguration";ModuleVersion="6.0.0.0"}
    Import-DscResource -ModuleName @{ModuleName="xActiveDirectory";ModuleVersion="2.16.0.0"}
    Import-DscResource -ModuleName @{ModuleName="xAdcsDeployment";ModuleVersion="1.1.0.0"}
	Import-DscResource -ModuleName @{ModuleName="xDnsServer";ModuleVersion="1.9.0.0"}
    Import-DscResource -ModuleName @{ModuleName="xComputerManagement";ModuleVersion="1.9.0.0"}
    Import-DscResource -ModuleName @{ModuleName="xCertificate";ModuleVersion="2.8.0.0"}
    Import-DscResource -ModuleName @{ModuleName="cADFS";ModuleVersion="1.2.0.0"}

    Write-Verbose "Processing Configuration ADFSServer"

    $DomainName = $EnvPrefix + ".local"
	$DomainNetBiosName = $EnvPrefix

    # Get the names of other node we need to reference
    Write-Verbose "Checking for other required environment services"
    $DcNodeName = $AllNodes.where({$_.Role -eq 'DomainController'}).NodeName
    Write-Verbose "Found DC: $DcNodeName"
	if (-not ($DcNodeName)) {
		throw "No Domain Controller configuration found"
	}

    Write-Verbose "Processing configuration: Node ADFSServer"
    node $AllNodes.where({$_.Role -eq 'ADFSServer'}).NodeName {
        Write-Verbose "Processing Node: $($Node.NodeName)"

		Write-Verbose "Generating Credential Objects"
		$DomainCredentials = New-Object System.Management.Automation.PSCredential ("$($DomainNetbiosName)\$($Credential.UserName)", $Credential.Password)
		$DomainCredentialsAtDomain = New-Object System.Management.Automation.PSCredential ("$($Credential.UserName)@$($DomainName)", $Credential.Password)
		#$LocalAdminCredential = New-Object System.Management.Automation.PSCredential ("$($node.NodeName)\administrator", $Credential.Password)
		$ServiceCredential = New-Object System.Management.Automation.PSCredential ("$($DomainNetBiosName)\svc_adfs", $Credential.Password)

        if ($IsAzure -eq $true) {
            # Find the first network adapter
            $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
            $InterfaceAlias = $($Interface.Name)
        }

        LocalConfigurationManager {
            RebootNodeIfNeeded = $true
            AllowModuleOverwrite = $true
            ConfigurationMode = 'ApplyOnly'
            CertificateID = $Node.Thumbprint
            DebugMode = 'All'
        }

        # Ignore this is in Azure
        if ($IsAzure -eq $false) {
            # Set a fixed IP address if the config specifies one
            if ($Node.IPaddress) {
                xIPAddress PrimaryIPAddress {
                    IPAddress = $Node.IPAddress
                    InterfaceAlias = $Node.InterfaceAlias
                    PrefixLength = $Node.PrefixLength
                    AddressFamily = $Node.AddressFamily
                }
            }
        }

        # Ignore this is in Azure
        if ($IsAzure -eq $false) {
            # Set a default gateway if the config specifies one
            if ($Node.DefaultGateway) {
                xDefaultGatewayAddress DefaultGateway {
                    InterfaceAlias = $Node.InterfaceAlias
                    Address = $Node.DefaultGateway
                    AddressFamily = $Node.AddressFamily
                }
            }
        }

        # Ignore this is in Azure
        if ($IsAzure -eq $false) {
            # Set the DNS server if the config specifies one
            if ($Node.DnsAddress) {
                xDNSServerAddress DNSaddress {
                    Address = $Node.DnsAddress
                    InterfaceAlias = $Node.InterfaceAlias
                    AddressFamily = $Node.AddressFamily
                }
            }
        }

        # Install AD required features
        WindowsFeature ADPS {
            Ensure = 'Present'
            Name = 'RSAT-AD-PowerShell'
        }

        # Wait for AD domain to come online
        if ($IsAzure -eq $false) {
			WaitForAll ADdomain {
				DependsOn = '[WindowsFeature]ADPS'
				#ResourceName = '[xADDomain]FirstDC'
				ResourceName = '[Script]EnableWebServerEnroll'
				NodeName = $DcNodeName
				RetryIntervalSec = $RetryIntervalSec
				RetryCount = $RetryCount
			}
		}
		else {
			xWaitForADDomain CheckAD {
				DependsOn = '[WindowsFeature]ADPS'
			    DomainName = $DomainName
			    DomainUserCredential = $DomainCredentialsAtDomain
			    RetryCount = $RetryCount
			    RetryIntervalSec = $RetryIntervalSec
			}
		}

        # Join server to AD domain
        if ($IsAzure -eq $false) {
            xComputer DomainJoin {
				DependsOn = '[WaitForAll]ADdomain'
                Name = $Node.NodeName
                DomainName = $DomainName
                Credential = $DomainCredentialsAtDomain
            }

            xADComputer UpdateComputerDescription {
				DependsOn = '[xComputer]DomainJoin'
                ComputerName = $Node.NodeName
                Description = 'ADFS'
                Ensure = 'Present'
                DomainAdministratorCredential = $DomainCredentialsAtDomain
            }
        }
        else {
            xComputer DomainJoin {
				DependsOn = '[xWaitForADDomain]CheckAD'
                Name = $env:ComputerName
                DomainName = $DomainName
                Credential = $DomainCredentialsAtDomain
            }

            xADComputer UpdateComputerDescription {
                DependsOn = '[xComputer]DomainJoin'
                ComputerName = $env:ComputerName
                Description = 'ADFS'
                Ensure = 'Present'
                DomainAdministratorCredential = $DomainCredentialsAtDomain
            }
        }

        # Install ADFS feature
        WindowsFeature ADFS {
            Ensure = 'Present'
            Name = 'ADFS-Federation'
        }

        # Create top level OU for Service Accounts if not already available
        $ServiceAccountOUPath = "DC=" + $DomainName.split(".")[0] + ",DC=" + $DomainName.split(".")[1]
        xADOrganizationalUnit ServiceAccountOU {
            DependsOn = '[xComputer]DomainJoin'
            Ensure = 'Present'
            Name = 'ServiceAccounts'
            Path = $ServiceAccountOUPath
            Credential = $DomainCredentialsAtDomain
        }

        # Create OU for ADFS Service Accounts
        $AdfsAccountOUPath = "OU=ServiceAccounts,$ServiceAccountOUPath"
        xADOrganizationalUnit AdfsAccountOU {
            DependsOn = '[xADOrganizationalUnit]ServiceAccountOU'
            Ensure = 'Present'
            Name = 'ADFS'
            Path = $AdfsAccountOUPath
            Credential = $DomainCredentialsAtDomain
        }

        # Create ADFS Service Account
        $UserPath = "OU=ADFS,$AdfsAccountOUPath"
        xADUser AdfsService {
            DependsOn = '[xADOrganizationalUnit]AdfsAccountOU'
            Ensure = 'Present'
            DomainName = $DomainName
            Path = $UserPath
            UserName = "svc_adfs"
            Password = $Credential
            DomainAdministratorCredential = $DomainCredentialsAtDomain
            DisplayName = 'ADFS Service'
            GivenName = 'ADFS'
            Surname = 'Service'
            Description = 'ADFS Service Account'
            PasswordNeverExpires = $true
        }

		if ($IsAzure -eq $false) {
			# Ensure Cert Stuff done on DC
			WaitForAll DCCertConfig {
				DependsOn = '[xADUser]AdfsService'
				ResourceName = '[Script]EnableWebServerEnroll'
				NodeName = $DcNodeName
				RetryIntervalSec = $RetryIntervalSec
				RetryCount = $RetryCount
				PsDscRunAsCredential = $DomainCredentialsAtDomain
			}
		}

        # Create ADFS Certificate
        $CARootName = $DomainName.split(".")[0] + "-dc-ca"
        $CAServerFQDN = $DcNodeName + "." + $DomainName
		if ($Node.AdfsServiceName) {
			$CertSubject = ($Node.AdfsServiceName).ToLower() + "." + $DomainName
		}
		else {
			$CertSubject = 'federation.' + $DomainName
		}

		if ($IsAzure -eq $false) {
			xCertreq ADFS {
				#PsDscRunAsCredential = $DomainCredentialsAtDomain
				DependsOn = '[WaitForAll]DCCertConfig'
				Subject = $CertSubject
				CAServerFQDN = $CAServerFQDN
				CARootName = $CARootName
				KeyLength = 1024
				KeyUsage = '0xa0'
				OID = '1.3.6.1.5.5.7.3.1'
				ProviderName = '"Microsoft RSA SChannel Cryptographic Provider"'
				CertificateTemplate = 'WebServer'
				AutoRenew = $true
				Exportable = $false
			}
		}
		else {
			xCertreq ADFS {
				#PsDscRunAsCredential = $DomainCredentialsAtDomain
				DependsOn = '[xADUser]AdfsService'
				Subject = $CertSubject
				CAServerFQDN = $CAServerFQDN
				CARootName = $CARootName
				KeyLength = 1024
				KeyUsage = '0xa0'
				OID = '1.3.6.1.5.5.7.3.1'
				ProviderName = '"Microsoft RSA SChannel Cryptographic Provider"'
				CertificateTemplate = 'WebServer'
				AutoRenew = $true
				Exportable = $false
			}
		}

        # Create ADFS Farm
        $AdfsDisplayName = $EnvPrefix + "Authentication"
        cADFSfarm AdfsConfigure {
			PsDscRunAsCredential = $DomainCredentialsAtDomain
            DependsOn = '[xCertReq]ADFS'
            Ensure = 'Present'
            ServiceCredential = $ServiceCredential
            InstallCredential = $DomainCredentials
            CertificateSubject = $CertSubject
            DisplayName = $AdfsDisplayName
            ServiceName = $CertSubject
        }

		if ($Node.CreateAdfsDns) {
			# Install DNS RSAT
			WindowsFeature DnsMgmt {
				Ensure = 'Present'
				Name = 'RSAT-DNS-Server'
			}

			# Create DNS Record for ADFS Proxied Service
			if ($IsAzure -eq $false) {
				xDnsRecord ADFSdns {
					DependsOn = '[xCertReq]ADFS'
					Ensure = 'Present'
					Type = 'ARecord'
					Zone = $DomainName
					Name = $Node.AdfsServiceName
					Target = $Node.IPAddress
					DnsServer = $CAServerFQDN
					PsDscRunAsCredential = $DomainCredentialsAtDomain
				}
			}
			else {
				$IPAddress = Get-NetIPAddress -InterfaceAlias $InterfaceAlias -AddressFamily IPv4
				xDnsRecord ADFSdns {
					DependsOn = '[xCertreq]ADFS'
					Ensure = 'Present'
					Type = 'ARecord'
					Zone = $DomainName
					Name = $Node.AdfsServiceName
					Target = $IPAddress
					DnsServer = $CAServerFQDN
					PsDscRunAsCredential = $DomainCredentialsAtDomain
				}
			}
		}
    }

# End configuration ADFSServer
}
