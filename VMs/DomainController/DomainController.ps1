# Domain Controller

# Stop the script if a fatal error occurs
$ErrorActionPreference = 'Stop'

Configuration DomainController {

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
    Import-DscResource -ModuleName @{ModuleName="xComputerManagement";ModuleVersion="1.9.0.0"}
	Import-DscResource -ModuleName @{ModuleName="xCertificate";ModuleVersion="2.8.0.0"}
    Import-DscResource -ModuleName @{ModuleName="xDnsServer";ModuleVersion="1.9.0.0"}
    Import-DscResource -ModuleName "bmDnsManagementDsc" -ModuleVersion 0.2.0.0

    Write-Verbose "Processing Configuration DomainController"

	    #Process our datafile if in Azure
		if ($IsAzure -eq $true) {
			for ($i=0;$i -lt $ConfigurationData.AllNodes.Count;$i++) {
				#Remove cert, thumbprint and set allow plaintext password
				$ConfigurationData.AllNodes[$i].Remove('CertificateFile')
				$ConfigurationData.AllNodes[$i].Remove('Thumbprint')
				$ConfigurationData.AllNodes[$i].PsDscAllowPlainTextPassword = $true
			
				#Update IP addresses for Azure
				if ($ConfigurationData.AllNodes[$i].AzureIPAddress) {
					$ConfigurationData.AllNodes[$i].IPAddress = $ConfigurationData.AllNodes[$i].AzureIPAddress
				}
			}
		}
    
    $DomainName = $EnvPrefix + ".local"
    $DomainNetBiosName = $EnvPrefix

    $IsMimInstall = $ConfigurationData.AllNodes.Where({$_.Role -eq 'MIMSyncServer' -or $_.Role -eq 'MIMPortalServer'})

    
    Write-Verbose "Processing configuration: Node DomainController"
    node $AllNodes.where({$_.Role -eq 'DomainController'}).NodeName {
        Write-Verbose "Processing Node: $($Node.NodeName)"

		Write-Verbose "Generating Credential Objects"
		$DomainCredentials = New-Object System.Management.Automation.PSCredential ("$($DomainNetbiosName)\$($Credential.UserName)", $Credential.Password)
		$DomainCredentialsAtDomain = New-Object System.Management.Automation.PSCredential ("$($Credential.UserName)@$($DomainName)", $Credential.Password)
		$LocalAdminCredential = New-Object System.Management.Automation.PSCredential ("$($node.NodeName)\administrator", $Credential.Password)

        if ($IsAzure -eq $true) {
            # Find the first network adapter
            $Interface = Get-NetAdapter | Where-Object Name -Like "Ethernet*" | Select-Object -First 1
            $InterfaceAlias = $($Interface.Name)
        }

        if ($IsAzure -eq $false) { 
            LocalConfigurationManager {
                RebootNodeIfNeeded = $true
                AllowModuleOverwrite = $true
                ConfigurationMode = 'ApplyOnly'
                CertificateID = $Node.Thumbprint
                DebugMode = 'All'
            }
        }
        else {
            LocalConfigurationManager {
                RebootNodeIfNeeded = $true
                AllowModuleOverwrite = $true
                ConfigurationMode = 'ApplyOnly'
                DebugMode = 'All'
            }
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

        # Set the DNS server if the config specifies one
        if ($IsAzure -eq $true) {
            if ($Node.DnsAddress) {
                xDNSServerAddress DNSaddress {
                    Address = $Node.DnsAddress
                    InterfaceAlias = $InterfaceAlias
                    AddressFamily = $Node.AddressFamily
                }
            }
        }
        else {
            if ($Node.DnsAddress) {
                xDNSServerAddress DNSaddress {
                    Address = $Node.DnsAddress
                    InterfaceAlias = $Node.InterfaceAlias
                    AddressFamily = $Node.AddressFamily
                }
            }
        }

        # Install AD required features
        WindowsFeature ADDS {
            Ensure = 'Present'
            Name = 'AD-Domain-Services'
        }

        # Install AD RSAT Tools
        WindowsFeature ADDSrsat {
            Ensure = 'Present'
            Name = 'RSAT-AD-Tools'
            IncludeAllSubFeature = $true
        }

        # Install CertServ Web Enroll required features
        WindowsFeature WebEnroll {
            Ensure = 'Present'
            Name = 'ADCS-Web-Enrollment'
        }

        # Create new AD domain
        xADDomain FirstDC {
            DependsOn = '[WindowsFeature]ADDS'
            DomainName = $DomainName
            DomainNetbiosName = $DomainNetBiosName
            SafemodeAdministratorPassword = $Credential
            DomainAdministratorCredential = $Credential
            DatabasePath = $Node.DSdrive + "\NTDS"
            LogPath = $Node.DSdrive + "\NTDS"
            SysVolPath = $Node.DSdrive + "\SysVol"
        }

		# Set Domain Admin Password to never expire
        xADUser DomainAdmin {
            DependsOn = '[xADDomain]FirstDC'
            Ensure = 'Present'
			DomainName = $DomainName
            UserName = "Administrator"
			UserPrincipalName = "Administrator@$DomainName"
            Password = $Credential
            DomainAdministratorCredential = $DomainCredentialsAtDomain
            PasswordNeverExpires = $true
        }

        # Install CertServ required features
        WindowsFeature ADCS {
            DependsOn = '[xADDomain]FirstDC'
            Ensure = 'Present'
            Name = 'ADCS-Cert-Authority'
        }

        WindowsFeature ADCSMgmt {
            DependsOn = '[xADDomain]FirstDC'
            Ensure = 'Present'
            Name = 'RSAT-ADCS-Mgmt'
        }

        # Create Cert Authority
        xAdcsCertificationAuthority CertAuth {
            DependsOn = '[WindowsFeature]ADCS'
            Ensure = 'Present'
            CAType = 'EnterpriseRootCA'
			HashAlgorithmName = 'SHA256'
			KeyLength = 2048
            Credential = $DomainCredentialsAtDomain
        }

		# Create Certificates Folder
		File Certificates {
			DependsOn = '[xAdcsCertificationAuthority]CertAuth'
			Ensure = 'Present'
			Type = 'Directory'
			DestinationPath = 'C:\Certificates'
		}

		# Export Domain Root Cert
		$CertFN = "CN=" + $EnvPrefix + "-" + $Node.NodeName + "-CA, DC=" + $EnvPrefix + ", DC=local"
		xCertificateExport DomainRoot {
			DependsOn = '[File]Certificates'
			Path = 'C:\Certificates\domainroot.cer'
			Subject = $CertFN
			Type = 'CERT'
		}

        # Enable Enroll on WebServer certificate template
        Script EnableWebServerEnroll {
            DependsOn = "[xAdcsCertificationAuthority]CertAuth"
            PsDscRunAsCredential = $DomainCredentialsAtDomain
            GetScript = {
                return @{ 'Result' = $true}
            }
            TestScript = {
                # Find the webserver template in AD and grant the Enroll extended right to the Domain Computers
                $Filter = "(cn=WebServer)"
                $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
                $ConfigContext = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

                $DirectorySearch = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$Filter)
                $Template = $DirectorySearch.Findone().GetDirectoryEntry()
                if ($Template -ne $null) {
                    $ObjUser = New-Object System.Security.Principal.NTAccount("Domain Computers")
                    # The following object specific ACE is to grant Enroll
                    $ObjectGuid = New-Object Guid 0e10c968-78fb-11d2-90d4-00c04f79dc55

                    ForEach ($AccessRule in $Template.ObjectSecurity.Access) {
                        If ($AccessRule.ObjectType.ToString() -eq $ObjectGuid) {
                            If ($AccessRule.IdentityReference -like "*$($ObjUser.Value)") {
                                Write-Verbose "TestScript: WebServer Template Enroll permission for Domain Computers exists. Returning True"
                                return $true
                            }
                        }
                    }
                }
                return $false
            }
            SetScript = {
                # Find the webserver template in AD and grant the Enroll extended right to the Domain Computers
                $Filter = "(cn=WebServer)"
                $ConfigContext = ([ADSI]"LDAP://RootDSE").configurationNamingContext
                $ConfigContext = "CN=Certificate Templates,CN=Public Key Services,CN=Services,$ConfigContext"

                $DirectorySearch = New-object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$ConfigContext",$Filter)
                $Template = $DirectorySearch.Findone().GetDirectoryEntry()

                if ($Template -ne $null) {
                    $ObjUser = New-Object System.Security.Principal.NTAccount("Domain Computers")
                    # The following object specific ACE is to grant Enroll
                    $ObjectGuid = New-Object Guid 0e10c968-78fb-11d2-90d4-00c04f79dc55
                    $ADRight = [System.DirectoryServices.ActiveDirectoryRights]"ExtendedRight"
                    $ACEType = [System.Security.AccessControl.AccessControlType]"Allow"
                    $ACE = New-Object System.DirectoryServices.ActiveDirectoryAccessRule -ArgumentList $ObjUser,$ADRight,$ACEType,$ObjectGuid
                    $Template.ObjectSecurity.AddAccessRule($ACE)
                    $Template.commitchanges()
                    Write-Verbose "SetScript: Completed WebServer additional permission"
                }
            }
        }

		if ($IsAzure -eq $false) {
			xDnsServerForwarder ForwardToGoogleDNS {
                IsSingleInstance = 'Yes'
                IPAddresses = '8.8.8.8','8.8.4.4'
                DependsOn = "[Script]EnableWebServerEnroll"
            }

			if ($Node.ConditionalForwarder)
			{
				DnsConditionalForwarder AddDnsConditionalForwarder {
                    Name = "blackmarble.co.uk"
                    MasterServers = "10.10.9.1", "10.10.9.2"
                    Ensure = 'Present'
                    DependsOn = "[Script]EnableWebServerEnroll"
					PsDscRunAsCredential = $DomainCredentialsAtDomain
				}
			}
		}

		# Configure Cert Services CRL distribution point
		$CrlShare = "file://crl/crldist$/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl"
		$CrlUrl = "http://crl.$DomainName/<CAName><CRLNameSuffix><DeltaCRLAllowed>.crl"
		Script ConfigureCrlDist {
            DependsOn = "[Script]EnableWebServerEnroll"
            PsDscRunAsCredential = $DomainCredentialsAtDomain
            GetScript = {
                return @{ 'Result' = $true}
            }
            TestScript = {
				# Check that both our CRL distribution points exist and that they have the correct settings
				$CheckCrlShare = $using:CrlShare
				$CheckCrlUrl = $using:CrlUrl

				$CrlShareExists = Get-CaCrlDistributionPoint | where {$_.uri -like $CheckCrlShare}
				$CrlUrlExists = Get-CaCrlDistributionPoint | where {$_.uri -like $CheckCrlUrl}

				if ($CrlShareExists) {
					if (($CrlShareExists.PublishToServer -eq $true) -and ($CrlShareExists.PublishDeltaToServer -eq $true)) {
						$CheckFlagCrlShare = $true
					}
				}
				else {
					$CheckFlagCrlShare = $false
				}

				if ($CrlUrlExists) {
					if (($CrlUrlExists.AddToCertificateCdp -eq $true) -and ($CrlUrlExists.AddToFreshestCrl -eq $true) -and ($CrlUrlExists.AddToCrlIdp -eq $true)) {
						$CheckFlagCrlUrl = $true
					}
				}
				else {
					$CheckFlagCrlUrl = $false
				}

				if (($CheckFlagCrlUrl -eq $true) -and ($CheckFlagCrlShare -eq $true)) {
					return $true
				}
				return $false

			}
			SetScript = {
				# Remove any existing Crl publishing rules with our Urls and create new ones
				$SetCrlShare = $using:CrlShare
				$SetCrlUrl = $using:CrlUrl

				$CrlShareExists = Get-CaCrlDistributionPoint | where {$_.uri -like $CheckCrlShare}
				$CrlUrlExists = Get-CaCrlDistributionPoint | where {$_.uri -like $CheckCrlUrl}

				Get-CaCrlDistributionPoint | Remove-CaCrlDistributionPoint -confirm:$false

				if ($CrlShareExists) {
					Remove-CaCrlDistributionPoint -uri $SetCrlShare -confirm:$false
				}

				Add-CACrlDistributionPoint -Uri $SetCrlShare -PublishToServer -PublishDeltaToServer

				if ($CrlUrlExists) {
					Remove-CaCrlDistributionPoint -uri $SetCrlUrl -confirm:$false
				}

				Add-CaCrlDistributionPoint -Uri $SetCrlUrl -AddToCertificateCdp -AddToFreshestCrl -AddToCrlIdp

				Restart-Service certsvc -confirm:$true
			}
		}

		# Remove GUI if required
		if ($Node.RemoveGUI) {
			WindowsFeature RemoveGUI {
				DependsOn = '[Script]AddDnsConditionalForwarder'
				Ensure = 'Absent'
				Name = 'Server-GUI-Shell'
			}
        }

        If ($IsMimInstall) {


            Script DownloadMIM {
                GetScript = { @{} }
                TestScript = {Test-Path -Path 'C:\Packages\en_microsoft_identity_manager_2016_with_service_pack_1_x64_dvd_9656597.iso'}
                SetScript = {
                    $FileSystemCredential = New-Object System.Management.Automation.PSCredential ("AZURE\user", (ConvertTo-SecureString "<accesskey>" -AsPlainText -Force))
                    New-PSDrive -Name Q -PSProvider Filesystem -Root \\storageaccount.file.core.windows.net\isofiles -Credential $FileSystemCredential
                    Copy-Item -path "Q:\en_microsoft_identity_manager_2016_with_service_pack_1_x64_dvd_9656597.iso" -Destination C:\Packages
                }
            }

            Script ExtractMimIso {
                DependsOn = '[Script]DownloadMIM'
                GetScript = {@{}}
                TestScript = { Test-Path -Path "C:\MIM\Software\Synchronization Service\setup.exe"}
                SetScript = {
                    $Iso = Get-ChildItem -Path C:\Packages -filter *Identity_Manager*.iso
                    Mount-DiskImage -ImagePath $Iso.fullname
                    $Drive = Get-PSDrive | where-object {$_.Provider -like '*FileSystem*' -and $_.free -eq 0}

                    copy-item -Path "$($Drive.Root)" -Destination "C:\MIM\Software\" -recurse -force
                }
            }
            $MimDependsOn += '[Script]ExtractMimIso'

            #START Install MIM Password Change Notification Service
                Script MimPcnsInstallSchema {
                    GetScript = { @{} }
                    TestScript = {
                        Test-Path -Path C:\MIM\Software\PCNS-log.txt
                    }
                    SetScript = {
                        Start-Process -Filepath msiexec.exe -Argumentlist '/i "C:\MIM\Software\Password Change Notification Service\x64\Password Change Notification Service.msi" /qn SCHEMAONLY=TRUE ACCEPT_EULA=1 /l*v C:\MIM\Software\PCNS-log.txt' -Wait
                    }
                    PsDscRunAsCredential = $DomainCredentials
                    DependsOn = '[Script]ExtractMimIso'
                }

                Package MimPcnsInstall {
                    Name = 'Microsoft Identity Manager Password Change Notification Service'
                    ProductId = '65801058-F13B-4066-BAA0-63FF944043AB'
                    Path = "C:\MIM\Software\Password Change Notification Service\x64\Password Change Notification Service.msi"
                    Arguments = "/qn ACCEPT_EULA=1"
                    PsDscRunAsCredential = $DomainCredentials
                    Ensure = 'Present'
                    DependsOn = '[Script]ExtractMimIso','[Script]MimPcnsInstallSchema'
                }
            #END Install MIM Password Change Notification Service
        }
    }

# End configuration DomainController
}
