@{
    AllNodes = @(
        @{
            # DomainController
            NodeName = "DC"
            Role = 'DomainController'
            DSdrive = 'C:'

            #Prevent credential error messages
            CertificateFile = "LabClient.cer"
            Thumbprint = "5940D7352AB397BFB2F37856AA062BB471B43E5E"
            # PSDscAllowPlainTextPassword = $true
            PSDscAllowDomainUser = $true


            # Networking
            IPAddress = '192.168.254.2'
            DnsAddress = '127.0.0.1'
            DefaultGateway = '192.168.254.1'
            PrefixLength = 24
            AddressFamily = 'IPv4'
            InterfaceAlias = 'Ethernet'
            CreateNATMappings = 85,86,89

            # Lability extras
            Lability_Media = 'BM_Server_2012_R2_Standard_x64'
            Lability_ProcessorCount = 2
            Lability_StartupMemory = 2GB
            Lability_MinimumMemory = 1GB
            Lability_MaximumMemory = 3GB
            Lability_BootOrder = 0
            Lability_BootDelay = 0
        }
    )

    NonNodeData = @{
        OrganisationName = 'Lab'

        Lability = @{
            EnvironmentPrefix = 'Lab-'

            DSCResource = @(
                @{ Name = 'xNetworking'; RequiredVersion = '3.2.0.0';}
                @{ Name = 'xPSDesiredStateConfiguration'; RequiredVersion = '6.0.0.0';}
                @{ Name = 'xActiveDirectory'; RequiredVersion = '2.16.0.0';}
                @{ Name = 'xAdcsDeployment'; RequiredVersion = '1.1.0.0';}
                @{ Name = 'xComputerManagement'; RequiredVersion = '1.9.0.0';}
                @{ Name = 'xCertificate'; RequiredVersion = '2.8.0.0';}
                @{ Name = 'xDnsServer'; RequiredVersion = '1.9.0.0';}
                @{ Name = 'bmDnsManagementDsc'; RequiredVersion = '0.2.0.0'}
            )
        }

    }
}
