gci .build -rec -file | % { . $_.Fullname }

$Datum = New-DatumStructure -DefinitionFile .\datum.yml

$Filtered = Get-FilteredConfigurationData -Environment Generic-AdfsWap -Datum $Datum

$example = $Filtered.AllNodes |
    Where-Object Name -ne * |
    ForEach-Object {
        $datum.Role.$($_.Role).AllNodes+$_
        #$nodeRSOP = Get-DatumRsop -Datum $datum -AllNodes ([ordered]@{} + $_) -CompositionKey AllNodes -Verbose
    }


    $Data = Import-PowerShellDataFile -Path .\Environments\Generic-ADFSWAP\Generic-ADFSWAP.psd1

    foreach ($Node in $data.AllNodes) {
        $NodeDataFile = gci ".\VMs\$($Node.Role)\*.psd1"

        $NodeData = Import-PowerShellDataFile -Path $NodeDataFile.FullName

        foreach ($Property in $NodeData.AllNodes.Keys.Where({$Node.Keys -notcontains $_})) {
            $Node.Add($Property,$NodeData.AllNodes[0][$Property])
        }

        $Data.Add('NonNodeData',$NodeData.NonNodeData)
    }


