gci .build -rec -file | % { . $_.Fullname }

$Datum = New-DatumStructure -DefinitionFile .\datum.yml

$Filtered = Get-FilteredConfigurationData -Environment Generic-AdfsWap -Datum $Datum

$Filtered.AllNodes |
    Where-Object Name -ne * |
    ForEach-Object {
        $nodeRSOP = Get-DatumRsop -Datum $datum -AllNodes ([ordered]@{} + $_) -CompositionKey 'Role'
    }
