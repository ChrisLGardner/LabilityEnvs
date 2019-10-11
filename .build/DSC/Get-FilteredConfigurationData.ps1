function Get-FilteredConfigurationData {
    param(
        [String]
        $Environment = 'DEV',

        [ScriptBlock]
        $Filter = {},

        $Datum = $(Get-variable Datum -ValueOnly -ErrorAction Stop)
    )

    $allNodes = @(Get-DatumNodesRecursive -Nodes $Datum.Environments.$Environment -Depth 20)
    
    if($Filter.ToString() -ne ([System.Management.Automation.ScriptBlock]::Create({})).ToString()) {
        $allNodes = [System.Collections.Hashtable[]]$allNodes.Where($Filter)
    }

    foreach ($node in $allnodes.Role) {
        foreach ($property in $datum.role.$node.AllNodes.Keys) {
            ($allNodes | where-object Role -eq $node).$property = $datum.role.$node.AllNodes.$property
        }
    }


    return @{
        AllNodes = $allNodes
        Datum = $Datum
    }
}
