
function Get-Bits {
    [cmdletbinding()]
    Param()

    $props = "Name", "Status", "Started", "StartMode", "PathName", "State", "StartName"

    #need the full command name for Select-Object when used in JEA

    Get-CimInstance -ClassName win32_service -filter "name = 'bits'" | 
        Microsoft.PowerShell.Utility\Select-object -Property $props

}

Export-ModuleMember -Function 'Get-Bits'