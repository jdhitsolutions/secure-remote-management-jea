
Return "This is a walk-through demo -- not a script file!"

#region configurations

Get-PSSessionConfiguration

Get-PSSessionConfiguration microsoft.powershell | select *

#endregion

#region a simple delegated endpoint

#or build in the Win10 client 
enter-pssession -VMName srv2 -Credential $artd
help New-PSSessionConfigurationFile -online

$newEP = ".\Restricted.pssc"

$params = @{
    Path = $newEP 
    Author = "Art Deco" 
    CompanyName = "Company.pri"
    Description = "A restricted endpoint" 
    ExecutionPolicy = "restricted"
    LanguageMode ="NoLanguage"
    MountUserDrive = $True 
    RunAsVirtualAccount = $True 
    TranscriptDirectory = "c:\JEA-Transcripts"
    VisibleCmdlets = 'Get-Service','Get-Process','Exit-PSSession','Get-Command','Get-FormatData','Out-File','Out-Default','Select-Object','Measure-Object' 
    VisibleFunctions = 'Get-Volume'
}

<#
required visible cmdlets
'Exit-PSSession','Get-Command','Get-FormatData','Out-File','Out-Default','Select-Object','Measure-Object'
#>

New-PSSessionConfigurationFile @params

get-content $newEP

#need to create the transcript folder
 If (-Not (Test-Path c:\JEA-Transcripts)) {
        mkdir C:\JEA-Transcripts
    }

help Register-PSSessionConfiguration 

# give this group access
# get-adgroup IT | get-adgroupmember
# get-aduser maryl -Properties memberof

#replace the SID
$sddl= "O:NSG:BAD:P(A;;GA;;;BA)(A;;GA;;;IU)(A;;GA;;;RM)(A;;GXGR;;;S-1-5-21-3627301624-3303859061-3311252252-1146)S:P(AU;FA;GA;;;WD)(AU;SA;GXGW;;;WD)"
Register-PSSessionConfiguration -Path $newEP -Name Restricted -SecurityDescriptorSddl $sddl
#use -ShowSecurityDescripterUI for an ACL GUI

Get-PSSessionConfiguration restricted

Enter-pssession -ComputerName win10 -Credential company\maryl -ConfigurationName restricted

Get-Command -noun pssessionconfiguration


#endregion

#region my module

invoke-item .\BitsAdmin

#need a module
psedit .\bitsadmin\bitsadmin.psm1

#endregion

#region define the .psrc file

# https://docs.microsoft.com/en-us/powershell/jea/role-capabilities

#who can do what
help New-PSRoleCapabilityFile -Online
show-command New-PSRoleCapabilityFile

$params = @{
    Path        = ".\BitsAdmin\RoleCapabilities\BITSAdministration.psrc"
    Author      = "Jeff Hicks" 
    Description = "A sample JEA capability file for BITS administration" 
}

# New-PSRoleCapabilityFile @params

psedit $params.path

#region saved file
<#
@{

    # ID used to uniquely identify this document
    GUID                    = '2765e350-2627-46cc-8bf5-81493f357cef'

    # Author of this document
    Author                  = 'Jeff Hicks'

    # Description of the functionality provided by these settings
    Description             = 'A sample JEA capability file for BITS administration'

    # Company associated with this document
    CompanyName             = 'Company'

    # Copyright statement for this document
    Copyright               = '(c) 2018 Jeff Hicks. All rights reserved.'

    # Modules to import when applied to a session
    # ModulesToImport = 'MyCustomModule', @{ ModuleName = 'MyCustomModule'; ModuleVersion = '1.0.0.0'; GUID = '4d30d5f0-cb16-4898-812d-f20a6c596bdf' }
    ModulestoImport         = "BitsTransfer", "CimCmdlets", "Storage"

    # Aliases to make visible when applied to a session
    #VisibleAliases = 'Item1', 'Item2'
    VisibleAliases          = "gsv"

    # Cmdlets to make visible when applied to a session
    # VisibleCmdlets = 'Invoke-Cmdlet1', @{ Name = 'Invoke-Cmdlet2'; Parameters = @{ Name = 'Parameter1'; ValidateSet = 'Item1', 'Item2' }, @{ Name = 'Parameter2'; ValidatePattern = 'L*' } }
    VisibleCmdlets          = @{ Name = 'Get-Service'; Parameters = @{ Name = 'Name'; ValidateSet = 'BITS' }},
    @{ Name = 'Restart-Service'; Parameters = @{ Name = 'Name'; ValidateSet = 'BITS' }},
    "bitstransfer\*"

    # Functions to make visible when applied to a session
    # VisibleFunctions = 'Invoke-Function1',
    # @{ Name = 'Invoke-Function2'; Parameters = @{ Name = 'Parameter1'; ValidateSet = 'Item1', 'Item2' }, @{ Name = 'Parameter2'; ValidatePattern = 'L*' } }
    VisibleFunctions        = "Get-PSSender", "help", "Get-Bits",
    @{Name="Get-Volume";Parameters=@{Name='DriveLetter';ValidateSet= "C"}}

    # External commands (scripts and applications) to make visible when applied to a session
    # VisibleExternalCommands = 'Item1', 'Item2'
    VisibleExternalCommands = "c:\windows\system32\netstat.exe", 
    "c:\windows\system32\whoami.exe",
    "C:\WINDOWS\system32\bitsadmin.exe"

    # Providers to make visible when applied to a session
    #VisibleProviders = ''

    # Scripts to run when applied to a session
    # ScriptsToProcess = 'C:\ConfigData\InitScript1.ps1', 'C:\ConfigData\InitScript2.ps1'

    # Aliases to be defined when applied to a session
    # AliasDefinitions = @{ Name = 'Alias1'; Value = 'Invoke-Alias1'}, @{ Name = 'Alias2'; Value = 'Invoke-Alias2'}

    # Functions to define when applied to a session
    # FunctionDefinitions = @{ Name = 'MyFunction'; ScriptBlock = { param($MyInput) $MyInput } }
    FunctionDefinitions     = @{ Name = 'Get-PSSender'; ScriptBlock = { 
            param() 
            [pscustomobject]@{
                ConnectionString = $PSSenderInfo.ConnectionString
                ConnectedUser    = $PSSenderInfo.ConnectedUser
                RunAsUser        = $PSSenderInfo.RunAsUser
                PSVersion        = $PSSenderInfo.ApplicationArguments.PSVersionTable.PSVersion
            }

        } 
    }

    # Variables to define when applied to a session
    # VariableDefinitions = @{ Name = 'Variable1'; Value = { 'Dynamic' + 'InitialValue' } }, @{ Name = 'Variable2'; Value = 'StaticInitialValue' }

    # Environment variables to define when applied to a session
    # EnvironmentVariables = @{ Variable1 = 'Value1'; Variable2 = 'Value2' }

    # Type files (.ps1xml) to load when applied to a session
    # TypesToProcess = 'C:\ConfigData\MyTypes.ps1xml', 'C:\ConfigData\OtherTypes.ps1xml'

    # Format files (.ps1xml) to load when applied to a session
    # FormatsToProcess = 'C:\ConfigData\MyFormats.ps1xml', 'C:\ConfigData\OtherFormats.ps1xml'

    # Assemblies to load when applied to a session
    # AssembliesToLoad = 'System.Web', 'System.OtherAssembly, Version=4.0.0.0, Culture=neutral, PublicKeyToken=b03f5f7f11d50a3a'

}#>

#endregion


<#
insert into the psrc file
 ModulestoImport = "BitsTransfer","CimCmdlets"
 VisibleAliases = "gsv"
VisibleCmdlets = @{ Name = 'Get-Service'; Parameters = @{ Name = 'Name'; ValidateSet = 'BITS' }},
@{ Name = 'Restart-Service'; Parameters = @{ Name = 'Name'; ValidateSet = 'BITS' }},
"bitstransfer\*"
VisibleFunctions = "Get-PSSender","help","Get-Bits"
VisibleExternalCommands = "c:\windows\system32\netstat.exe","c:\windows\system32\whoami.exe"
FunctionDefinitions = @{ Name = 'Get-PSSender'; ScriptBlock = { 
param() 
[pscustomobject]@{
    ConnectionString = $PSSenderInfo.ConnectionString
    ConnectedUser = $PSSenderInfo.ConnectedUser
    RunAsUser = $PSSenderInfo.RunAsUser
    PSVersion = $PSSenderInfo.ApplicationArguments.PSVersionTable.PSVersion
}

} }


#>

<#
To use the role capability file in a session configuration, first place the 
file in a RoleCapabilities subfolder of a valid Windows PowerShell module folder. 
Then reference the file by name in the RoleDefinitions field in a PowerShell 
Session Configuration (.pssc) file.
#>

#endregion

#region define the .pssc file

help New-PSSessionConfigurationFile -Online

$params = @{
    Path                = ".\myBits.pssc"
    SessionType         = "RestrictedRemoteServer" 
    TranscriptDirectory = "c:\JEA-Transcripts" 
    RunAsVirtualAccount = $True 
    Description         = "Company BITS Admin endpoint"
    RoleDefinitions     = @{'Company\BitsAdmins' = @{ RoleCapabilities = 'BITSAdministration' }}
}

#I already have the file
# New-PSSessionConfigurationFile @params
psedit $params.path

#endregion

#region Set up the node

#domain admin credential
$cred = Get-Credential Company\artd
$dc = New-PSSession -VMName DOM1 -Credential $cred

<# 
AD Setup for the demo
Invoke-Command { Get-ADGroup Bitsadmins } -session $dc
Invoke-Command { New-ADGroup -Name BitsAdmins -GroupScope Global } -Session $dc

Invoke-command {
    $p = @{
    Name = "BillBits"
    SamAccountName = "billb" 
    UserPrincipalName = "billb@company.com" 
    AccountPassword = (ConvertTo-SecureString "P@ssw0rd" -AsPlainText -force)
    Enabled = $True
    passthru = $True
}

New-aduser @p 
} -session $dc

#add the user to the BitsAdmin domain global group
Invoke-Command {
  Add-ADGroupMember -Identity "BitsAdmins" -Members (Get-ADUser billb)
} -session $dc
#>

Invoke-Command { Get-ADGroupMember BitsAdmins } -Session $dc
Invoke-Command { Get-ADuser Billb -Properties MemberOf} -session $dc

$s = New-PSSession -VMName SRV1 -Credential $cred

#need to have the module
Invoke-command { Get-Module BitsTransfer -list } -session $s

#and commands
Invoke-Command { Add-WindowsFeature Bits } -session $s

#copy my module
$copyparams = @{
    Path        = ".\BitsAdmin"
    Container   = $True
    Recurse     = $True 
    Destination = "$env:ProgramFiles\WindowsPowerShell\Modules"
    ToSession   = $s
    force       = $True
}

Copy-item @copyparams

Invoke-command { Get-module BitsAdmin -list } -session $s

#create Transcript folder
Invoke-Command {
    If (-Not (Test-Path c:\JEA-Transcripts)) {
        mkdir C:\JEA-Transcripts
    }
} -session $s

#copy the pssc 
Copy-item -Path .\myBits.pssc -Destination C:\ -ToSession $s -force

#get current configurations
Invoke-Command {Get-PSSessionConfiguration | Select Name} -session $s

#remove any existing versions from previous demos
Invoke-Command { Unregister-PSSessionConfiguration -Name BitsAdmin} -session $s

#setup the new one
Invoke-Command { Register-PSSessionConfiguration -Path C:\myBits.pssc -Name BitsAdmin} -session $s

#Get session config to verify
Invoke-Command {Get-PSSessionConfiguration bitsadmin | select *} -session $s

#endregion

#region Test

help Get-PSSessionCapability -online

Invoke-Command { 
Get-PSSessionCapability -ConfigurationName BitsAdmin -Username company\billb
} -session $s

#need an execution policy so modules will load
Invoke-command { set-executionpolicy remotesigned -force } -session $s

#let's be Bill
$bill = Get-Credential Company\billb

$test = New-pssession -VMName SRV1 -Credential $bill -ConfigurationName bitsadmin
Enter-pssession $Test

clear-host
get-command
whoami
get-service
#might need to create a proxy function for Get-service defaults

#but this works
get-service winrm
gsv bits
Restart-Service winrm
restart-service bits
get-pssender
get-pssender | format-list
netstat
get-volume
get-module 
get-help add-bitsfile
help add-bitsfile

#my custom function
get-bits
exit

remove-pssession $test

#endregion

#region Transcript

invoke-command { dir c:\jea-transcripts } -session $s

#get last transcript and copy to clipboard
invoke-command { dir c:\jea-transcripts | Sort LastWriteTime | 
Select -last 1 | get-content } -session $s | Set-Clipboard

#endregion

# demo clean up
invoke-command { dir c:\jea-transcripts | remove-item } -session $s
Get-pssession | remove-pssession