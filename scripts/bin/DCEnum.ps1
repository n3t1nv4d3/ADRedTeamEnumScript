Write-Host "Checking if output directory exists" -ForegroundColor Cyan
if(!(Test-Path $home\desktop\AD_Assessment\DCEnum)){ New-Item -Path "$home\desktop\AD_Assessment" -ItemType Directory -Name 'DCEnum'}
$OutputPath = "$home\desktop\AD_Assessment\DCEnum"

Write-Host '========================================' -ForegroundColor Cyan
Write-Host '     Domain Controller Enumeration'     -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan


$gdc = Get-ADDomainController -Filter * 

[System.Collections.ArrayList]$ArrayList = @()

foreach ($item in $gdc)
{
    $obj = "" | select 'name','IPv4Address','IsGlobalCatalog','IsReadOnly','OperatingSystem','OperationMasterRoles'

    $obj.name = $item.name
    $obj.IPv4Address = $item.IPv4Address
    $obj.IsGlobalCatalog = $item.IsGlobalCatalog
    $obj.IsReadOnly = $item.IsReadOnly
    $obj.OperatingSystem = $item.OperatingSystem
    $obj.OperationMasterRoles = [string]$item.OperationMasterRoles

    $ArrayList += $obj
    $obj = $null
}

$ArrayList | epcsv $OutputPath\DomainControllers.csv



#  Aging and scavenging

$DCs= (GET-ADDOMAIN).ReplicadirectoryServers

[System.Collections.ArrayList]$ArrayList = @()

#loop through list of DCs and dump lines with "scavenging" in them 
foreach ($dc in $DCs) 
{ 
    $obj = "" | select 'Name','ScavengingInterval'

    $output = dnscmd $DC /info 
    $string = $output |Select-string "Scavenging" 

    $obj.name = $DC
    $obj.ScavengingInterval = $string
    
    $ArrayList += $obj
    $obj = $null    
} 
$ArrayList | epcsv $OutputPath\AgingAndScavenging.csv


#  Test internet access

if(!(Test-Path $home\desktop\AD_Assessment\DomainControllers\InternetTest)){ New-Item -Path "$home\desktop\AD_Assessment\DCEnum" -ItemType Directory -Name 'InternetTest'}
$DCs = Get-ADDomainController -Filter *

foreach($Dc in $DCs)
{
    icm -ComputerName $Dc.name -ScriptBlock {Test-Connection -ComputerName google.com -Count 1} | Out-File $OutputPath\InternetTest\"$Dc.name".txt
}



#  UAC enabled?
$DomainControllers = Get-ADDomainController -Filter *
[System.Collections.ArrayList]$ArrayList = @()

$value = "EnableLUA"
foreach($DC in $DomainControllers)
{
    $computer = $DC.name

    $obj = "" | Select 'ComputerName','Key','Value','Data'

    #Query the computer
    $reg = [Microsoft.Win32.RegistryKey]::OpenRemoteBaseKey("LocalMachine",$computer)
    $key = $reg.OpenSubkey("Software\Microsoft\Windows\CurrentVersion\Policies\System")
    $v1 = $key.GetValue("$value")

    $obj.ComputerName = $computer
    $obj.Key = $key
    $obj.Value = ($value -split "{")[0]
    $obj.Data = $v1

    $ArrayList += $obj
    $obj = $null
 
 }       
$ArrayList | epcsv $OutputPath\DCs_UAC_Config.csv


#  DNS Client Settings
Write-Host "DC DNS Client Settings" -ForegroundColor Cyan

function DNSClientSetting
{
    $DCs= (GET-ADDOMAIN).ReplicadirectoryServers
    foreach($dc in $DCs)
    {
        Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPENABLED = 'True'" -ComputerName $dc | select DNSHostName,DNSServerSearchOrder
    }
}
DNSClientSetting | Out-File $OutputPath\DNSClientSettings.txt




#  DCDiag
Write-Host "DCDiag" -ForegroundColor Cyan
$server = (Get-ADDomain).PDCEmulator
dcdiag /s:$server /e /f:$OutputPath\DCDiag.txt



#  AD Replication
Write-Host "Getting Replication Report" -ForegroundColor Cyan
Get-ADReplicationPartnerMetadata -PartnerType Both -Scope Domain | Select-Object Server, Partner, PartnerType, Partition, ConsecutiveReplicationFailures, LastReplicationAttempt, LastReplicationResult, LastReplicationSuccess | epcsv $OutputPath\ReplicationHealth.csv


#  AD Replication Connections
Write-Host "AD Replication Connections" -ForegroundColor Cyan
function GetReplicationConnections
{
    ForEach($Site in (Get-ADObject -Filter 'objectClass -eq "site"' -Searchbase (Get-ADRootDSE).ConfigurationNamingContext)) 
    { 
        Foreach($Server in (Get-ADObject -Filter 'ObjectClass -eq "server"' -SearchBase "CN=Servers,$($Site.DistinguishedName)"))
        {
            Foreach($Connection in (Get-ADObject -SearchBase "$($server.DistinguishedName)" -Filter 'objectClass -eq "nTDSconnection"'))
            {
                Get-ADObject $Connection -Properties Options
            }
        }
    }
}
GetReplicationConnections | epcsv $OutputPath\ADreplicationConnections.csv



#  Time Source
Write-Host "Query PDC Time Source" -ForegroundColor Cyan
icm -ComputerName (Get-ADDomain).PDCEmulator -ScriptBlock {w32tm /query /source} | Out-File $OutputPath\PDCtimeSource.txt
