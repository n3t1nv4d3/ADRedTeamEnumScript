Write-Host "Checking if output directory exists" -ForegroundColor Cyan
if(!(Test-Path $home\desktop\AD_Assessment\DomainInfoTrusts)){ New-Item -Path "$home\desktop\AD_Assessment" -ItemType Directory -Name 'DomainInfoTrusts'}
$OutputPath = "$home\desktop\AD_Assessment\DomainInfoTrusts"

Write-Host '========================================' -ForegroundColor Cyan
Write-Host '    Domain Info and Trusts Enumeration'            -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan

#  Get Domain Creation Date
Write-Host "Domain Creation Date" -ForegroundColor Cyan
'Domain Creation Date' | Out-File $OutputPath\DomainInfo.txt
 Get-ADObject -SearchBase (Get-ADForest).PartitionsContainer `
 -LDAPFilter "(&(objectClass=crossRef)(systemFlags=3))" `
 -Property dnsRoot, NetBIOSName, whenCreated | Sort-Object whenCreated | Format-Table dnsRoot, NetBIOSName, whenCreated –AutoSize | Out-File $OutputPath\DomainInfo.txt -Append

 
#  Get RID Pool Count
Write-Host "Rid Pool Count" -ForegroundColor Cyan
 'RID Pool Count' | Out-File $OutputPath\DomainInfo.txt -Append
 $DC = (Get-ADDomainController -Filter *).name[0]
 Dcdiag.exe /TEST:RidManager /v /s:$dc | find /i "Available RID Pool for the Domain" | Out-File $OutputPath\DomainInfo.txt -Append


#  Sites and Stats
Write-Host "AD Sites and Stats" -ForegroundColor Cyan
Get-ADObject -LDAPFilter '(objectClass=site)' -SearchBase (Get-ADRootDSE).ConfigurationNamingContext -Properties WhenCreated, Description |
Select-Object *, `
    @{label='IsEmpty';expression={If ($(Get-ADObject -Filter {ObjectClass -eq "nTDSDSA"} -SearchBase $_.DistinguishedName)) {$false} else {$true}}}, `
    @{label='DCCount';expression={@($(Get-ADObject -Filter {ObjectClass -eq "nTDSDSA"} -SearchBase $_.DistinguishedName)).Count}}, `
    @{label='SubnetCount';expression={@($(Get-ADObject -Filter {ObjectClass -eq "subnet" -and siteObject -eq $_.DistinguishedName} -SearchBase (Get-ADRootDSE).ConfigurationNamingContext)).Count}}, `
    @{label='SiteLinkCount';expression={@($(Get-ADObject -Filter {ObjectClass -eq "sitelink" -and siteList -eq $_.DistinguishedName} -SearchBase (Get-ADRootDSE).ConfigurationNamingContext)).Count}} |
Sort-Object Name | select Name, SiteLinkCount, SubnetCount, DCCount, IsEmpty, WhenCreated, Description | export-csv $OutputPath\SitesAndStats.csv

#  AD Domain Trusts
Write-Host 'AD Domain Trusts' -ForegroundColor Cyan
$DomainDNS = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().Name
[array]$ADDomainTrusts = Get-ADObject -Filter {ObjectClass -eq "trustedDomain"} -Properties *
[int]$ADDomainTrustsCount = $ADDomainTrusts.Count

"Discovered $ADDomainTrustsCount Trust(s) in $DomainDNS `r" | Out-File $OutputPath\DomainInfo.txt -Append
if(($ADDomainTrusts).count -ne 0){$ADDomainTrusts | select Name,Created,flatName,instanceType,trustAttributesmsecurityIdentifier | epcsv $OutputPath\ADTrusts.csv}

# AD Site Links
Write-Host "AD Site Links" -ForegroundColor Cyan
'AD Site Links' | Out-File $OutputPath\DomainInfo.txt -Append
Get-ADObject -Filter 'objectClass -eq "siteLink"' -Searchbase (Get-ADRootDSE).ConfigurationNamingContext -Property Options, Cost, ReplInterval, SiteList, Schedule | Select-Object Name, @{Name="SiteCount";Expression={$_.SiteList.Count}}, Cost, ReplInterval, @{Name="Schedule";Expression={If($_.Schedule){If(($_.Schedule -Join " ").Contains("240")){"NonDefault"}Else{"24×7"}}Else{"24×7"}}}, Options | Format-Table * -AutoSize | Out-File $OutputPath\DomainInfo.txt -Append

Write-Host ""
$ADDomain = Get-ADDomain
$ADForest = Get-ADForest
$name = $ADDomain.name
$path = "$OutputPath\$Name DomainandForest.txt" 
$ADDomain | Out-File $path
$ADForest | Out-File $path -Append



#  Admin SDHolder
#Loop through each domain in the forest
Write-Host "AdminSD Holder ACL" -ForegroundColor Cyan
(Get-ADForest).Domains | ForEach-Object {
    #Get System Container path
    $Domain = Get-ADDomain -Identity $_
    #Connect a PS Drive
    $Drive = New-PSDrive -Name $Domain.Name -PSProvider ActiveDirectory -Root $Domain.SystemsContainer -Server $_
    #Export AdminSDHolder ACL
    if ($Drive) {
        $Acl = (Get-Acl "$($Drive.Name):CN=AdminSDHolder").Access
        if ($Acl) {
            $Acl | Export-Clixml -Path ".\$(($Domain.Name).ToUpper())_ADMINSDHOLDER_ACL_FULL.xml"
            $Acl | Select-Object -Property IdentityReference -Unique | Export-Csv -Path "$OutputPath\$(($Domain.Name).ToUpper())_ADMINSDHOLDER_ACL_GROUPS.csv"
        }
        #Remove PS Drive
        Remove-PSDrive -Name $Domain.Name
    }
}

#  Get all AD subnets
Write-Host "AD Subnets" -ForegroundColor Cyan
Get-ADReplicationSubnet -Filter * | select Location,Name | epcsv $OutputPath\ADSubnets.csv

#  Missing AD subnets
Write-Host "Seaching for missing AD subnets" -ForegroundColor Cyan
$SearchString = Get-Date -Uformat %m/%d
$input_path = "$OutputPath\Netlogon.txt"
Get-ADDomainController -Filter * | foreach {Write-Host $_ ; Get-Content \\$_\c$\Windows\debug\netlogon.log | select-string $SearchString} | Out-File $input_path
$regex = '([a-zA-Z]{2}[_][a-zA-Z]{6}[_][a-zA-Z]{4}[:])(.*)(\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b)'
Select-String -Path $input_path -Pattern $regex -AllMatches | % { $_.Matches } | % { $_.Value } | Group-Object | sort count -Descending | select count,name | epcsv $OutputPath\MissingADSubnets.csv

#  Get KRBTGT Info
Write-Host 'Get KRBTGT Account Info' -ForegroundColor Cyan
function Get-PSADForestKRBTGTInfo
{

Param
    (
            )

Write-Verbose "Get current Active Directory domain... "
$ADForestInfo = [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
$ADForestInfoRootDomain = $ADForestInfo.RootDomain
$ADForestInfoRootDomainDN = "DC=" + $ADForestInfoRootDomain -Replace("\.",',DC=')

$ADDomainInfoLGCDN = 'GC://' + $ADForestInfoRootDomainDN

Write-Verbose "Discovering service account SPNs in the AD Forest $ADForestInfoRootDomainDN "
$root = [ADSI]$ADDomainInfoLGCDN 
$ADSearcher = new-Object System.DirectoryServices.DirectorySearcher($root,"(serviceprincipalname=kadmin/changepw)") 
$ADSearcher.PageSize = 5000
$AllADKRBTGTAccountSPNs = $ADSearcher.FindAll() 

$AllADKRBTGTAccountSPNsCount = $AllADKRBTGTAccountSPNs.Count

Write-Output "Processing $AllADKRBTGTAccountSPNsCount service accounts (user accounts) with SPNs discovered in AD Forest $ADForestInfoRootDomainDN `r "

$AllKRBTGTAccountReport = $Null
ForEach ($AllADKRBTGTAccountSPNsItem in $AllADKRBTGTAccountSPNs)
    {
        $KRBTGTAccountsItemDomain = $Null
        [array]$AllADKRBTGTAccountSPNsItemDNArray = ($AllADKRBTGTAccountSPNsItem.Properties.distinguishedname) -Split(",DC=")
                [int]$DomainNameFECount = 0
                ForEach ($AllADKRBTGTAccountSPNsItemDNArrayItem in $AllADKRBTGTAccountSPNsItemDNArray)
                    {
                        IF ($DomainNameFECount -gt 0)
                        { [string]$KRBTGTAccountsItemDomain += $AllADKRBTGTAccountSPNsItemDNArrayItem + "." }
                        $DomainNameFECount++
                    }
        $KRBTGTAccountsItemDomain = $KRBTGTAccountsItemDomain.Substring(0,$KRBTGTAccountsItemDomain.Length-1)

        [string]$KRBTGTAccountsItemSAMAccountName = $AllADKRBTGTAccountSPNsItem.properties.samaccountname
        [string]$KRBTGTAccountsItemdescription = $AllADKRBTGTAccountSPNsItem.properties.description
        [string]$KRBTGTAccountsItempwdlastset = $AllADKRBTGTAccountSPNsItem.properties.pwdlastset
            [string]$KRBTGTAccountsItemPasswordLastSetDate = [datetime]::FromFileTimeUTC($KRBTGTAccountsItempwdlastset)
        [string]$KRBTGTAccountsItemlastlogon = $AllADKRBTGTAccountSPNsItem.properties.lastlogon
            [string]$KRBTGTAccountsItemLastLogonDate = [datetime]::FromFileTimeUTC($KRBTGTAccountsItemlastlogon)

        $KRBTGTAccountReport = New-Object -TypeName System.Object
        $KRBTGTAccountReport | Add-Member -MemberType NoteProperty -Name Domain -Value $KRBTGTAccountsItemDomain
        $KRBTGTAccountReport | Add-Member -MemberType NoteProperty -Name UserID -Value $KRBTGTAccountsItemSAMAccountName
        $KRBTGTAccountReport | Add-Member -MemberType NoteProperty -Name Description -Value $KRBTGTAccountsItemdescription
        $KRBTGTAccountReport | Add-Member -MemberType NoteProperty -Name PasswordLastSet -Value $KRBTGTAccountsItemPasswordLastSetDate
        $KRBTGTAccountReport | Add-Member -MemberType NoteProperty -Name LastLogon -Value $KRBTGTAccountsItemLastLogonDate

        [array]$AllKRBTGTAccountReport += $KRBTGTAccountReport

    }


# $AllKRBTGTAccountReport | sort PasswordLastSet

return $AllKRBTGTAccountReport
}
 Get-PSADForestKRBTGTInfo | Out-File $OutputPath\KRBTGTinfo.txt


 #  SYSVOL Replication Method
 Write-Host "SYSVOL Replication Method" -ForegroundColor Cyan
 icm -ComputerName (Get-ADDomain).PDCEmulator -ScriptBlock {dfsrmig /GetMigrationState} | Out-File $OutputPath\SYSVOLrepl.txt


