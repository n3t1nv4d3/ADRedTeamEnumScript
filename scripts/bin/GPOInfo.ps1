﻿Write-Host
Write-Host '========================================' -ForegroundColor Cyan
Write-Host '     Group Policy Object Enumeration'            -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host
if(!(Test-Path $home\desktop\AD_Assessment\GPOEnum)){ New-Item -Path "$home\desktop\AD_Assessment" -ItemType Directory -Name 'GPOEnum'}
$OutputPath = "$home\desktop\AD_Assessment\GPOEnum"
Start-Sleep 2
# Import the module goodness
Import-Module GroupPolicy
Import-Module c:\temp\scripts\bin\PowerView.ps1
Start-Sleep 5

# Restricted Groups
Get-DomainGPOLocalGroup > $OutputPath\RestrictedGroups.txt

#Search for interesting ACEs (use without GUIDs for faster result)
Find-InterestingDomainAcl -ResolveGUIDs > $OutputPath\InterestingACEs.txt

#  Get AD OUs and their linked GPOs
Get-ADOrganizationalUnit -Filter * | select @{label='target';e={$_.distinguishedname}} | Get-GPInheritance | where {$_.gpolinks -ne 'null'} | select @{label='OU';e={$_.name}},path,GpoInheritanceBlocked -ExpandProperty GpoLinks | epcsv $OutputPath\GPO_OU_Links.csv


#  OUs with blocked inheritance
Write-Host "OUs with Blocked Inheritance" -ForegroundColor Cyan
Get-ADOrganizationalUnit -Filter * | Get-GPInheritance | Where {$_.GpoInheritanceBlocked } | epcsv $OutputPath\BlockedIheritance.csv


Get-GPOReport -Name 'Default Domain Policy' -ReportType Html -Path $OutputPath\DefaultDomainPolicy.html
Get-GPOReport -Name 'Default Domain Controllers' -ReportType Html -Path $OutputPath\DefaultDomaincontrollers.html


# Grab a list of all GPOs
Write-Host "List all GPOs" -ForegroundColor Cyan
$GPOs = Get-GPO -All | Select-Object ID, Path, DisplayName, GPOStatus, WMIFilter

# Create a hash table for fast GPO lookups later in the report.
# Hash table key is the policy path which will match the gPLink attribute later.
# Hash table value is the GPO object with properties for reporting.
$GPOsHash = @{}
ForEach ($GPO in $GPOs) {
    $GPOsHash.Add($GPO.Path,$GPO)
}

# Empty array to hold all possible GPO link SOMs
$gPLinks = @()

# GPOs linked to the root of the domain
#  !!! Get-ADDomain does not return the gPLink attribute
$gPLinks += `
 Get-ADObject -Identity (Get-ADDomain).distinguishedName -Properties name, distinguishedName, gPLink, gPOptions |
 Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={0}}

# GPOs linked to OUs
#  !!! Get-GPO does not return the gPLink attribute
# Calculate OU depth for graphical representation in final report
$gPLinks += `
 Get-ADOrganizationalUnit -Filter * -Properties name, distinguishedName, gPLink, gPOptions |
 Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={($_.distinguishedName -split 'OU=').count - 1}}

# GPOs linked to sites
Write-Host "GPO link report" -ForegroundColor Cyan
$gPLinks += `
 Get-ADObject -LDAPFilter '(objectClass=site)' -SearchBase "CN=Sites,$((Get-ADRootDSE).configurationNamingContext)" -SearchScope OneLevel -Properties name, distinguishedName, gPLink, gPOptions |
 Select-Object name, distinguishedName, gPLink, gPOptions, @{name='Depth';expression={0}}

# Empty report array
$report = @()

# Loop through all possible GPO link SOMs collected
ForEach ($SOM in $gPLinks) {
    # Filter out policy SOMs that have a policy linked
    If ($SOM.gPLink) {
        # If an OU has 'Block Inheritance' set (gPOptions=1) and no GPOs linked,
        # then the gPLink attribute is no longer null but a single space.
        # There will be no gPLinks to parse, but we need to list it with BlockInheritance.
        If ($SOM.gPLink.length -gt 1) {
            # Use @() for force an array in case only one object is returned (limitation in PS v2)
            # Example gPLink value:
            #   [LDAP://cn={7BE35F55-E3DF-4D1C-8C3A-38F81F451D86},cn=policies,cn=system,DC=wingtiptoys,DC=local;2][LDAP://cn={046584E4-F1CD-457E-8366-F48B7492FBA2},cn=policies,cn=system,DC=wingtiptoys,DC=local;0][LDAP://cn={12845926-AE1B-49C4-A33A-756FF72DCC6B},cn=policies,cn=system,DC=wingtiptoys,DC=local;1]
            # Split out the links enclosed in square brackets, then filter out
            # the null result between the closing and opening brackets ][
            $links = @($SOM.gPLink -split {$_ -eq '[' -or $_ -eq ']'} | Where-Object {$_})
            # Use a for loop with a counter so that we can calculate the precedence value
            For ( $i = $links.count - 1 ; $i -ge 0 ; $i-- ) {
                # Example gPLink individual value (note the end of the string):
                #   LDAP://cn={7BE35F55-E3DF-4D1C-8C3A-38F81F451D86},cn=policies,cn=system,DC=wingtiptoys,DC=local;2
                # Splitting on '/' and ';' gives us an array every time like this:
                #   0: LDAP:
                #   1: (null value between the two //)
                #   2: distinguishedName of policy
                #   3: numeric value representing gPLinkOptions (LinkEnabled and Enforced)
                $GPOData = $links[$i] -split {$_ -eq '/' -or $_ -eq ';'}
                # Add a new report row for each GPO link
                $report += New-Object -TypeName PSCustomObject -Property @{
                    Depth             = $SOM.Depth;
                    Name              = $SOM.Name;
                    DistinguishedName = $SOM.distinguishedName;
                    PolicyDN          = $GPOData[2];
                    Precedence        = $links.count - $i
                    GUID              = "{$($GPOsHash[$($GPOData[2])].ID)}";
                    DisplayName       = $GPOsHash[$GPOData[2]].DisplayName;
                    GPOStatus         = $GPOsHash[$GPOData[2]].GPOStatus;
                    WMIFilter         = $GPOsHash[$GPOData[2]].WMIFilter.Name;
                    Config            = $GPOData[3];
                    LinkEnabled       = [bool](!([int]$GPOData[3] -band 1));
                    Enforced          = [bool]([int]$GPOData[3] -band 2);
                    BlockInheritance  = [bool]($SOM.gPOptions -band 1)
                } # End Property hash table
            } # End For
        } Else {
            # BlockInheritance but no gPLink
            $report += New-Object -TypeName PSCustomObject -Property @{
                Depth             = $SOM.Depth;
                Name              = $SOM.Name;
                DistinguishedName = $SOM.distinguishedName;
                BlockInheritance  = [bool]($SOM.gPOptions -band 1)
            }
        } # End If
    } Else {
        # No gPLink at this SOM
        $report += New-Object -TypeName PSCustomObject -Property @{
            Depth             = $SOM.Depth;
            Name              = $SOM.Name;
            DistinguishedName = $SOM.distinguishedName;
            BlockInheritance  = [bool]($SOM.gPOptions -band 1)
        }
    } # End If
} # End ForEach

# Output the results to CSV file for viewing in Excel
$report |
 Select-Object @{name='SOM';expression={$_.name.PadLeft($_.name.length + ($_.depth * 5),'_')}}, `
  DistinguishedName, BlockInheritance, LinkEnabled, Enforced, Precedence, `
  DisplayName, GPOStatus, WMIFilter, GUID, PolicyDN |
 Export-CSV $OutputPath\gPLink_Report.csv -NoTypeInformation


 #  Find unlinked GPOs
 Write-Host "Find Unlinked GPOs" -ForegroundColor Cyan
 Import-Module grouppolicy 
function IsNotLinked($xmldata)
{ 
    If ($xmldata.GPO.LinksTo -eq $null) 
	{ 
        Return $true 
    } 
     
    Return $false 
} 
 
$unlinkedGPOs = @() 
 
Get-GPO -All | ForEach { $gpo = $_ ; $_ | Get-GPOReport -ReportType xml | ForEach { If(IsNotLinked([xml]$_)){$unlinkedGPOs += $gpo} }} 
 
If ($unlinkedGPOs.Count -eq 0) 
{ 
    "No Unlinked GPO's Found" | Out-File $OutputPath\UnlinkedGPO.txt
} 

Else
{ 
    $unlinkedGPOs | epcsv $OutputPath\UnlinkedGPO.csv
}



Write-Host "Export GPO html GPO Report for all Group Policy Objects" -ForegroundColor Cyan
if(!(Test-Path $home\desktop\AD_Assessment\GroupPolicy\GPOExport)){ New-Item -Path "$home\desktop\AD_Assessment\GroupPolicy" -ItemType Directory -Name 'GPOExport'}
Get-GPO -All | % {$name = $_.displayname; Get-GPOReport -Guid $_.id -ReportType Html -Path "$OutputPath\GPOExport\$name.html" -Verbose }



#  GPO CSV Report

if(!(Test-Path $home\desktop\AD_Assessment\GroupPolicy\XML)){ New-Item -Path "$home\desktop\AD_Assessment\GroupPolicy" -ItemType Directory -Name 'XML'}

$GPOs = Get-GPO -All

foreach ($GPO in $GPOs)
{
    $name = $gpo.DisplayName
    $id = $gpo.Id
    Get-GPOReport -Guid $id -ReportType xml -Path $OutputPath\XML\$name.xml
}

$gci = Get-ChildItem $OutputPath\xml

[System.Collections.ArrayList]$ArrayList = @()

foreach ($item in $gci)
{
    $obj = "" | select "Name","CreatedTime","ModifiedTime","ComputerEnabled","UserEnabled","Linked","LinksTo","Description"
    $name = $item.name
    [xml]$report = Get-Content "$OutputPath\xml\$name"
    $description = Get-GPO -Name $name.split(".xml")[0] 
    $report.GPO.LinksTo.SOMPath

    $obj.name = $report.GPO.Name
    $obj.CreatedTime = $report.GPO.CreatedTime
    $obj.ModifiedTIme = $report.GPO.ModifiedTime
    $obj.ComputerEnabled = $report.GPO.Computer.Enabled
    $obj.UserEnabled = $report.GPO.User.Enabled
    $report.GPO.LinksTo.SOMPath | foreach {$obj.LinksTo += "$_  *** "}

    if ($obj.LinksTo -eq $null)
    {
        $obj.Linked = "False"
    }
    else
    {
        $obj.Linked = "True"
    }

    $obj.Description = $description.description

    $ArrayList += $obj
    $obj = $null
}

 $ArrayList | Export-Csv $OutputPath\AllGPO.csv

