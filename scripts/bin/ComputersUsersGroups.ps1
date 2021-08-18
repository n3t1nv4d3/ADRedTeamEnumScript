Write-Host
Write-Host '========================================' -ForegroundColor Cyan
Write-Host ' Computers, Users, and Groups - Oh My!' -ForegroundColor Cyan
Write-Host '========================================' -ForegroundColor Cyan
Write-Host
if(!(Test-Path $home\desktop\AD_Assessment\ComputersUsersGroups)){ New-Item -Path "$home\desktop\AD_Assessment" -ItemType Directory -Name 'ComputersUsersGroups'}
$OutputPath = "$home\desktop\AD_Assessment\ComputersUsersGroups"

# Import the module goodness
Import-Module C:\temp\scripts\bin\PowerUpSQL-master\PowerupSQL.psd1
Import-Module C:\temp\scripts\bin\ADModule-master\Microsoft.ActiveDirectory.Management.dll
Import-Module C:\temp\scripts\bin\ADModule-master\ActiveDirectory\ActiveDirectory.psd1
Import-Module C:\temp\scripts\bin\PowerView.ps1

#  Service Accounts
. C:\temp\scripts\bin\Find-PSServiceAccounts.ps1
Find-PSServiceAccounts | Out-File "$OutputPath\PSServiceAccounts.csv"

# Get Systems with LAPS
Get-DomainOU | Get-DomainObjectAcl -ResolveGUIDs | Where-Object {($_.ObjectAceType -like 'ms-Mcs-AdmPwd') -and ($_.ActiveDirectoryRights -match 'ReadProperty')} | ForEach-Object {$_ | Add-Member NoteProperty 'IdentityName' $(Convert-SidToName $_.SecurityIdentifier);$_} > $OutputPath\LAPS_Systems.txt

# SQL Servers
Get-SQLInstanceDomain | Get-SQLServerInfo -Verbose > $OutputPath\SQL_System.txt

# AD Group Report
Write-Host "AD Group Report" -ForegroundColor Cyan
$GroupList = Get-ADGroup -Filter * -Properties Name, DistinguishedName, GroupCategory, GroupScope, whenCreated, WhenChanged, member, memberOf, sIDHistory, SamAccountName, Description, AdminCount | 
    Select-Object Name, DistinguishedName, GroupCategory, GroupScope, whenCreated, whenChanged, member, memberOf, AdminCount, SamAccountName, Description, `
    @{name='MemberCount';expression={$_.member.count}}, `
    @{name='MemberOfCount';expression={$_.memberOf.count}}, `
    @{name='SIDHistory';expression={$_.sIDHistory -join ','}}, `
    @{name='DaysSinceChange';expression={[math]::Round((New-TimeSpan $_.whenChanged).TotalDays,0)}} | Sort-Object Name            
            
$GroupList | Select-Object Name, GroupCategory, GroupScope, whenCreated, whenChanged, DaysSinceChange, MemberCount, MemberOfCount, AdminCount, Description, DistinguishedName | epcsv $OutputPath\ADGroups.csv


# AD User Report
Write-Host "AD User Report" -ForegroundColor Cyan
Get-ADUser -filter * –Properties Admincount,DisplayName,lastlogondate,passwordlastset,passwordneverexpires,"msDS-UserPasswordExpiryTimeComputed",AccountNotDelegated,Description |`
sort passwordlastset| Select-Object -Property `
                                Displayname, samaccountname,enabled,AccountNotDelegated,`
                                lastlogondate,`
                                @{Name="ExpiryDate";Expression={[datetime]::FromFileTime($_."msDS-UserPasswordExpiryTimeComputed")}},`
                                passwordlastset, `
                                @{l='PasswordAge';e={(New-TimeSpan $_.passwordlastset).Days}},passwordneverexpires,Admincount,Description | epcsv $OutputPath\ADUsers.csv


# Servers
Write-Host "Server Report" -ForegroundColor Cyan
Get-ADComputer -Filter 'OperatingSystem -like "*Server*"' -properties OperatingSystem,LastLogonDate | select name,enabled,operatingsystem,LastLogonDate,description | epcsv $OutputPath\Servers.csv

# User Hunting
# Find all machines on the current domain where the current user has local admin access (PowerView)
Find-LocalAdminAccess -Verbose > $OutputPath\localAdmin.txt

# Find computers where a domain admin (or specified user/group) has sessions:
Find-DomainUserLocation -Verbose > $OutputPath\DAsessions.txt

# Find computers where a domain admin session is available and current user has admin access (uses Test-AdminAccess).
Find-DomainUserLocation -CheckAccess > $OutputPath\DAsessionUserAdmin.txt

# Enumerate members of all privileged groups
Write-Host "Enumerating privileged group members" -ForegroundColor Cyan
$Groups = Get-ADGroup -Filter 'AdminCount -eq 1'

[System.Collections.ArrayList]$ArrayList = @()

foreach ($group in $Groups)
{
    
    if((Get-ADGroupMember -Identity $group.samaccountname).count -ne '0')
    {
    
        $Members = Get-ADGroupMember -Identity $group.samaccountname 
    
        foreach ($member in $Members)
        {
            
            $obj = "" | select 'GroupName','MemberName','Samaccountname','ObjectClass','LastLogonDate','Enabled','Description'

            if($member.objectClass -eq 'user')
            {
                $user = Get-ADUser -Identity $member.samaccountname -Properties LastLogonDate,Description

                $obj.groupname = $group.name
                $obj.membername = $user.name
                $obj.samaccountname = $member.samaccountname
                $obj.ObjectClass = $member.objectClass
                $obj.lastlogondate = $user.lastlogondate
                $obj.enabled = $user.enabled
                $obj.description = $user.description

                $ArrayList += $obj
                $obj = $null
            }

            else
            {
                $obj.GroupName = $group.Name
                $obj.memberName = $member.name
                $obj.samaccountname = $member.SamAccountName
                $obj.objectClass = $member.objectClass

                $ArrayList += $obj
                $obj = $null
            }
        }
    }
} 

$ArrayList | epcsv $OutputPath\PrivilegedGroupMembers.csv


# Domain Password Policy
Write-Host "Domain Password Policy" -ForegroundColor Cyan
(Get-DomainPolicyData).systemaccess > $OutputPath\PasswordPolicy.txt

# Domain Lockout Policy
#Write-Host "Domain Lockout Policy" -ForegroundColor Cyan
#$Domain = (Get-ADDomain).DNSRoot
#$RootDSE = Get-ADRootDSE -Server $Domain
#$AccountPolicy = Get-ADObject $RootDSE.defaultNamingContext -Properties lockoutDuration,lockoutObservationWindow,lockoutThreshold  
#$AccountPolicy | Select @{n="PolicyType";e={"Account Lockout"}},`
#                            DistinguishedName,`
#                            @{n="lockoutDuration";e={"$($_.lockoutDuration / -600000000) minutes"}},`
#                            @{n="lockoutObservationWindow";e={"$($_.lockoutObservationWindow / -600000000) minutes"}},`
#                            lockoutThreshold | Format-List | Out-File $OutputPath\LockoutPolicy.txt



# Domain Kerberos Policy
(Get-DomainPolicyData).KerberosPolicy > $OutputPath\KerberosPolicy.txt
Start-Sleep 2
# Discover Accounts with Kerboeros Delegation
Write-Host "Accounts with Kerberos Delegation" -ForegroundColor Cyan
Get-ADObject -filter { (UserAccountControl -BAND 0x0080000) -OR (UserAccountControl -BAND 0x1000000) -OR (msDS-AllowedToDelegateTo -like '*') } -prop Name,ObjectClass,PrimaryGroupID,UserAccountControl,ServicePrincipalName,msDS-AllowedToDelegateTo | epcsv $OutputPath\UsersKerbDeleg.csv


# Discover Computers with Kerberos Unconstrained Delegation  -- a little flaky at times, try manual 
Write-Host "Computers with Kerberos Unconstrained Delegation" -ForegroundColor Cyan
Write-Host "Enumerating Computers with Unconstrained Delegation" -ForegroundColor Cyan
Get-ADComputer -Filter 'TrustedForDelegation -eq $true -and PrimaryGroupId -eq 515' -Properties TrustedforDelegation,PrimarygroupId,TrustedToAuthForDelegation,ServicePrincipalName | epcsv $OutputPath\Computers_UnconstrainedDeleg.csv

# AD ACL Scan
Write-Host "AD ACL Scan" -ForegroundColor Cyan
$base = (Get-ADRootDSE).defaultNamingContext
C:\temp\scripts\bin\ADACLScan.ps1 -Base $base -Scope Subtree -Output CSV -OutputFolder $OutputPath -SDDate
