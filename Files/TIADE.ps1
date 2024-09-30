<#
File: TIADE.ps1
Author: MSFT for AD Module DLL
Automator: Yobroda (@itsyobroda)
#>


function Chck-Feasi{
	param (
        [string]$nm
    )
	$rlt1 = Test-NetConnection -ComputerName $nm -Port 9389
	$rlt2 = nslookup $nm
	
	if (($rlt1.TcpTestSucceeded) -or ($rlt2 -match "Name:")){
		return $true
	}
	else{
		return $false
	}
}

function Ini-Enu{
	param (
        [string]$dname
    )
	$fexec = Chck-Feasi($dname)
if ($fexec){
	try {
		"";"$([char]27)[4mDomain Details:$([char]27)[24m:";
		Get-ADDomain -Server $dname -ErrorAction SilentlyContinue|Select DomainSID,Forest,Name,NetBIOSName,DistinguishedName,DNSRoot,PDCEmulator,DomainMode,ChildDomains
		"";
		Start-Sleep -Seconds 4;
		"";"$([char]27)[4mPassword policy and kerberos policy$([char]27)[24m:";
		$Cdomain=(Get-ADDomain -Server $dname -ErrorAction SilentlyContinue).DNSRoot;cat "\\$Cdomain\sysvol\$CDomain\Policies\{31B2F340-016D-11D2-945F-00C04FB984F9}\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf"
		"";
		Get-ADDefaultDomainPasswordPolicy -Server $dname -ErrorAction SilentlyContinue;
		"";
		Start-Sleep -Seconds 7;
		"";"$([char]27)[4mTrusts$([char]27)[24m:";"";;
		"";$allnames = (Get-ADTrust -Filter * -Server $dname -ErrorAction SilentlyContinue);
		foreach($allname in $allnames){
			Write-Output ("");
			if($allname.Direction -eq "BiDirectional"){
				Write-Output ("$dname has BiDirectional Trust with $($allname.Name)");
				
			}elseif($allname.Direction -eq "Inbound"){
				Write-Output ("$dname has Inbound Trust from $($allname.Name)");
				Write-Output ("Access is from $dname to $($allname.Name)");
				
			}elseif($allname.Direction -eq "Outbound"){
				Write-Output ("$dname has OutBound Trust to $($allname.Name)");
				Write-Output ("Access is from $($allname.Name) to $dname");
			}
			
			$ifr = if ($allname.IntraForest){"Yes"}else {"No"};
			Write-Output ("Is $($allname.Name) IntraForest w.r.t $dname - $ifr");
			$sffa = if ($allname.SIDFilteringForestAware){"Yes"}else {"No"};
			Write-Output ("Is $($allname.Name) SIDFiltering Forest Aware w.r.t $dname - $sffa");
			$sfq = if ($allname.SIDFilteringQuarantined){"Yes"}else {"No"};
			Write-Output ("Does $($allname.Name) has SID Filtering Quarantined w.r.t $dname - $sfq");
			
			$pam = if (($allname.ForestTransitive -eq $True) -and ($allname.SIDFilteringQuarantined -eq $False)){"Yes"}else {"No"};
			Write-Output ("Does $($allname.Name) has Possible PAM Trust w.r.t $dname - $pam");
			
			if ($allname.TrustAttributes -gt 2048){
				Write-Output ("TGT Delegation is enabled between $($allname.Name) and $dname");
			}
			
			
		}
		
		"";"$([char]27)[4mUsers$([char]27)[24m:";
		Get-ADUser -Filter * -Properties * -Server $dname -ErrorAction SilentlyContinue|Select SamAccountName,Description,logonCount,sid,memberof,DistinguishedName | FL;
		"";
		
		Start-Sleep -Seconds 9;
		
		"";"$([char]27)[4mDisabled Users (If the o/p shows guest and krbrgt, it is expected)$([char]27)[24m:";
		Get-ADObject -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=2))" -Properties * -Server $dname -ErrorAction SilentlyContinue|Select SamAccountName,Description,logonCount,sid,memberof,DistinguishedName | FL;
		"";
		
		Start-Sleep -Seconds 3;
		
		"";"$([char]27)[4mUsers with password never expires enabled$([char]27)[24m:";
		Get-ADObject -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=65536))" -Properties * -Server $dname -ErrorAction SilentlyContinue|Select SamAccountName,Description,logonCount,sid,memberof,DistinguishedName | FL
		"";
		
		Start-Sleep -Seconds 6;
		
		"";"$([char]27)[4mAccounts that does not require kerberos preauthentication for asrep roasting$([char]27)[24m:";
		Get-ADObject -LDAPFilter "(&(objectCategory=person)(objectClass=user)(userAccountControl:1.2.840.113556.1.4.803:=4194304))" -Properties * -Server $dname -ErrorAction SilentlyContinue|Select SamAccountName,Description,logonCount,sid,memberof,DistinguishedName | FL
		"";
		
		Start-Sleep -Seconds 2;
		"";"$([char]27)[4mWindows Servers$([char]27)[24m:";
		Get-ADComputer -Filter 'OperatingSystem -like "*Windows Server*"' -Properties * -Server $dname -ErrorAction SilentlyContinue | select Name,OperatingSystem,DistinguishedName,IPv4Address,SID | FL;
		"";
		Start-Sleep -Seconds 1;
		if ($dname -eq ((Get-ADDomain).DNSRoot).ToString()){
			"";"$([char]27)[4mSystems whose local admin password current user can retrieve$([char]27)[24m:";
			Get-ADComputer -Filter {ms-mcs-admpwd -ne "$null"} -Properties * -Server $dname -ErrorAction SilentlyContinue | select  Name,ms-mcs-admpwd,DistinguishedName,ServicePrincipalName | FL;
			"";
		}
		Start-Sleep -Seconds 14;
		"";"$([char]27)[4mService Accounts$([char]27)[24m:";
		Get-ADUser -Filter {ServicePrincipalName -ne "$null"} -Properties *  -Server $dname -ErrorAction SilentlyContinue | select samaccountname,DistinguishedName,ServicePrincipalName | FL ;
		$svcnames = (Get-ADServiceAccount -Filter * -Server $dname -ErrorAction SilentlyContinue).Name; ForEach ($svcname in $svcnames){"";"Managed SVC Account: ";"";Get-ADServiceAccount -Identity $svcname -Properties * | select DistinguishedName,PrincipalsAllowedToRetrieveManagedPassword | FL};
		"";"$([char]27)[4mMSSQL Service Accounts$([char]27)[24m:";
		Get-ADObject -Filter { ServicePrincipalName -like "mssql*" } -Property ServicePrincipalName -Server $dname -ErrorAction SilentlyContinue
		"";
		Start-Sleep -Seconds 12;
		
		"";"$([char]27)[4mDAs, EAs and Groups having Admin keyword in there name:$([char]27)[24m:";
		Get-ADGroupMember -Identity "Domain Admins" -Recursive -Server $dname -ErrorAction SilentlyContinue
		Get-ADGroupMember -Server (Get-ADDomain -Identity (Get-ADForest).RootDomain).PDCEmulator -Identity "Enterprise Admins" -Recursive -ErrorAction SilentlyContinue
		Get-ADGroup -Filter 'Name -like "*admin*"' -Server $dname -ErrorAction SilentlyContinue | select Name 
		Get-ADGroup -Filter 'Name -like "*master*"'-Server $dname -ErrorAction SilentlyContinue | select Name 
		"";
		Start-Sleep -Seconds 10;
		function Get-ADPrincipalGroupMembershipRecursive ($SamAccountName) { 
		# Courtesy Altered Security
		$groups = @(Get-ADPrincipalGroupMembership -Identity $SamAccountName | select -ExpandProperty distinguishedname) 
		$groups 
			if ($groups.count -gt 0) 
			{ 
				foreach ($group in $groups) 
				{ 
					Get-ADPrincipalGroupMembershipRecursive $group
				}	 
			} 
		}
		if ($dname -eq ((Get-ADDomain).DNSRoot).ToString()){
		"";"$([char]27)[4mCurrent user group membership$([char]27)[24m:";
		$un = [Environment]::UserName; $grps = Get-ADPrincipalGroupMembership -Identity $un -ErrorAction SilentlyContinue| select Name,samaccountname
		Get-ADPrincipalGroupMembershipRecursive ([Environment]::UserName).ToString()
		"";
		}
		Start-Sleep -Seconds 3;
		"";"$([char]27)[4mControl over DAs$([char]27)[24m:";
		$dagroup = Get-ADGroup -Identity "Domain Admins" -Server $dname -ErrorAction SilentlyContinue
		$dadnPath = $dagroup.DistinguishedName
		$DAacl = Get-Acl -Path "AD:$dadnPath" -ErrorAction SilentlyContinue
		$DAacl.Access | Select ActiveDirectoryRights,AccessControlType,IdentityReference  |FL
		Start-Sleep -Seconds 12;
		"";
		"";"$([char]27)[4mDC-Sync Rights of DC$([char]27)[24m:";
		$do = Get-ADDomain -Server $dname -ErrorAction SilentlyContinue;
		$dodnPath = $do.DistinguishedName ;
		$Doacl = Get-Acl -Path "AD:$dodnPath" -ErrorAction SilentlyContinue;
		$Doacl.Access | ?{If($_.ObjectType -match '1131f6ad-9c07-11d1-f79f-00c04fc2dcd2' -or $_.ObjectType -match '1131f6aa-9c07-11d1-f79f-00c04fc2dcd2' -or $_.ObjectType -match '89e95b76-444d-4c62-991a-0facbeda640c') { $_ } };
		Start-Sleep -Seconds 7;
		"";
		"";"$([char]27)[4mUnconstrained Delegation$([char]27)[24m:";
		Get-ADComputer -Filter {TrustedForDelegation -eq $True} -Server $dname -ErrorAction SilentlyContinue
		Get-ADUser -Filter {TrustedForDelegation -eq $True} -Server $dname -ErrorAction SilentlyContinue
		"";
		Start-Sleep -Seconds 11;
		
		"";"$([char]27)[4mRBCD Principals allowed to delegate to$([char]27)[24m:";
		$ataobooi = Get-ADObject -LDAPFilter "(&(msDS-AllowedToActOnBehalfOfOtherIdentity=*)(!(UserAccountControl:1.2.840.113556.1.4.803:=2)))" -Properties * -Server $dname -ErrorAction SilentlyContinue
		$ataobooi | Select Name,ms-mcs-admpwd,DistinguishedName,ServicePrincipalName| FL;$ataobooi."msDS-AllowedToActOnBehalfOfOtherIdentity" |FL
		"";
		Start-Sleep -Seconds 15;
				
		"";"$([char]27)[4mConstrained Delegation$([char]27)[24m:";
		ActiveDirectory\Get-ADObject -Filter {msDS-AllowedToDelegateTo -ne "$null"} -Properties msDS-AllowedToDelegateTo -Server $dname -ErrorAction SilentlyContinue
		Start-Sleep -Seconds 5;
		
		"";"$([char]27)[4mUser/Computer accounts that are marked sensitive and cannot be delegated:$([char]27)[24m:";
		Get-ADObject -LDAPFilter "(userAccountControl:1.2.840.113556.1.4.803:=1048576)" -Properties * -Server $dname -ErrorAction SilentlyContinue|Select SamAccountName,Description,sid,memberof,DistinguishedName | FL
		Start-Sleep -Seconds 5;
		
		
		"";"$([char]27)[4mFSPs$([char]27)[24m:";
		$fsps = ActiveDirectory\Get-ADObject -Filter {objectClass -eq "foreignSecurityPrincipal"} -Server $dname -ErrorAction SilentlyContinue
		foreach($fsp in $fsps){if(($fsp.Name -match 'S-1-5-4')-or ($fsp.Name -match 'S-1-5-11') -or ($fsp.Name -match 'S-1-5-9') -or ($fsp.Name -match 'S-1-5-17') ){}else{$fsp}}
		"";
		Start-Sleep -Seconds 2;
		
		"";"$([char]27)[4mShadow Security Principals:$([char]27)[24m:";
		Get-ADObject -SearchBase ("CN=Shadow Principal Configuration,CN=Services," + (Get-ADRootDSE -Server $dname).configurationNamingContext) -Filter * -Properties * -Server $dname | select Name,member,msDS-ShadowPrincipalSid | fl
		Start-Sleep -Seconds 2;
		
		"";"$([char]27)[4mAD Connect User for Azure:$([char]27)[24m:";
		Get-ADUser -Filter "samAccountName -like 'MSOL_*'" -Server $dname -Properties * | select SamAccountName,Description | fl
		Start-Sleep -Seconds 5;
		
		
		
		if ($dname -eq ((Get-ADDomain).DNSRoot).ToString()){
		"";"$([char]27)[4mACL Takeover of the Current User$([char]27)[24m:";
		$un = [Environment]::UserName;$nbns=(Get-ADDomain -ErrorAction SilentlyContinue).NetBIOSName ;$dnnames=Get-ADPrincipalGroupMembershipRecursive ([Environment]::UserName).ToString();$grps=foreach($dnname in $dnnames) {$onlyname=(Get-ADGroup -Identity $dnname).Name;$finalgrpname=$nbns+"\"+$onlyname;$finalgrpname};$nogrps = $grps.Count; 1..$nogrps | ForEach-Object { Set-Variable -Name "grp$_" -Value $grps[$_]};$cusid=(Get-ADUser -Identity $un).SID; Write-Output "Users over whom control is possible are as follows:"; $adObjects = Get-ADObject -Filter * -Properties Name ; $oacl = @() ; foreach ($adObject in $adObjects) { $acl = Get-Acl -Path "AD:$($adObject.DistinguishedName)"; foreach ($access in $acl.Access) {$customObject = [PSCustomObject]@{ DistinguishedName= $adObject.DistinguishedName;Name = $adObject.Name; IdentityReference = $access.IdentityReference ; ActiveDirectoryRights = $access.ActiveDirectoryRights; AccessControlType   = $access.AccessControlType;IsInherited = $access.IsInherited;InheritanceFlags = $access.InheritanceFlags ; PropagationFlags = $access.PropagationFlags;ObjectType = $access.ObjectType;InheritedObjectType = $access.InheritedObjectType;};$oacl += $customObject}}; $oaclfil = $oacl | ?{ (($_.IdentityReference -match $cusid) -or ($_.IdentityReference -match $un) -or ($_.IdentityReference -contains $grp1) -or ($_.IdentityReference -contains $grp2) -or ($_.IdentityReference -contains $grp3) -or ($_.IdentityReference -contains $grp4) -or ($_.IdentityReference -contains $grp5) -or ($_.IdentityReference -match 'Everyone')) -and (($_.ActiveDirectoryRights -match 'ExtendedRight') -or ($_.ActiveDirectoryRights -match 'GenericAll') -or ($_.ActiveDirectoryRights -match 'GenericWrite') -or ($_.ActiveDirectoryRights -match 'WriteOwner') -or ($_.ActiveDirectoryRights -match 'WriteDACL') -or ($_.ActiveDirectoryRights -match 'ReadProperty') -or ($_.ActiveDirectoryRights -match 'WriteProperty') -or ($_.ActiveDirectoryRights -match 'Self') ) -and ($_.ObjectType -ne 'ab721a53-1e2f-11d0-9819-00aa0040529b') } | Select Name,DistinguishedName,ObjectType,ActiveDirectoryRights,IdentityReference; $oaclfil | FL;
		}
		Start-Sleep -Seconds 4;
		"";"$([char]27)[4mOUs and GPOs Information$([char]27)[24m:";
		$domainDN = (Get-ADDomain -Server $dname).DistinguishedName;$ldapFilter = "(objectClass=groupPolicyContainer)";$searchBase = "CN=Policies,CN=System,"+$domainDN;$gpos = Get-ADObject -LDAPFilter $ldapFilter -SearchBase $searchBase -Properties * -Server $dname; $domain = (Get-ADDomain -Server $dname -ErrorAction SilentlyContinue).DNSRoot;$ous = Get-ADOrganizationalUnit -Filter * -Properties * -Server $dname -ErrorAction SilentlyContinue|Select Name,DistinguishedName,gpLink; ForEach($ou in $ous){ "------------------------";"OuDetails:";$ou |FL ; $gpl = $ou.gpLink; $gplid=$gpl.ToString().Split("{")[-1].Split("}")[0]; "GPO details related to above OU:"; $dgpo= $gpos | Where-Object {$_.CN -match $gplid}; $dgpo; $dgpopth=$dgpo.gpcfilesyspath+"\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf";"Contents of GPO file from SYSVOL:";"";$optmp=cat $dgpopth;$optmp;if($optmp  | Select-String -Pattern '\[Group Membership\]'){"";"-++++++This GPO may have restricted groups+++++++-"}; "";"Where the OU is applied i.e. applicability on which members:"; ""; $sb=$ou.DistinguishedName; Get-ADComputer -Filter * -SearchBase $sb -Server $dname -ErrorAction SilentlyContinue | Select Name; "";"------------------------" }; "------------------------";"OuDetails: NA "; "";"GPO details related to Default Domain Policy:";"";$ddgpo=$gpos | Where-Object {$_.CN -match '{31B2F340-016D-11D2-945F-00C04FB984F9}'};$ddgpo;$ddgpopth=$ddgpo.gpcfilesyspath+"\MACHINE\Microsoft\Windows NT\SecEdit\GptTmpl.inf";"Contents of GPO file from SYSVOL:";"";cat $ddgpopth;"------------------------";
		Start-Sleep -Seconds 9;
		
		
	}
	catch{
	Write-Output "Enum failed for $dname";
	Write-Output "An error occurred: $_";
	return
	}
}else {
	Write-Output "As it is not feasible, Enum not ran for $dname over ADWS protocol"
	if ((Test-NetConnection -ComputerName $nm -Port 389).TcpTestSucceeded){
			Write-Output "$dname accessible over LDAP port. Try using dsquery or similar tool"
	}
}
}

function Bgn-Here {
	function DmnsList {
	$var0=Get-ADTrust -Filter * 
	$immdomnames = $var0.Name ;
	$uniquedms = [System.Collections.Generic.HashSet[string]]::new()
	foreach ($immdomname in $immdomnames) {
		$uniquedms.Add($immdomname) | Out-Null
	}
	$uniquedmscopy1=[System.Collections.Generic.HashSet[string]]::new($uniquedms)
	foreach ($dmn in $uniquedms) {
		$var1 = Get-ADTrust -Filter * -Server $dmn 
		$deepdomnames=$var1.Name;
		foreach ($deepdomname in $deepdomnames) {
		$uniquedmscopy1.Add($deepdomname) | Out-Null
		}
	}
	if (!($uniquedmscopy1.setEquals($uniquedms))){
		$uniquedms.UnionWith($uniquedmscopy1);
		$uniquedmscopy2=[System.Collections.Generic.HashSet[string]]::new($uniquedms)
		foreach ($dmn2 in $uniquedms) {
			$var2 = Get-ADTrust -Filter * -Server $dmn2 
			$2deepdomnames=$var2.Name;
			foreach ($2deepdomname in $2deepdomnames) {
				$uniquedmscopy2.Add($2deepdomname) | Out-Null
			}
		}
		if (!($uniquedmscopy2.setEquals($uniquedmscopy1))){
			$uniquedms.UnionWith($uniquedmscopy2)
			$uniquedmscopy3=[System.Collections.Generic.HashSet[string]]::new($uniquedms)
			foreach ($dmn3 in $uniquedms) {
				$var3=Get-ADTrust -Filter * -Server $dmn3 
				$3deepdomnames=$var3.Name;
				foreach ($3deepdomname in $3deepdomnames) {
					$uniquedmscopy3.Add($3deepdomname) | Out-Null
				}
			}
			if (!($uniquedmscopy3.setEquals($uniquedmscopy2))){
				$uniquedms.UnionWith($uniquedmscopy3)
				$uniquedmscopy4=[System.Collections.Generic.HashSet[string]]::new($uniquedms)
				foreach ($dmn4 in $uniquedms) {
					$var4=Get-ADTrust -Filter * -Server $dmn4 
					$4deepdomnames=$var4.Name;
					foreach ($4deepdomname in $4deepdomnames) {
						$uniquedmscopy4.Add($4deepdomname) | Out-Null
					}
				}
				if (!($uniquedmscopy4.setEquals($uniquedmscopy3))){
					$uniquedms.UnionWith($uniquedmscopy4)
					$uniquedmscopy5=[System.Collections.Generic.HashSet[string]]::new($uniquedms)
					foreach ($dmn5 in $uniquedms) {
					$var5=Get-ADTrust -Filter * -Server $dmn5 
					$5deepdomnames=$var5.Name;
						foreach ($5deepdomname in $5deepdomnames) {
							$uniquedmscopy5.Add($5deepdomname) | Out-Null
						}
					}
					$uniquedms.UnionWith($uniquedmscopy5)
					return $uniquedms
				}
				
				else {
					return $uniquedms
				}
			}
			else {
				return $uniquedms
			}
		}
		else{
			return $uniquedms
		}
				
	}
	else{
		return $uniquedms
	}
}

$dmnsarr=DmnsList;

$maindmns=[System.Collections.ArrayList]::new()
if((((Get-ADForest).Name).ToString()) -eq (((Get-ADDomain).DNSRoot).ToString())){
	$maindmns.Add(((Get-ADDomain).DNSRoot).ToString())
}else{
	$currentDomain = (Get-ADDomain).DNSRoot
	$domains = (Get-ADForest).Domains
	$maindmns.Add($currentDomain) | Out-Null
	foreach ($domain in $domains) {
		if ($domain -ne $currentDomain) {
			$maindmns.Add($domain) | Out-Null
		}
	}	
}
$dmnsarrlstbf = $maindmns.ToArray();
$dmnsarrlsttm =  $dmnsarr | Where-Object { $_ -notin $dmnsarrlstbf };
$dmnsarrlstfn = [System.Collections.ArrayList]::new();
$dmnsarrlstfn.AddRange($dmnsarrlstbf);
$dmnsarrlstfn.AddRange($dmnsarrlsttm);
Write-Output ("All domains found:")
Write-Output ("")
$dmnsarrlstfn;
$cter = 1;
foreach ($dmnarrlstfn in $dmnsarrlstfn){
	Write-Output "*********** $cter. For $dmnarrlstfn *****************************************"
    Ini-Enu ($dmnarrlstfn)
	$cter++
}

}

$adm=(Import-Module ActiveDirectory -PassThru -ErrorAction SilentlyContinue)
if ($adm -ne $null){
	Set-Location $PSScriptRoot
	Import-Module ActiveDirectory 
	$fop = Bgn-Here
	$fopfp = Join-Path -Path $PSScriptRoot -ChildPath "finalop.txt"
	$fop | Tee-Object -FilePath $fopfp
}
elseif ($adm -eq $null){
	Set-Location $PSScriptRoot
	Import-Module .\Microsoft.ActiveDirectory.Management.dll
	Import-Module .\ActiveDirectory.psd1
	$fop = Bgn-Here
	$fopfp = Join-Path -Path $PSScriptRoot -ChildPath "finalop.txt"
	$fop | Tee-Object -FilePath $fopfp
}
