# note, that if we do not hardcode the IP, we will see multiple errors from the 
# DC Promo process (for DNS and for AD Services)
# 

# requires several calm macros:
# @@{Netbios_Domain_Name}@@  --this is needed to build the credential
# @@{Domain_Admin_Name}@@   --this is needed to build the credential
# @@{Domain_Admin_Pass}@@   --this is needed to build the credential
# @@{FQDN_DOMAIN_NAME}@@   --this is needed to pass to the DC promotion
# @@{IP_OF_KNOWN_DC}@@  --this is needed to resolve the domain name

# set the execution policy on the server (atleast temporarily)
Set-ExecutionPolicy -ExecutionPolicy Unrestricted

# install the needed roles\features
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools

# they should import automatically, but just in case
Import-Module ADDSDeployment

# build the credential
# -----------     $domainName = @@{NETBIOS_DOMAIN_NAME}@@ 
# -----------     $domainAdmin = @@{DOMAIN_ADMIN_NAME}@@ 
# -----------     $domainPass = ConvertTo-SecureString -AsPlainText @@{DOMAIN_ADMIN_PASS}@@  -Force
# -----------     $safeModePW = ConvertTo-SecureString -AsPlainText @@{DOMAIN_RESTORE_PW}@@  -Force
$safeModePW = Read-Host -Prompt "Enter the safe mode restore password:  " -AsSecureString
$domainName = Read-Host -Prompt "Enter the netbios (does not include '@') domain name:  "
$domainAdmin = Read-Host -Prompt "Enter the domain admin username:  "
$domainPass = Read-host -Prompt "Enter the password for the domain admin user:  " -AsSecureString

$DACredential = New-Object System.Management.Automation.PSCredential("$($domainName)\$($domainAdmin)",$domainPass)

# promote the server to a DC
# -----------     $FQDN = @@{FQDN_DOMAIN_NAME}@@ 

Install-ADDSDomainController -NoGlobalCatalog:$false -Credential $DACredential -CriticalReplicationOnly:$false -DomainName $domainName -InstallDns:$true -NoRebootOnCompletion:$false -Force:$true -SafeModeAdministratorPassword $safeModePW

