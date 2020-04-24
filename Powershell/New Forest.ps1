# set the execution policy on the server (atleast temporarily)
Set-ExecutionPolicy -ExecutionPolicy Unrestricted

# Vars
$compname = "win2019dc1"

# set the time zone
c:\windows\system32\tzutil /s "Mountain Standard Time"

rename-computer -computername $env:computername -newname $compname

# we need to restart after installing due to the computer rename.
Install-WindowsFeature -Name AD-Domain-Services -IncludeManagementTools -Restart

# --------------copy\paste stop here-----------------------

# pass the vars again
$domname = "dustylane.local"
$dsrm = "RestoreModePW123456!@#"

#encrypt the password
$enc_dsrm=ConvertTo-SecureString -AsPlainText $dsrm -Force

# create the forest and domain
install-addsforest -domainname $domname -installdns -safemodeadministratorpassword $enc_dsrm -confirm:$false



