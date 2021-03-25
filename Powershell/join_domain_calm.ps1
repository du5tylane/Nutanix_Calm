# note, that if we do not hardcode the IP, we will see multiple errors from the 
# DC Promo process (for DNS and for AD Services)
# 
# ------we probably need to set the DNS server to an existing domain controller

# requires several calm macros:
# @@{Netbios_Domain_Name}@@  --this is needed to build the credential
# @@{Domain_Admin_Name}@@   --this is needed to build the credential
# @@{Domain_Admin_Pass}@@   --this is needed to build the credential
# @@{FQDN_DOMAIN_NAME}@@   --this is needed to pass to the DC promotion
# @@{IP_OF_KNOWN_DC}@@  --this is needed to resolve the domain name

# set the execution policy on the server (atleast temporarily)
Set-ExecutionPolicy -ExecutionPolicy Unrestricted

# 
# get the index number of the interface
$InterfaceIndex = (Get-NetIPInterface -AddressFamily ipv4 | where-object {$_.connectionstate -eq "Connected"} | where-object {$_.interfacealias -notlike "Loopback*"} | Select-Object -First 1).ifIndex

# establish a variable for the IP of the domain controller
#   ********* 
$DNSIP = @@{DNSServer_IP}@@ 

# set the DNS server so that we can resolve the domain name
Set-DnsClientServerAddress -InterfaceIndex $InterfaceIndex -ServerAddresses ($DNSIP)

# join computer to domain
$domainname = @@{Netbios_Domain_Name}@@
$domainAdmin = @@{Domain_Admin_Name}@@ 
$domainPass = @@{Domain_Admin_Pass}@@

$DACredential = New-Object System.Management.Automation.PSCredential("$($domainName)\$($domainAdmin)",$domainPass)

Add-Computer -DomainName $domainname -Credential $DACredential -Restart -Force -Verbose
