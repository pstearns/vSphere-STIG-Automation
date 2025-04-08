<# 
#==========================================================================
# NAME: vSphere_VCSA_STIG.ps1, v6.0.0
# AUTHOR: Peter Stearns
# UPDATED: 02/18/2025
# PROFILE: VMware_vSphere_8.0_VCSA_STIG_V2R2 (Services)
# PROFILE: VMware_vSphere_8.0_vCenter_STIG_V2R2
# DESCRIPTION:
#    -This script runs the Inspec Profile against the VCSA Services and vCenter
#    -Then calls Ansible to fix open findings
#    -Outputs a STIG Viewer Checklist file for each service and vCenter
#==========================================================================

    Tested against
    -PowerCLI 12.6
    -Powershell 5/Core 7.2.6
    -vCenter/ESXi 8.0 U3

    Example command to run script
    ./vSphere_VCSA_STIG_.ps1 -vcenter vcentername.test.local -profiles eam,vCenter

    .PARAMETER vcenter
    Enter the FQDN or IP of the vCenter Server to connect to
    .PARAMETER hostname
    Enter the STIG Profiles to run against the vCenter Server 
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$vcenter,
    [Parameter()]
    [array]$profiles,
    [Parameter()]
    [object]$credObj,
    [Parameter()]
    [string]$RunBy,
    [Parameter()]
    [switch]$silent,
    [Parameter()]
    [switch]$skipFix
)

# Capture the start time
$startTime = Get-Date
Start-Transcript -path /opt/stigtools/vsphere8/transcript/vcsa.log -append -Force

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#/////////////////////DECLARE VARIABLES///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$STIG_ver = "VMware_vSphere_8.0_VCSA_STIG_V2R2"
$NAME = "vSphere_VCSA_STIG_.ps1, v6.0.0"
$UPDATED = "02/18/2025"
   
# VCSA Varibles
# ==================================================================

$classification = "U"
$MARKING        = "CUI"
$authprivlog    = "/var/log/audit/sshinfo.log"
$syslogServers  = @('udp://sylog:514',"192.168.10.10","192.168.10.12")
$ntpServers     = @("192.168.10.100","192.168.10.14","192.168.10.150","192.168.10.155")
$sslIssueOrg    = 'go daddy','verisign','generic'
$backup3rdParty = "false"
$embeddedIdp    = "true"

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////COMMENTS and MARKUPS//////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# VCSA-80-000095
# =============================================================================================
$VCSA095 = @{
    VULN_ID = "VCSA-80-000095"

    COMMENT = '
All users are assigned by groups. Groups are assigned roles to grant only permissions needed.
Verified all groups have appropriate permissions according to the following SSPs.

vCenter SSP Section x.x
'
    STATUS = "NotAFinding"
}

# VCSA-80-000150
# =============================================================================================
$VCSA150 = @{
    VULN_ID = "VCSA-80-000150"

    COMMENT = '
There are no AO-defined events, this is not a finding'

    STATUS = "NotAFinding"
}

# VCSA-80-000279
# =============================================================================================
$VCSA279 = @{
    VULN_ID = "VCSA-80-000279"

    COMMENT = '
All IP-Based storage NFS/iSCSI VMkernel port groups are in a dedicated VLANs that are logically separated from other traffic types'

    STATUS = "NotAFinding"
}

# VCSA-80-000285
# =============================================================================================
$VCSA285 = @{
    VULN_ID = "VCSA-80-000285"

    COMMENT = '
vCLSAdmin has Cryptographic privileges
NoTrustedAdmin has Cryptographic privileges
Admin has Cryptographic privileges
vSphereKubernetesManager has Cryptographic privileges

Verified Roles with cryptographic-related permissions according to the following SSPs.
vCenter SSP Section x.x.x
'
    STATUS = "NotAFinding"
}

# VCSA-80-000284
# =============================================================================================
$VCSA284 = @{
    VULN_ID = "VCSA-80-000284"

    COMMENT = '
Least privlege roles are created and assigned.
Verified all groups have appropriate permissions according to the following SSPs.
vCenter SSP Section x.x
'
    STATUS = "NotAFinding"
}

# VCSA-80-000196
# =============================================================================================
$VCSA196	 = @{
    VULN_ID = "VCSA-80-000196"

    COMMENT = '
vSAN is not enabled, this is not applicable.'
}


# VCSA-80-000281
# =============================================================================================
$VCSA281	 = @{
    VULN_ID = "VCSA-80-000281"

    COMMENT = '
vSAN is not enabled, this is not applicable.'
}

# VCSA-80-000282
# =============================================================================================
$VCSA282	 = @{
    VULN_ID = "VCSA-80-000282"

    COMMENT = '
vSAN is not enabled, this is not applicable.'
}

# VCSA-80-000286
# =============================================================================================
$VCSA286	 = @{
    VULN_ID = "VCSA-80-000286"

    COMMENT = '
vSAN is not enabled, this is not applicable.'
}


# VCSA-80-000287
# =============================================================================================
$VCSA287	 = @{
    VULN_ID = "VCSA-80-000287"

    COMMENT = '
vSAN is not in use, this is not applicable.'
}

# VCSA-80-000304
# =============================================================================================
$VCSA304	 = @{
    VULN_ID = "VCSA-80-000304"

    COMMENT = '
vSAN is not in use, this is not applicable.'
}

# VCSA-80-000080
# =============================================================================================
$VCSA080	 = @{
    VULN_ID = "VCSA-80-000080"

    COMMENT = '
A federated identity provider is configured and used for an identity source and supports Smartcard authentication, this is not applicable.
'
	STATUS = "Not_Applicable"
}

# VCSA-80-000283
# =============================================================================================
$VCSA283	 = @{
    VULN_ID = "VCSA-80-000283"

    COMMENT = '
A federated identity provider is configured and used for an identity source, this is not applicable.

'

    STATUS = "Not_Applicable"
}

# Distributed Switch Items
# =============================================================================================
$DVSUpdates = @{
     COMMENT = '
Distributed switches are not used, this is not applicable.
'
    STATUS = "Not_Applicable"
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////////Manual Items///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# VCSA-80-000024
# =============================================================================================
$VCSA024	 = @{
    VULN_ID = "VCSA-80-000024"
    FINDING_DETAILS = 'Manually verified Login Banner is formatted in accordance with DTM-08-06.'
    COMMENT = ' '
}

# VCSA-80-000057
# =============================================================================================
$VCSA057	 = @{
    VULN_ID = "VCSA-80-000057"
    FINDING_DETAILS = 'Manually verified no unauthorized plugins are installed.'
    COMMENT = ' '
}

# VCSA-80-000059
# =============================================================================================
$VCSA059	 = @{
    VULN_ID = "VCSA-80-000059"
    FINDING_DETAILS = 'Manually verified appropriate LDAPs servers are configured.'
    COMMENT = ' '
}

# VCSA-80-000089
# =============================================================================================
$VCSA089	 = @{
    VULN_ID = "VCSA-80-000089"
    FINDING_DETAILS = "Manually verified Session timeout is 60 minute(s)"
    STATUS = "Open"
    COMMENT = " " 
}

# VCSA-80-000248
# =============================================================================================
$VCSA248	 = @{
    VULN_ID = "VCSA-80-000248"
    FINDING_DETAILS = 'Manually verified Program Status: Not Joined'
    COMMENT = ' '
}

# VCSA-80-000253
# =============================================================================================
$VCSA253	 = @{
    VULN_ID = "VCSA-80-000253"
    FINDING_DETAILS = 'Manually verified SNMP.GET - Enable" is set to "False" and Authentication is set to "SHA1", Privacy is set to "AES128"'
    COMMENT = ' '
}

# VCSA-80-000277
# =============================================================================================
$VCSA277	 = @{
    VULN_ID = "VCSA-80-000277"
    FINDING_DETAILS = 'Manually verified Lifecycle Manager is disabled, internet patch repositories and any patches must be manually validated and imported as needed.'
    COMMENT = ' '
}

# VCSA-80-000278
# =============================================================================================
$VCSA278	 = @{
    VULN_ID = "VCSA-80-000278"
    FINDING_DETAILS = 'Manually verified each external application that connects to vCenter has a unique service account dedicated to that application.'
    COMMENT = ' '
}

# VCSA-80-000288
# =============================================================================================
$VCSA288	 = @{
    VULN_ID = "VCSA-80-000288"
    FINDING_DETAILS = 'Manually verified appropriate LDAPs servers are configured.'
    COMMENT = ' '
}

# VCSA-80-000294
# =============================================================================================
$VCSA294	 = @{
    VULN_ID = "VCSA-80-000294"
    FINDING_DETAILS = 'Manually verified backups exist for the Native Key Provider and they are password protected'
    COMMENT = ' '
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#///////////////////////////// STIG SETTINGS /////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$vcconfig = [ordered]@{
  tlsProfile           = "NIST_2024"  #VCSA-80-000009
  ssoLoginAttempts     = "3"  #VCSA-80-000023
  configLogLevel       = @{"config.log.level" = "info"} #VCSA-80-000034
  ssoPasswordLength    = "15" #VCSA-80-000069
  ssoPasswordReuse     = "5"  #VCSA-80-000070
  ssoPasswordUpper     = "1"  #VCSA-80-000071
  ssoPasswordLower     = "1"  #VCSA-80-000072
  ssoPasswordNum       = "1"  #VCSA-80-000073
  ssoPasswordSpecial   = "1"  #VCSA-80-000074
  ssoPasswordLifetime  = "90" #VCSA-80-000079
  ssoFailureInterval   = "900" #VCSA-80-000145
  ssoUnlockTime        = "0"  #VCSA-80-000266
  vcNetflowCollectorIp = $vcNetflowCollectorIp   #VCSA-80-000271
  vpxdExpiration       = @{"VirtualCenter.VimPasswordExpirationInDays" = "30"} #VCSA-80-000275
  vpxdPwLength         = @{"config.vpxd.hostPasswordLength" = "32"} #VCSA-80-000276
  vpxdEventSyslog      = @{"vpxd.event.syslog.enabled" = "true"} #VCSA-80-000280
  bashAdminUsers       = @("Administrator") #VCSA-80-000290  Administrator is the only user or group by default in this group
  bashAdminGroups      = @()  #VCSA-80-000290
  trustedAdminUsers    = @() #VCSA-80-000291  No users or groups by default
  trustedAdminGroups   = @()  #VCSA-80-000291
  dbEventAge           = @{"event.maxAge" = "30"} #VCSA-80-000293
  dbTaskAge            = @{"task.maxAge" = "30"} #VCSA-80-000293
}

##### Enable or Disable specific STIG Remediations #####
$controlsenabled = [ordered]@{
  VCSA8000009 = $true  #TLS Profile
  VCSA8000023 = $true  #SSO Login Attempts
  VCSA8000024 = $true  #SSO Banner - Manual
  VCSA8000034 = $true  #config.log.level
  VCSA8000057 = $true  #Plugins - Manual
  VCSA8000059 = $true  #Identity Provider
  VCSA8000060 = $true  #MFA
  VCSA8000069 = $true  #SSO Password Length
  VCSA8000070 = $true  #SSO Password Reuse
  VCSA8000071 = $true  #SSO Password Upper
  VCSA8000072 = $true  #SSO Password Lower
  VCSA8000073 = $true  #SSO Password Number
  VCSA8000074 = $true  #SSO Password Special
  VCSA8000077 = $true  #FIPS
  VCSA8000079 = $true  #SSO Password Lifetime
  VCSA8000080 = $true  #SSO Revocation Checking
  VCSA8000089 = $true  #Session Timeout
  VCSA8000095 = $true  #User roles
  VCSA8000110 = $true  #NIOC
  VCSA8000123 = $true  #SSO Alarm
  VCSA8000145 = $true  #SSO Failed Interval
  VCSA8000148 = $true  #Syslog
  VCSA8000158 = $true  #NTP
  VCSA8000195 = $true  #DoD Cert
  VCSA8000196 = $true  #vSAN DAR Encryption
  VCSA8000248 = $true  #CEIP
  VCSA8000253 = $true  #SNMP v3 security
  VCSA8000265 = $true  #Disable SNMP v1/2
  VCSA8000266 = $true  #SSO unlock time
  VCSA8000267 = $true  #DVS health check
  VCSA8000268 = $true  #DVPG Forged Transmits
  VCSA8000269 = $true  #DVPG MAC Changes
  VCSA8000270 = $true  #DVPG Promiscuous mode
  VCSA8000271 = $true  #Netflow
  VCSA8000272 = $true  #Native VLAN
  VCSA8000273 = $true  #VLAN Trunking
  VCSA8000274 = $true  #Reserved VLANs
  VCSA8000275 = $true  #VPX user password change
  VCSA8000276 = $true  #VPX user password length
  VCSA8000277 = $true  #vLCM internet
  VCSA8000278 = $true  #Service Accounts
  VCSA8000279 = $true  #Isolate IP storage networks
  VCSA8000280 = $true  #Send events to syslog
  VCSA8000281 = $true  #VSAN HCL
  VCSA8000282 = $true  #VSAN Datastore name
  VCSA8000283 = $true  #Disable UN/PW and IWA
  VCSA8000284 = $true  #Crypto role
  VCSA8000285 = $true  #Crypto permissions
  VCSA8000286 = $true  #iSCSI CHAP
  VCSA8000287 = $true  #VSAN KEKs
  VCSA8000288 = $true  #LDAPS
  VCSA8000289 = $true  #LDAP Account
  VCSA8000290 = $true  #Bash admins
  VCSA8000291 = $true  #TrustedAdmins
  VCSA8000292 = $true  #Backups
  VCSA8000293 = $true  #Event Retention
  VCSA8000294 = $true  #NKP
  VCSA8000295 = $true  #Content Library Password
  VCSA8000296 = $true  #Content Library Security Policy
  VCSA8000298 = $true  #SSO groups for authorization
  VCSA8000299 = $true  #Disable CDP/LLDP on VDS
  VCSA8000300 = $true  #Port Mirroring
  VCSA8000301 = $true  #DPG Override policies
  VCSA8000302 = $true  #DPG reset at disconnect
  VCSA8000303 = $true  #SSH Disable
  VCSA8000304 = $true  #vSAN DIT Encryption
  VCSA8000305 = $true  #Disable IWA Accounts
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////Known Open Items///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$KnownIssues = @($VCSA009,$VCSA095,$VCSA150,$VCSA284,$VCSA286,$VCSA287,$VCSA080,$VCSA283,$VCSA281,$VCSA282,$VCSA285,$VCSA279,$VCSA024,$VCSA057,$VCSA059,$VCSA089,$VCSA248,$VCSA253,$VCSA277,$VCSA278,$VCSA288,$VCSA289,$VCSA294,$VCSA196,$VCSA304)
$KnownIDs   += $KnownIssues | ForEach-Object { $_.VULN_ID } 
$DVSIDs = @("VCSA-80-000110","VCSA-80-000267","VCSA-80-000268","VCSA-80-000269","VCSA-80-000270","VCSA-80-000271","VCSA-80-000272","VCSA-80-000273","VCSA-80-000274","VCSA-80-000299","VCSA-80-000300","VCSA-80-000301","VCSA-80-000302")

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////////INTIALIZE VARIABLES//////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Write-Host "
#==========================================================================
# NAME: $NAME
# AUTHOR: Peter Stearns
# UPDATED: $UPDATED
# PROFILE: VMW_vSphere_8-0_vCA_V2R2 (Services)
# PROFILE: VMW_vSphere_8-0_vCenter_V2R2
# DESCRIPTION:
#    -This script runs the Inspec Profile against the VCSA Services and vCenter
#    -Then calls Ansible to fix open findings
#    -Outputs a STIG Viewer Checklist file for each service and vCenter
#=========================================================================="

If($global:DefaultVIServer -or $global:DefaultVIServers) { Disconnect-VIServer * -Confirm:$false }
If($global:defaultSsoAdminServer -or $global:defaultSsoAdminServers) { Disconnect-SsoAdminServer * }

#Get Current Date
$date = Get-Date
$dateStr = (Get-Date -Format "yyyMMdd")

Function Write-ToConsole ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate):  $Details"
} 

if($profiles){Write-ToConsole "Using $profiles..."}

#Prompt for vCenter
# =============================================================================================
$msgvCenter = "Enter vCenter FQDN"
if($vcenter){
    $vCenter_FQDN  = $vcenter
    $splitName     = $vCenter_FQDN.split(".")
    $connection    = Test-Connection -ComputerName $vCenter_FQDN -Count 1 -Quiet
    if($vCenter_FQDN -ne $null -and $vCenter_FQDN -ne "" -and $splitName[1] -ne $null -and $connection -eq "True"){
        Write-ToConsole "$($vcenter) - Starting Inspec..."
    }
    else{    
        do {
            $vCenter_FQDN  = Read-Host $msgvCenter
            $splitName     = $vCenter_FQDN.split(".") 
            $connection    = Test-Connection -ComputerName $vCenter_FQDN -Count 1 -Quiet
        }
        until ($vCenter_FQDN -ne $null -and $vCenter_FQDN -ne "" -and $splitName[1] -ne $null -and $connection -eq "True")
    }
}else{    
    do {
        $vCenter_FQDN  = Read-Host $msgvCenter
        $splitName     = $vCenter_FQDN.split(".") 
        $connection    = Test-Connection -ComputerName $vCenter_FQDN -Count 1 -Quiet
    }
    until ($vCenter_FQDN -ne $null -and $vCenter_FQDN -ne "" -and $splitName[1] -ne $null -and $connection -eq "True")
}

$vCenter_IP   = [system.net.dns]::GetHostByName($vCenter_FQDN).AddressList[0].IPAddressToString

if($credObj){
    $vcsaAdmnCred = $credObj.vcsaAdmnCred
    $vcsaRootCred = $credObj.vcsaRootCred
    $esxiRootCred = $credObj.esxiRootCred
}

if(!$vcsaAdmnCred){ $vcsaAdmnCred = Get-Credential -Message "Enter administrator@vsphere Creds:" }
if(!$vcsaRootCred){ $vcsaRootCred = Get-Credential -message "Enter VCSA root password" -UserName "root" }
if(!$RunBy){ $RunBy = Read-Host -Prompt "Enter your full name" }

$splitName       = $vCenter_FQDN.split(".")
$VCSAshortname   = $splitName[0].ToUpper()

$reportFolder    = "/opt/stigtools/vsphere8/Reports/" + $VCSAshortname
$inspecPath      = "/opt/stigtools/vsphere8/dod-compliance-and-automation-master/vsphere/8.0/v2r2-stig/vcsa/inspec/vmware-vcsa-8.0-stig-baseline"
$inspecvCenter   = "/opt/stigtools/vsphere8/dod-compliance-and-automation-master/vsphere/8.0/v2r2-stig/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/vcenter"
$VulnID_mapper   = "/opt/stigtools/vsphere8/VulnID_mapper8.csv"
$ansiblePlaybook = "/opt/stigtools/vsphere8/dod-compliance-and-automation-master/vsphere/8.0/v2r2-stig/vcsa/ansible/vmware-vcsa-8.0-stig-ansible-hardening/playbook.yml"
$csvPath       = $reportFolder + "/Open_VCSA_STIGs_Report.csv"

$ENV:RUBYOPT     = 'rubygems'
$ENV:RUBY_DIR    = '/opt/cinc-auditor/embedded'
$ENV:GEM_PATH    = '/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems'
$ENV:PATH        = '/opt/cinc-auditor/embedded/bin;' + $ENV:PATH
$ENV:NO_COLOR    = $true

$ENV:VISERVER           = $vCenter_FQDN
$ENV:VISERVER_USERNAME  = $vcsaAdmnCred.UserName
$ENV:VISERVER_PASSWORD  = $vcsaAdmnCred.GetNetworkCredential().password

$profileTable = [ordered]@{}
$profileTable = [System.Collections.Hashtable]::Synchronized($profileTable)
$profileResultTable = [ordered]@{}
$profileResultTable = [System.Collections.Hashtable]::Synchronized($profileResultTable)
$OpenReport = @()
$remediateTable  = [ordered]@{}

$NameDateTag = "

Automated checks run by: $RunBy on $dateStr"

# Import VMware.vSphere.SsoAdmin module
Import-Module "/opt/microsoft/powershell/7/Modules/VMware.vSphere.SsoAdmin/VMware.vSphere.SsoAdmin.psm1" -DisableNameChecking -Force
Import-Module "/opt/microsoft/powershell/7/Modules/VMware.vSphere.SsoAdmin/VMware.vSphere.SsoAdmin.psd1" -DisableNameChecking -Force
Connect-VIServer -Server $vCenter_FQDN -Credential $vcsaAdmnCred -ErrorAction SilentlyContinue | Out-Null
$sessionID =  $global:DefaultVIServer.SessionId

# ================= GET MAC ADDRESS FROM FIRST NIC
try {
    $networkadapters = Get-VM -Name "*$VCSAshortname*" | get-networkadapter
    $networkadapter = $networkadapters[0] 
    $macaddress = $networkadapter.macaddress
}catch{
    $macaddress = arp -a | select-string $vCenter_IP |% { $_.ToString().Trim().Split(" ")[3] }
}
    

# Verify report folder
# =============================================================================================
If(Test-Path -Path $reportFolder){
    Write-ToConsole "$($VCSAshortname) - Validated path for report at $reportFolder"
}Else{
    Write-ToConsole "Report path $reportFolder doesn't exist...attempting to create..."
    New-Item -ItemType Directory -Path $reportFolder -Force
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////////////////// FUNCTIONS ///////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Run Inspec to find open items
Function InspecVCSA(){
    param (
        [string]$profile,
        [hashtable]$profileTable,
        [hashtable]$profileResultTable,
        [DateTime]$startTime
    )

    $profileObj = $profileTable[$profile]
    
    # Functions
    ${function:Write-ToConsole} = $profileObj.WriteToConsole
    
    # Varibles
    $MARKING       = $profileObj.MARKING
    $VulnID_mapper = $profileObj.VulnID_mapper
    $inspecPath    = $profileObj.inspecPath
    $inspecvCenter = $profileObj.inspecvCenter
    $NameDateTag   = $profileObj.NameDateTag
    $KnownIDs      = $profileObj.KnownIDs
    $KnownIssues   = $profileObj.KnownIssues
    $silent        = $profileObj.silent

    # vCenter Varibles
    $vcsaAdmnCred  = $profileObj.vcsaAdmnCred
    $vcsaRootCred  = $profileObj.vcsaRootCred
    $sessionID     = $profileObj.sessionID 
    $vCenter_FQDN  = $profileObj.vCenter_FQDN
    $vCenter_IP    = $profileObj.vCenter_IP
    $VCSAshortname = $profileObj.VCSAshortname
    $macaddress    = $profileObj.macaddress
        
    # Profile Specific Varibles
    $ProfileName = $profileObj.profileName
    $ProfileVer  = $profileObj.profileVer
    $stigName    = $profileObj.stigName
    $ProfilePath = $profileObj.ProfilePath
    $reportFile  = $profileObj.reportFile
    $cklFile     = $profileObj.cklFile
    $FixReport   = $profileObj.FixReport
    $FixCklFile  = $profileObj.FixCklFile
    $attestFile  = $profileObj.attestFile
    $templateCklFile = $profileObj.templateCklFile
    $finalCklFile = $profileObj.finalCklFile

    # STIG Varibles
    $authprivlog    = $profileObj.authprivlog
    $syslogServers  = $profileObj.syslogServers
    $ntpServers     = $profileObj.ntpServers 
    $sslIssueOrg    = $profileObj.sslIssueOrg 
    $backup3rdParty =  $profileObj.backup3rdParty 
    $embeddedIdp    =  $profileObj.embeddedIdp 

    Start-Sleep -MilliSeconds (Get-Random -Minimum 2000 -Maximum 7000)
    Write-ToConsole "$($profileObj.VCSAshortname) - Running Inspec $($profileObj.ProfileName) Profile"
    Connect-VIServer -Server $profileObj.vCenter_FQDN -Session $profileObj.SessionID -ErrorAction SilentlyContinue | Out-Null

    # Run Inspec profile against VCSA
    # =============================================================================================
    if($profileObj.ProfileName -ne "vCenter"){

		# Enable vCenter SSH
		$body = Initialize-AccessSshSetRequestBody -Enabled $true
		Invoke-SetAccessSsh -AccessSshSetRequestBody $body

        cinc-auditor exec $($profileObj.profilePath) -t ssh://root@$vCenter_FQDN --password $vcsaRootCred.GetNetworkCredential().password --input authprivlog=$authprivlog  --reporter json:$($profileObj.reportFile)
    }
    elseif($profileObj.ProfileName -eq "vCenter"){
		Connect-SsoAdminServer -Server $vCenter_FQDN -Credential $vcsaAdmnCred -SkipCertificateCheck -ErrorAction SilentlyContinue | Out-Null
		
		# Disable vCenter SSH
		$body = Initialize-AccessSshSetRequestBody -Enabled $false
		Invoke-SetAccessSsh -AccessSshSetRequestBody $body
        
		cinc-auditor exec $($profileObj.profilePath) -t vmware:// --input syslogServers=$syslogServers ntpServers=$ntpServers sslIssueOrg=$sslIssueOrg backup3rdParty=$backup3rdParty embeddedIdp=$embeddedIdp --reporter json:$($profileObj.reportFile)
    }
    Write-ToConsole "$($profileObj.VCSAshortname) - Creating CKL for $($profileObj.ProfileName)"
    inspec_tools inspec2ckl -j $($profileObj.reportFile) -o $($profileObj.cklFile)

    # CleanUp
    # =============================================================================================
    if($profileObj.reportFile){Remove-Item -Path $($profileObj.reportFile) -erroraction 'silentlycontinue'}

    # Finalize CKL
    # Create XML object from CKL
    # =============================================================================================
    Try{$xmlCkl = ( Select-Xml -Path $($profileObj.cklFile) -XPath / ).Node}
    Catch{Write-Error "Failed to import $($profileObj.ProfileName) CKL.."; Exit -1}

    # Update CKL FILE With ASSET Info
    # =============================================================================================
    # Find Asset String
    if($xmlCkl){

        $xmlCkl.CHECKLIST.ASSET.ROLE            = "Member Server"
        $xmlCkl.CHECKLIST.ASSET.ASSET_TYPE      = "Computing"
        #$xmlCkl.CHECKLIST.ASSET.MARKING        = $MARKING
        $xmlCkl.CHECKLIST.ASSET.HOST_NAME       = $profileObj.VCSAshortname
        $xmlCkl.CHECKLIST.ASSET.HOST_IP         = $profileObj.vCenter_IP
        $xmlCkl.CHECKLIST.ASSET.HOST_MAC        = $profileObj.macaddress
        $xmlCkl.CHECKLIST.ASSET.HOST_FQDN       = $profileObj.vCenter_FQDN
        $xmlCkl.CHECKLIST.ASSET.WEB_OR_DATABASE = "false"

        # Find and Markup Known Issues
        # =============================================================================================
        foreach ($KnownID in $profileObj.KnownIDs){
            $Vuln_Node = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN |  Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $KnownID }
            if($Vuln_Node){
                $Vuln_Object        = $profileObj.KnownIssues | where-object VULN_ID -contains $KnownID
                $Vuln_Node.COMMENTS = $Vuln_Object.COMMENT
                if($Vuln_Object.STATUS){
                    $Vuln_Node.STATUS   = $Vuln_Object.STATUS
		}
		if($Vuln_Object.FINDING_DETAILS){
                    $Vuln_Node.FINDING_DETAILS   = $Vuln_Object.FINDING_DETAILS
                }
            }
        }

        # Mark DVS to Not applicable if not found (vCenter profile only)
        # =============================================================================================
        if($profileObj.ProfileName -eq "vCenter"){
            foreach ($DVSID in $profileObj.DVSIDs){
                $Vuln_Node = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $DVSID }
                if($Vuln_Node.FINDING_DETAILS.Contains("No distributed")){
                    $Vuln_Node.COMMENTS = $profileObj.DVSUpdates.COMMENT
                    $Vuln_Node.STATUS   = $profileObj.DVSUpdates.STATUS
                }
            }
        }
        
        # Add Name and Date to comments
        # =============================================================================================
        $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | ForEach-Object {
            $CommentValue = $_.COMMENTS
            $_.COMMENTS = $CommentValue + $profileObj.NameDateTag
        }

        # Save XML data to CKL file
        # =============================================================================================
        $xmlCkl.Save($profileObj.cklFile)
    }
    else{Write-Error "Failed to run read XML..."; Exit -1}

    # Create List Open Items
    # =============================================================================================    
    $OpenItems = @()
    $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
        $OpenItem = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Rule_Ver"}).ATTRIBUTE_DATA
        $OpenItems += $OpenItem
        if($OpenItem -in $KnownIDs){$Known = "True"}
        else {$Known = "False"}
    }
    $profileResultTable.add($profileObj.ProfileName,$OpenItems)
    Write-ToConsole "$($profileObj.VCSAshortname) - Checklist for $($profileObj.ProfileName) saved..."
}

Function VulnID2StigID () {
    param(
        [hashtable]$profileTable
    )
    # Replace update VULN_ID with proper ID
    # =============================================================================================
    if ($profileTable){
        $VulnIDTable = @{}
        Import-CSV $($VulnID_mapper) | % { $VulnIDTable[$_.STIGID] = $_.VulnID }
        $profileTable.keys | ForEach-Object {
            $profile = $_
            $profileObj = $profileTable[$_]
            $xmlCkl = ( Select-Xml -Path $profileObj.cklFile -XPath / ).Node
            $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Vuln_Num"} | ForEach-Object {
                $NodeID = $_.ATTRIBUTE_DATA
                $Vuln_ID = $VulnIDTable.Item($NodeID)
                if($Vuln_ID){
	                $_.ATTRIBUTE_DATA = $Vuln_ID
                }
            }
            # Save XML data to CKL file
            $xmlCkl.Save($profileObj.cklFile)
        }
    }
}

Function ListOpenItems () {
    param(
        [array]$KnownIDs,
        [hashtable]$profileTable,
        [hashtable]$RemediateTable
    )
    # List Open Items
    # =============================================================================================
    if ($profileTable){
        $summary = @()
        $profileTable.keys | ForEach-Object {
            $profile = $_
            $profileObj = $profileTable[$profile]
            $remediated = $remediateTable[$profile]
            $xmlCkl = ( Select-Xml -Path $profileObj.cklFile -XPath / ).Node
            $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
				$RuleID = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Rule_Ver"}).ATTRIBUTE_DATA
				$VulnID = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Vuln_Num"}).ATTRIBUTE_DATA
                $OpenItems += $RuleID
                if($RuleID -in $KnownIDs){$Known = "True"}
                else {$Known = "False"}
                $obj = New-Object -TypeName PSObject
                $obj | Add-Member -MemberType NoteProperty -Name Date -Value (Get-Date -format "dd-MMM-yyyy HH:mm")
                $obj | Add-Member -MemberType NoteProperty -Name Service -Value $profileObj.ProfileName 
                $obj | Add-Member -MemberType NoteProperty -Name VulnID -Value $VulnID
                $obj | Add-Member -MemberType NoteProperty -Name STIGID -Value $RuleID
                $obj | Add-Member -MemberType NoteProperty -Name Known -value $Known
                $obj | Add-Member -MemberType NoteProperty -Name Remediated -value $remediated
                $summary += $obj
            }
        }
        Write-ToConsole "*********************************************"
        Write-ToConsole "  $($profileObj.VCSAshortname) - SUMMARY                        "
        Write-ToConsole "*********************************************"
        Write-Host ($summary | Sort-Object Service | Format-Table | Out-String)
        $summary | Export-Csv $csvPath -Append -Force -NoTypeInformation
    }
}

Function MergeTemplate () {
    param(
        [hashtable]$profileTable
    )
    if ($profileTable){
        $profileTable.keys | ForEach-Object {
            $profile = $_
            $profileObj = $profileTable[$profile]
            $templateXmlCkl = ( Select-Xml -Path $profileObj.templateCklFile -XPath / ).Node
            $xmlCkl = ( Select-Xml -Path $profileObj.cklFile -XPath / ).Node

            # Merge Assest info to template
            # =============================================================================================
            $templateXmlCkl.CHECKLIST.ASSET.ROLE            = $xmlCkl.CHECKLIST.ASSET.ROLE
            $templateXmlCkl.CHECKLIST.ASSET.MARKING         = $profileObj.MARKING
            $templateXmlCkl.CHECKLIST.ASSET.ASSET_TYPE      = $xmlCkl.CHECKLIST.ASSET.ASSET_TYPE
            $templateXmlCkl.CHECKLIST.ASSET.HOST_NAME       = $xmlCkl.CHECKLIST.ASSET.HOST_NAME
            $templateXmlCkl.CHECKLIST.ASSET.HOST_IP         = $xmlCkl.CHECKLIST.ASSET.HOST_IP
            $templateXmlCkl.CHECKLIST.ASSET.HOST_MAC        = $xmlCkl.CHECKLIST.ASSET.HOST_MAC
            $templateXmlCkl.CHECKLIST.ASSET.HOST_FQDN       = $xmlCkl.CHECKLIST.ASSET.HOST_FQDN
            $templateXmlCkl.CHECKLIST.ASSET.WEB_OR_DATABASE = $xmlCkl.CHECKLIST.ASSET.WEB_OR_DATABASE

            # Merge VULN Details info to template
            # =============================================================================================
            try{
                $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN |  ForEach-Object {  
                    $xmlVulnID       = $_.STIG_DATA.ATTRIBUTE_DATA[0]
                    $xmlVulnSTATUS   = $_.STATUS
                    $xmlVulnFindDet  = $_.FINDING_DETAILS
                    $xmlVulnCOMMENTS = $_.COMMENTS

                    $templateCklNode = $templateXmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $xmlVulnID }
                    $templateCklNode.STATUS           = $xmlVulnSTATUS
                    $templateCklNode.FINDING_DETAILS  = $xmlVulnFindDet
                    $templateCklNode.COMMENTS         = $xmlVulnCOMMENTS
                }
            }Catch{Write-Error "Failed to merge into Template CKL for $($profile)... $_.Exception"}

            # Save XML data to CKL file
            # =============================================================================================
            $templateXmlCkl.Save($profileObj.finalCklFile)
            if($profileObj.cklFile){Remove-Item -Path $profileObj.cklFile -erroraction 'silentlycontinue'}
        }
    }
}

Function RemediateItem(){
    param (
        [object]$profileObj
    )
    $profileName = $profileObj.ProfileName
	$vcenter = $profileObj.vCenter_FQDN
    # Create XML object from CKL
    # =============================================================================================
    Try{$xmlCkl = ( Select-Xml -Path $($profileObj.cklFile) -XPath / ).Node}
    Catch{Write-Error "Failed to import $($profileName) CKL.."; Exit -1}

    # Find all OPEN ITEMS compare to known issues
    # =============================================================================================
    $OpenItems = @()
    $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
        $OpenItems += ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Rule_Ver"}).ATTRIBUTE_DATA
    }

    $FixItems = $OpenItems | Where-Object { $profileObj.KnownIDs -notcontains $_ }

    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
    #/////////////////////// REMEDIATION OPEN ITEMS //////////////////////////
    #+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

    if($FixItems){
	
        Write-ToConsole "*********************************************" 
        Write-ToConsole "The Following Items will need to Remediated" -ForegroundColor Yellow 
        Write-ToConsole "Profile: $($profileName)" -ForegroundColor Yellow 
        Write-ToConsole "*********************************************"
        Write-ToConsole $FixItems -ForegroundColor Red 

        $msg = "$(Get-Date -Format T):  Run Ansible to remediate items? [y/n]"
        do {$response = Read-Host -Prompt $msg
        }until ($response -eq "y" -or $response -eq "n")

        if(($response -eq "y") -and ($profileName -ne "vCenter")){
			
            # Running Ansible on Open Items
            # =============================================================================================
			
			# Enable vCenter SSH
			$body = Initialize-AccessSshSetRequestBody -Enabled $true
			Invoke-SetAccessSsh -AccessSshSetRequestBody $body
			
            $profile_backup = $profileName + "_backup,"            
            $FixItemString = $profile_backup + ($FixItems -join ",")
            
            ansible-playbook -v -i "$vCenter_FQDN," -u root $ansiblePlaybook --tags $FixItemString -e "ansible_ssh_pass=$($vcsaRootCred.GetNetworkCredential().password)"
            $remediated = "Ansible run on" + $FixItemString

            # Running Inspec to Verify Items
            # =============================================================================================
            Write-ToConsole "Re-Generating $($profileName) STIG Checklist for $($VCSAshortname)"
            cinc-auditor exec $($profileObj.profilePath) -t ssh://root@$vCenter_FQDN --password $vcsaRootCred.GetNetworkCredential().password --input authprivlog=$authprivlog --show-progress --reporter json:$($profileObj.FixReport) --controls $FixItems

            Write-ToConsole "Converting STIG Checklist..."
            inspec_tools inspec2ckl -j $($profileObj.FixReport) -o $($profileObj.FixCklFile)
			
		    # Disable vCenter SSH
			$body = Initialize-AccessSshSetRequestBody -Enabled $false
			Invoke-SetAccessSsh -AccessSshSetRequestBody $body

            # Updating CKL with fixed items
            # =============================================================================================
            $xmlFixCkl = ( Select-Xml -Path $($profileObj.FixCklFile) -XPath / ).Node
            $xmlFixCkl.CHECKLIST.STIGS.iSTIG.VULN | ForEach-Object {
                $CommentValue = $_.COMMENTS
                $_.COMMENTS = $CommentValue + $NameDateTag
            }

            foreach ($FixItem in $FixItems){
                $Fix_Node                    = $xmlFixCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $FixItem }
                $xmlCkl_Node                 = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $FixItem }
                $xmlCkl_Node.STATUS          = $Fix_Node.STATUS
                $xmlCkl_Node.COMMENTS        = $Fix_Node.COMMENTS
                $xmlCkl_Node.FINDING_DETAILS = $Fix_Node.FINDING_DETAILS
            }
        }
        elseif(($response -eq "y") -and ($profileName -eq "vCenter")){
            # Running PowerCLI for vCenter specific Items
            # =============================================================================================
			Import-Module "/opt/stigtools/vsphere8/vCenter_STIG_Module/vmware-vCenter-8.0-stig-module.ps1" -DisableNameChecking -force
                        Connect-VIServer -Server vCenter_FQDN -Session $profileObj.SessionID -ErrorAction SilentlyContinue | Out-Null
			Connect-SsoAdminServer -Server $vCenter_FQDN -Credential $vcsaAdmnCred -SkipCertificateCheck -ErrorAction SilentlyContinue | Out-Null			
			foreach ($FixItem in $FixItems){
				try{& $FixItem $controlsenabled $vcconfig $vcenter
				}catch{Write-Error "Failed remediate $($FixItem) on $($vcenter)... $_.Exception"}
			}

            # Running Inspec to Verify Items
            # =============================================================================================
			Write-ToConsole "Re-Generating $($profileName) STIG Checklist for $($VCSAshortname)"
			cinc-auditor exec $($profileObj.profilePath) -t vmware:// --input syslogServers=$syslogServers ntpServers=$ntpServers sslIssueOrg=$sslIssueOrg backup3rdParty=$backup3rdParty embeddedIdp=$embeddedIdp --show-progress --reporter json:$($profileObj.FixReport) --controls $FixItems
            Write-ToConsole "Converting STIG Checklist..."
            inspec_tools inspec2ckl -j $($profileObj.FixReport) -o $($profileObj.FixCklFile)
			
            # Updating CKL with fixed items
            # =============================================================================================
            $xmlFixCkl = ( Select-Xml -Path $($profileObj.FixCklFile) -XPath / ).Node
            $xmlFixCkl.CHECKLIST.STIGS.iSTIG.VULN | ForEach-Object {
                $CommentValue = $_.COMMENTS
                $_.COMMENTS = $CommentValue + $NameDateTag
            }

            foreach ($FixItem in $FixItems){
                $Fix_Node                    = $xmlFixCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $FixItem }
                $xmlCkl_Node                 = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $FixItem }
                $xmlCkl_Node.STATUS          = $Fix_Node.STATUS
                $xmlCkl_Node.COMMENTS        = $Fix_Node.COMMENTS
                $xmlCkl_Node.FINDING_DETAILS = $Fix_Node.FINDING_DETAILS
            }
        }
        elseif($response -eq "n"){
            Write-ToConsole "*********************************************"
            Write-ToConsole "Finializing $($profileName) STIG CKL with open items..." -ForegroundColor Yellow
            $remediated = "Remeditaion skipped" 
        }
    }
    else{
        Write-ToConsole "*********************************************"
        Write-ToConsole "All $($profileName) STIG items are remediated" 
        Write-ToConsole "Finializing $($profileName) STIG CKL..."
        $remediated = "No open items"
    }

    # Save XML data to CKL file
    # =============================================================================================
    Write-ToConsole "Saving File..."
    $xmlCkl.Save($profileObj.cklFile)

    # CleanUp
    # =============================================================================================   
    if($profileObj.FixReport){Remove-Item -Path $($profileObj.FixReport) -erroraction 'silentlycontinue'}
    if($profileObj.FixcklFile){Remove-Item -Path $($profileObj.FixcklFile) -erroraction 'silentlycontinue'}
    
    $remediateTable.add($profileName,$remediated)
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#///////////////////////////MAIN SCRIPT//////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Write-ToConsole "$($VCSAshortname) - Running Inspec VMW_VSPHERE_8-0_VCENTER_V2R2 Profile"
Write-ToConsole ""

if(!$profiles) {
    $profiles = @("eam","lookup","perfcharts","photon","postgresql","envoy","sts","vami","ui","vcenter")
}

if(!$silent){
    Function Write-ToConsole ($Details) {
	    $LogDate = Get-Date -Format T
	    Write-Host "$($LogDate):  $Details"
    }
}Else{Function Write-ToConsole ($Details) { write-host . -NoNewline}}

# Create Profile Object for each service
# =============================================================================================

$WriteToConsole = ${Function:Write-ToConsole}.ToString()
$InspecVCSA     = ${Function:InspecVCSA}.ToString()

foreach($profile in $profiles){  
    if($profile -eq "vcenter"){
        $profileName   = "vCenter"
        $stigName      = "vcenter"
        $profileVer    = "VMW_VSPHERE_8-0_VCENTER_V2R2"
        $profilePath   = $inspecvCenter
        $reportPath    = $reportFolder + "/VCSA"
        $templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_vCenter_STIG_V2R2.ckl"
    }
    else{
        $profileName   = $profile.ToUpper()
        $profilePath   = $inspecPath + "/" + $profile
        $reportPath    = $reportFolder + "/VCSA"
        if($profile -eq "eam")             {
            $stigName = "vCenter Appliance EAM"
            $profileVer    = "VMW_VSPHERE_8-0_VCA_$($profileName)_V2R2"
            $templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_vCA_EAM_STIG_V2R2.ckl"
        }elseif($profile -eq "lookup")     {
            $stigName = "vCenter Appliance Lookup Service"
            $profileVer    = "VMW_VSPHERE_8-0_VCA_$($profileName)_V2R1"
            $templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_vCA_Lookup_Svc_STIG_V2R1.ckl"
        }elseif($profile -eq "perfcharts") {
            $stigName = "vCenter Appliance Perfcharts"
            $profileVer    = "VMW_VSPHERE_8-0_VCA_$($profileName)_V2R1"
            $templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_vCA_Perfcharts_STIG_V2R1.ckl"
        }elseif($profile -eq "photon")     {
            $stigName = "vCenter Appliance Photon OS"
            $profileVer    = "VMW_VSPHERE_8-0_VCA_$($profileName)_V2R1"
            $templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_vCA_Photon_OS_4_STIG_V2R1.ckl"
        }elseif($profile -eq "postgresql") {
            $stigName = "vCenter Appliance PostgreSQL"
            $profileVer    = "VMW_VSPHERE_8-0_VCA_$($profileName)_V2R1"
            $templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_vCA_PostgreSQL_STIG_V2R1.ckl"
        }elseif($profile -eq "envoy") {
            $stigName = "vCenter Appliance Envoy"
            $profileVer    = "VMW_VSPHERE_8-0_VCA_$($profileName)_V2R1"
            $templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_vCA_Envoy_STIG_V2R1.ckl"
        }elseif($profile -eq "sts")        {
            $stigName = "vCenter Appliance STS"
            $profileVer    = "VMW_VSPHERE_8-0_VCA_$($profileName)_V2R1"
            $templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_vCA_STS_STIG_V2R1.ckl"
        }elseif($profile -eq "vami")       {
            $stigName = "VAMI"
            $profileVer    = "VMW_VSPHERE_8-0_VCA_$($profileName)_V2R1"
            $templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_VAMI_STIG_V2R1.ckl"
        }elseif($profile -eq "ui")         {
            $stigName = "vCenter Appliance UI"
            $profileVer    = "VMW_VSPHERE_8-0_VCA_$($profileName)_V2R1"
            $templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_vCA_UI_STIG_V2R1.ckl"
        }
    }

    $reportFile    = $reportPath + "/" + $VCSAshortname + "_" + $classification + "_" + $profileVer + "_" + $dateStr + ".json"
    $cklFile       = $reportPath + "/" + $VCSAshortname + "_" + "temp" + "_" + $profileVer + "_" + $dateStr + ".ckl"
    $finalCklFile  = $reportPath + "/" + $VCSAshortname + "_" + $classification + "_" + $profileVer + "_" + $dateStr + ".ckl"
    $FixReport     = $reportPath + "/" + $VCSAshortname + "_" + "Remediation" + "_" + $profileVer + "_" + $dateStr + ".json"
    $FixCklFile    = $reportPath + "/" + $VCSAshortname + "_" + "Remediation" + "_" + $profileVer + "_" + $dateStr + ".ckl"
    $attestFile    = $profilePath + "/vmware-vsphere-8.0-stig-" + $profileName + "-attestation.yml"

    $profileObj = [PSCustomObject]@{
        # Functions
        WriteToConsole = [string]$WriteToConsole

        # Varibles
        MARKING       = [string]$MARKING
        VulnID_mapper = [string]$VulnID_mapper
        inspecPath    = [string]$inspecPath
        inspecvCenter = [string]$inspecvCenter
        NameDateTag   = [string]$NameDateTag
        KnownIDs      = [array]$KnownIDs
        KnownIssues   = [array]$KnownIssues
        VCSA286       = [Hashtable]$VCSA286
        DVSIDs        = [array]$DVSIDs 
        DVSUpdates    = [Hashtable]$DVSUpdates
        silent        = [switch]$silent

        # vCenter Varibles
        vcsaAdmnCred  = [object]$vcsaAdmnCred
        vcsaRootCred  = [object]$vcsaRootCred
        vCenter_FQDN  = [string]$vCenter_FQDN
        vCenter_IP    = [string]$vCenter_IP
        VCSAshortname = [string]$VCSAshortname
        macaddress    = [string]$macaddress
        sessionID     = [object]$sessionID 
        
        # Profile Specific Varibles
        ProfileName = [string]$profileName
        ProfileVer  = [string]$profileVer
        stigName    = [string]$stigName
        ProfilePath = [string]$ProfilePath
        reportFile  = [string]$reportFile
        cklFile     = [string]$cklFile
        FixReport   = [string]$FixReport
        FixCklFile  = [string]$FixCklFile
        attestFile  = [string]$attestFile
        templateCklFile = [string]$templateCklFile
	    finalCklFile = [string]$finalCklFile

        # STIG Varibles
        authprivlog    = [string]$authprivlog
        syslogServers  = [array]$syslogServers
        ntpServers     = [array]$ntpServers 
        sslIssueOrg    = [array]$sslIssueOrg 
        backup3rdParty = [string]$backup3rdParty 
        embeddedIdp    = [string]$embeddedIdp 
    }
    $profileTable.add($profile,$profileObj)
}

# RUNNING INSPEC CHECKS and CREATING CKLS
# =============================================================================================
Write-ToConsole "Running INSPEC for VCA services"
$profiles | Foreach -ThrottleLimit 15 -Parallel {
    ${function:InspecVCSA} = $using:InspecVCSA
    ${function:Write-ToConsole} = $using:WriteToConsole
	if ($_ -ne "vcenter") {
		InspecVCSA -profile $_ -profileTable $using:profileTable -profileResultTable $using:profileResultTable -startTime $using:startTime
	}
}

Write-ToConsole "Running INSPEC for vCenter"
$profiles | Foreach -ThrottleLimit 15 -Parallel {
    ${function:InspecVCSA} = $using:InspecVCSA
    ${function:Write-ToConsole} = $using:WriteToConsole
	if ($_ -eq "vcenter") {
		InspecVCSA -profile $_ -profileTable $using:profileTable -profileResultTable $using:profileResultTable -startTime $using:startTime
	}
}

$FormatEnumerationLimit=-1
Write-ToConsole " "
Write-ToConsole "$($VCSAshortname) - OPENS: "
foreach ($r in $profileResultTable.GetEnumerator() ) {
    Write-Host "$($r.Name) : `t$($r.Value)"
}

# REMEDIATE OPEN ITEMS
# =============================================================================================
if(!$skipFix){
    $silent = $null
    Write-ToConsole "*********************************************" 
    Write-ToConsole "        Starting Remediation Process...      "
    Write-ToConsole "*********************************************"
    $msg = "$(Get-Date -Format T):  Run Ansible to remediate items? [y/n]"
    do {$response = Read-Host -Prompt $msg
    }until ($response -eq "y" -or $response -eq "n")
}else{$response = "n"}
    
if($response -eq "y") {
    $profileTable.keys | ForEach-Object {
        $profile = $_
        $profileObj = $profileTable[$profile]

        # Run Ansible to Remeditate Open Items on Services
        # =============================================================================================
		if ($profile -ne "vcenter") {
			RemediateItem $profileObj
		}
		
		# Run PowerCLI to Remeditate Open Items on vCenter
        # =============================================================================================
		elseif ($profile -eq "vcenter") {
			RemediateItem $profileObj
		}
    }
}
elseif($response -eq "n"){
    Write-ToConsole "*********************************************"
    Write-ToConsole "Finializing STIG CKLs without remediating open items..."
    foreach($profile in $profiles){
        $remediateTable.add($profile,"Skipped")
    }
}

VulnID2StigID -ProfileTable $profileTable
ListOpenItems -KnownIDs $KnownIDs -ProfileTable $profileTable -remediateTable $remediateTable
MergeTemplate -ProfileTable $profileTable

# Change permission
# =============================================================================================  
$login = logname
chmod -R 755 /opt/stigtools/vsphere8/Reports/
chown -R $login /opt/stigtools/vsphere8/Reports/

# Calculate elapsed time in minutes and seconds
$elapsedTime = (Get-Date) - $startTime
$elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
$elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

Write-ToConsole ""
Write-ToConsole "$($vCenter_FQDN) - END SCRIPT"
Write-ToConsole "$($vCenter_FQDN) - Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"

Stop-Transcript
chmod -R 755 /opt/stigtools/vsphere8/transcript/
chown -R $login /opt/stigtools/vsphere8/transcript/
