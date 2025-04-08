<# 
#==========================================================================
# NAME: vSphere_ESXi_STIG.ps1, v6.0.0 (Parallel)
# AUTHOR: Peter Stearns
# UPDATED: 02/18/2025
# PROFILE: VMware_vSphere_8.0_ESXi_STIG_V2R2
# DESCRIPTION:
#    -This script runs the Inspec Profile against all ESXi in a VCSA
#    -Then calls Ansible and Powershell to fix open findings
#    -Outputs a STIG Viewer Checklist file per ESXi host
#==========================================================================

    Tested against
    -PowerCLI 12.6
    -Powershell 5/Core 7.2.6
    -vCenter/ESXi 8.0 U3

    Example command to run script
    .\VMware_vSphere_8.0_STIG_ESXi_Remediation.ps1 -vcenter vcentername.test.local -hostname myhost.test.local

    .PARAMETER vcenter
    Enter the FQDN or IP of the vCenter Server to connect to
    .PARAMETER hostname
    Enter the hostname of a single ESXi host to remediate
    .PARAMETER cluster
    Enter the cluster name of a vSphere cluster to remediate all hosts in a targeted cluster
    .PARAMETER vdi
    Enter yes, y, Yes if running against a VDI cluster. This will allow for MemPage Sharing
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$vcenter,
    [Parameter()]
    [string]$hostname,
    [Parameter()]
    [string]$cluster,
    [Parameter()]
    [ValidateSet("y","n")]
    [string]$vdi,
    [Parameter()]
    [string]$RunBy,
    [Parameter()]
    [object]$credObj,
    [Parameter()]
    [switch]$silent,
    [Parameter()]
    [switch]$skipFix
)

# Capture the start time
$startTime = Get-Date
Start-Transcript -path /opt/stigtools/vsphere8/transcript/ESXi.log -append -Force

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#/////////////////////DECLARE VARIABLES///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$workingdir = "/opt/stigtools/vsphere8"
$STIG_ver   = "VMW_VSPHERE_8-0_ESXi_V2R2"
$NAME       = "vSphere8_ESXi_STIG.ps1, v6.0.0 (Parallel)"
$UPDATED    = "02/18/2025"

$templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_ESXi_STIG_V2R2.ckl"


# ESXi Varibles
# ==================================================================
    
    $classification = "U"
    $MARKING        = "CUI"
    $esxiNtpServers = "192.168.100.100","192.168.100.14","192.168.100.11"
    $syslogServer   = 'udp://splunk:514'
    $esxAdminsGroup  = "VIADMINS"
    $allowedIPs     = "192.168.0.0/16","192.16.0.0/16","192.168.0.0/16"
    $esxiVer        = '24414501'
    $ExceptionUser  = 'svc.acas'
    $domainName     = 'site.dod.com'
    $CanonicalOU    = 'site.dod.com/z/y/x'
    $OU             = 'OU=x,OU=y,OU=z,DC=site,DC=dod,DC=com'

    $vMotionVlanId  = '950','920','930','940'
    $vsanVlanId     = '10'
    $mgtVlanId      = '0','10','20','30'
    $sslIssueOrg    = 'U.S. Government','godaddy'
    $nativeVLAN     = "1"
    $Scratch        = '[syslog] '
    $snmpEnabled    = $false

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////COMMENTS and MARKUPS//////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# ESXI-80-000199
# =============================================================================================
$ESX199 = @{
    VULN_ID = "ESXI-80-000199"

    COMMENT = '
All IP-Based Storage is configured on seperate VLANs per our standard configuration during inital setup.
Manually verifed the VLANs associated with each VMkernel that are used for IP-based storage traffic. Verified that they are dedicated for that purpose and are logically separated from other functions.'
    
    STATUS = "NotAFinding"
}

# ESXI-80-000145
# =============================================================================================
$ESX145 = @{
    VULN_ID = "ESXI-80-000145"

    COMMENT = '
There are no iSCSI HBAs present so this control is Not Applicable'
    
    STATUS = "Not_Applicable"
}

# ESXI-80-000224
# =============================================================================================
$ESX224 = @{
    VULN_ID = "ESXI-80-000224"

    COMMENT = '
SSL is not used for a syslog target, this is not applicable.'
    
    STATUS = "Not_Applicable"
}

# ESXI-80-000234
# =============================================================================================
$ESX234 = @{
    VULN_ID = "ESXI-80-000234"

    COMMENT = '
SSL is not used for a syslog target, this is not applicable.'
    
    STATUS = "Not_Applicable"
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////Known Open Items///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$KnownIssues = @($ESX199,$ESX145,$ESX224,$ESX234)
$KnownIDs   += $KnownIssues | ForEach-Object { $_.VULN_ID }

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////////////STIG Values//////////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
$stigsettings = [ordered]@{

    ##### Environment Specific STIG Values #####

    ExceptionUser           = $ExceptionUser                                           #ESXI-80-000201
    syslogHost              = @{"Syslog.global.logHost" = $syslogServer}               #ESXI-80-000114
    CanonicalOU             = $CanonicalOU                                             #ESXI-80-000049
    domainName              = $domainName                                              #ESXI-80-000049
    esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = $esxAdminsGroup} #ESXI-80-000241
    syslogScratch           = @{"Syslog.global.logDir" = "$($Scratch)scratch/log"}     #ESXI-80-000243
    syslogUnique            = @{"Syslog.global.logDirUnique" = "True"}                 #ESXI-80-000243
    esxiNtpServers          = $esxiNtpServers                                          #ESXI-80-000124
    allowedips              = $allowedIPs                                              #ESXI-80-000239 Allows IP ranges for the ESXi firewall
    esxiLatestBuild         = $esxiVer                                                 #ESXI-80-000221
    # nativeVLANid            = $nativeVLAN                                              #ESXI-70-000063
    
    ##### Default STIG Values #####

    lockdownlevel           = "lockdownNormal"                                         #ESXI-80-000008 Lockdown level: lockdownDisabled,lockdownNormal,lockdownStrict
    DCUIAccess              = @{"DCUI.Access" = "root"}                                #ESXI-80-000189
    accountLockFailures     = @{"Security.AccountLockFailures" = "3"}                  #ESXI-80-000005
    accountUnlockTime       = @{"Security.AccountUnlockTime" = "900"}                  #ESXI-80-000111
    syslogLogLevel          = @{"Syslog.global.logLevel" = "info"}                     #ESXI-80-000235
    logLevel                = @{"Config.HostAgent.log.level" = "info"}                 #ESXI-80-000015
    passwordComplexity      = @{"Security.PasswordQualityControl" = "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"} #ESXI-80-000035
    passwordHistory         = @{"Security.PasswordHistory" = "5"}                      #ESXI-80-000043
    enableMob               = @{"Config.HostAgent.plugins.solo.enableMob" = "False"}   #ESXI-80-000047
    sshEnabled              = $false                                                   #ESXI-80-000193
    shellEnabled            = $false                                                   #ESXI-80-000194
	sshIgnorerhosts         = @{"ignorerhosts" = "yes"} 							   #ESXI-80-000052
    shellIntTimeout         = @{"UserVars.ESXiShellInteractiveTimeOut" = "900"}        #ESXI-80-000068
    shellTimeout            = @{"UserVars.ESXiShellTimeOut" = "600"}                   #ESXI-80-000195
    DCUITImeout             = @{"UserVars.DcuiTimeOut" = "600"}                        #ESXI-80-000196
    vibacceptlevel          = "PartnerSupported"                                       #ESXI-80-000133 VIB Acceptance level CommunitySupported,PartnerSupported,VMwareAccepted,VMwareCertified
    snmpEnabled             = $false                                                   #ESXI-80-000212
    ShareForceSalting       = @{"Mem.ShareForceSalting" = "2"}                         #ESXI-80-000213
    ShareForceSaltingVDI    = @{"Mem.ShareForceSalting" = "0"}                         #ESXI-80-000213
    BlockGuestBPDU          = @{"Net.BlockGuestBPDU" = "1"}                            #ESXI-80-000215
    DVFilterBindIpAddress   = @{"Net.DVFilterBindIpAddress"= ""}                       #ESXI-80-000219
    sslProtocols            = @{"UserVars.ESXiVPsDisabledProtocols" = "sslv3,tlsv1,tlsv1.1"} #ESXI-80-000161
	sshCiphers              = @{"ciphers" = "aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr"} #ESXI-80-000192
	sshHostbasedauth        = @{"hostbasedauthentication" = "no"}                      #ESXI-80-000202
    sshPermituserenv        = @{"permituserenvironment" = "no"}                        #ESXI-80-000204
    sshGatewayports         = @{"gatewayports" = "no"}                                 #ESXI-80-000207
    sshPermittunnel         = @{"permittunnel" = "no"}                                 #ESXI-80-000209
    sshClientalivecountmax  = @{"clientalivecountmax" = "3"}                           #ESXI-80-000210
    sshClientaliveinterval  = @{"clientaliveinterval" = "200"}                         #ESXI-80-000211
    suppressShellWarning    = @{"UserVars.SuppressShellWarning" = "0"}                 #ESXI-80-000222
	sshAllowtcpforwarding   = @{"allowtcpforwarding" = "no"}                           #ESXI-80-000230
    sshBanner               = @{"banner" = "/etc/issue"}                               #ESXI-80-000187
	executeVibs             = @{"VMkernel.Boot.execInstalledOnly" = "true"}            #ESXI-80-000244
    suppressHyperWarning    = @{"UserVars.SuppressHyperthreadWarning" = "0"}           #ESXI-80-000223
	auditRecordStorageCap   = @{"Syslog.global.auditRecord.storageCapacity" = "100"}   #ESXI-80-000113
	syslogAuditEnable       = @{"Syslog.global.auditRecord.storageEnable" = $true}     #ESXI-80-000232
	syslogAuditRemote       = @{"Syslog.global.auditRecord.remoteEnable" = $true}      #ESXI-80-000233
	syslogCertStrict        = @{"Syslog.global.certificate.strictX509Compliance" = $true} #ESXI-80-000234
    slpdEnabled             = $false                                                   #ESXI-80-000231
    syslogCertCheck         = @{"Syslog.global.certificate.checkSSLCerts" = "true"}    #ESXI-80-000224
    memEagerZero            = @{"Mem.MemEagerZero" = "1"}                              #ESXI-80-000225
    apiTimeout              = @{"Config.HostAgent.vmacore.soap.sessionTimeout" = "30"} #ESXI-80-000226
    hostClientTimeout       = @{"UserVars.HostClientSessionTimeout"       = "900"}     #ESXI-80-000010
    passwordMaxAge          = @{"Security.PasswordMaxDays"                = "90"}      #ESXI-80-000227
    cimEnabled              = $false                                                   #ESXI-80-000228
	tlsServerProfile        = "NIST_2024" 											   #ESXI-80-000247
	bmcNetworkEnable        = @{"Net.BMCNetworkEnable" = 0}                            #ESXI-80-000250
    ConfigEtcIssue          = @{"Config.Etc.issue" = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential.  See  User Agreement for details.'}
    AnnotationsMessage      = @{"Annotations.WelcomeMessage" = "
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{hostname} , {ip}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{esxproduct} {esxversion}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:yellow}{memory} RAM{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:black}{color:white}        {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By      {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  using this IS (which includes any device attached to this IS), you consent to the following conditions:                 {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -       The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited     {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law      {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          enforcement (LE), and counterintelligence (CI) investigations.                                                  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -       At any time, the USG may inspect and seize data stored on this IS.                                              {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -       Communications using, or data stored on, this IS are not private, are subject to routine monitoring,            {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          interception, and search, and may be disclosed or used for any USG-authorized purpose.                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -       This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not     {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          for your personal benefit or privacy.                                                                           {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}  -       Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching    {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          or monitoring of the content of privileged communications, or work product, related to personal representation  {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work       {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}          product are private and confidential. See User Agreement for details.                                           {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{align:left}{bgcolor:yellow}{color:black}                                                                                                                          {/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
{bgcolor:black} {/color}{align:left}{bgcolor:dark-grey}{color:white}  <F2> Accept Conditions and Customize System / View Logs{/align}{align:right}<F12> Accept Conditions and Shut Down/Restart  {bgcolor:black} {/color}{/color}{/bgcolor}{/align}
{bgcolor:black} {/color}{bgcolor:dark-grey}{color:black}                                                                                                                          {/color}{/bgcolor}
"}
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////////// INTIALIZE ENVIRONMENT ///////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Write-Host "
#==========================================================================
# NAME: $NAME
# AUTHOR: Peter Stearns
# UPDATED: $UPDATED
# PROFILE: $($STIG_ver)
# DESCRIPTION: Runs Inspec and Ansible to STIG ESXI
# WORKING DIR: $($workingdir)
#=========================================================================="

# Intialize Varibles
# =============================================================================================
if($vcenter){$vCenter_FQDN = "$($vcenter)"}
if($hostname -or $cluster){$SUBTARGET = "$($hostname)$($cluster)"}
if($vdi -eq "y"){
   $VDISet = "Page Sharing Allowed For VDI"
}else{$VDISet = "NON-VDI Cluster - Page Sharing not allowed"}

# Prompt Varibles
# =============================================================================================
if(!$vCenter_FQDN){
    $msgvCenter = "Enter vCenter FQDN"
    do {
        $vCenter_FQDN  = Read-Host $msgvCenter
        $splitName     = $vCenter_FQDN.split(".") 
        $connection    = Test-Connection -ComputerName $vCenter_FQDN -Count 1 -Quiet
    }
    until ($vCenter_FQDN -ne $null -and $vCenter_FQDN -ne "" -and $splitName[1] -ne $null -and $connection -eq "True")
}

if($credObj){
    $vcsaAdmnCred = $credObj.vcsaAdmnCred
    $vcsaRootCred = $credObj.vcsaRootCred
    $esxiRootCred = $credObj.esxiRootCred
}

if(!$vcsaAdmnCred){ $vcsaAdmnCred = Get-Credential -Message "Enter administrator@vsphere Creds:"  }
if(!$esxiRootCred){ $esxiRootCred = Get-Credential -Message "Enter ESXi Username and password:"}
if(!$RunBy){ $RunBy = Read-Host -Prompt "Enter your full name" }
#$domainCred   = Get-Credential -Message "Enter Domain Creds:"

# Import ESXi Remediation Module
Import-Module "$($workingdir)/ESXi_STIG_Module/vmware-esxi-8.0-stig-module.ps1" -DisableNameChecking -force

If($global:DefaultVIServer -or $global:DefaultVIServers) {
    Disconnect-VIServer * -Confirm:$false
}

# Get Current Date and Time
$date = Get-Date
$dateStr = (Get-Date -Format "yyyMMdd")

# Environment Variables
$splitName      = $vCenter_FQDN.split(".")
$VCSAshortname  = $splitName[0].ToUpper()

$ENV:RUBYOPT    = 'rubygems'
$ENV:RUBY_DIR   = '/opt/cinc-auditor/embedded'
$ENV:GEM_PATH   = '/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems'
$ENV:PATH       = '/opt/cinc-auditor/embedded/bin;' + $ENV:PATH
$ENV:NO_COLOR   = $true

$ENV:VISERVER          = $vCenter_FQDN
$ENV:VISERVER_USERNAME = $vcsaAdmnCred.UserName
$ENV:VISERVER_PASSWORD = $vcsaAdmnCred.GetNetworkCredential().password

$inspecPath     = "$($workingdir)/dod-compliance-and-automation-master/vsphere/8.0/v2r2-stig/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/esxi/"
$inspecEsxSSH   = "$($workingdir)/ESXi_STIG_Module/vmware-esxi-8.0-stig-inspec/esxi-ssh/"
$VulnID_mapper  = "$($workingdir)/VulnID_mapper8.csv"
$reportPath     = "$($workingdir)/Reports/" + $VCSAshortname + "/ESXi"
$csvPath        = "$($workingdir)/Reports/" + $VCSAshortname + "/Open_ESXi_STIGs_Report.csv"

$hostCklTable   = [ordered]@{}
$hostCklTable   = [System.Collections.Hashtable]::Synchronized($hostCklTable)
$esxiResultTable = [ordered]@{}
$esxiResultTable = [System.Collections.Hashtable]::Synchronized($esxiResultTable)

$FinalItems     = @('ESXI-80-000194','ESXI-80-000193','ESXI-80-000008','ESXI-80-000227')
$controls       = cinc-auditor export $inspecPath | where-object {$_ -like "*- ESXI-80-00*"} | ForEach-Object {$_ -Replace "  -" -replace ' ',''}
$SSHItems       = cinc-auditor export $inspecEsxSSH | where-object {$_ -like "*- ESXI-80-00*"} | ForEach-Object {$_ -Replace "  -" -replace ' ',''}
$ESXItems       = Compare-Object $controls $SSHItems -includeEqual -passthru | where-object {$_.SideIndicator -eq '<='}

$ansiblePlaybook = "$($workingdir)/ESXi_STIG_Module/vmware-esxi-8.0-stig-ansible/playbook.yml"
$RemediateTable  = [ordered]@{}
$OpenReport = [ordered]@{}

$NameDateTag = "

Automated checks run by: $RunBy on $(date +%F)"

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#///////////////////////////// FUNCTIONS ////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
if(!$silent){
    Function Write-ToConsole ($Details) {
	    $LogDate = Get-Date -Format T
	    Write-Host "$($LogDate) $Details"
    }
}Else{Function Write-ToConsole ($Details) { write-host . -NoNewline}}
    
Function EnableAccess () {
    param(
        [object]$vmhost
    )
    # Disable Lockdown and Enable SSH and ESXi Password Age
    $vmhostv = $vmhost | Get-View 
    $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
    If($vmhostv.config.LockdownMode -ne 'lockdownDisabled'){$lockdown.ChangeLockdownMode('lockdownDisabled')}
    $PasswordAge = $vmhost | Get-AdvancedSetting -Name Security.PasswordMaxDays
    If($PasswordAge -ne '99999'){$vmhost | Get-AdvancedSetting -Name Security.PasswordMaxDays | Set-AdvancedSetting -Value 99999 -Confirm:$false | out-null}
    $PasswordHistory = $vmhost | Get-AdvancedSetting -Name Security.PasswordHistory
    If($PasswordHistory -ne '0'){$vmhost | Get-AdvancedSetting -Name Security.PasswordHistory | Set-AdvancedSetting -Value 0 -Confirm:$false | out-null}
    $vmhost | Foreach {Start-VMHostService -Confirm:$false -HostService ($_ | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"} )} | out-null

}

Function DisableAccess () {
    param(
        [object]$vmhost
    )
    # Enable Lockdown and Disable SSH and ESXi Password Age
    $vmhostv = $vmhost | Get-View 
    $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
    If($vmhostv.config.LockdownMode -ne 'lockdownNormal'){$lockdown.ChangeLockdownMode('lockdownNormal')}
    $PasswordAge = $vmhost | Get-AdvancedSetting -Name Security.PasswordMaxDays
    If($PasswordAge -ne '90'){$vmhost | Get-AdvancedSetting -Name Security.PasswordMaxDays | Set-AdvancedSetting -Value 90 -Confirm:$false | out-null}
    $PasswordHistory = $vmhost | Get-AdvancedSetting -Name Security.PasswordHistory
    If($PasswordHistory -ne '5'){$vmhost | Get-AdvancedSetting -Name Security.PasswordHistory | Set-AdvancedSetting -Value 5 -Confirm:$false | out-null}
    $vmhost | Foreach {Stop-VMHostService -Confirm:$false -HostService ($_ | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"} )} | out-null
}

Function InspecESXi () {
    param (
        [object]$vmhost,
        [hashtable]$esxiResultTable,
        [object]$variableObj,
        [string]$VCSAshortname
    )

    # Functions
    ${function:Write-ToConsole} = $variableObj.WriteToConsole
    ${function:EnableAccess}    = $variableObj.EnableAccess
    ${function:DisableAccess}   = $variableObj.DisableAccess

    # STIG Varibles
    $MARKING        = $variableObj.MARKING
    $ExceptionUser  = $variableObj.ExceptionUser
    $sslIssueOrg    = $variableObj.sslIssueOrg 
    $snmpEnabled    = $variableObj.snmpEnabled
    $syslogServer   = $variableObj.syslogServer
    $esxAdminsGroup = $variableObj.esxAdminsGroup
    $esxiNtpServers = $variableObj.esxiNtpServers
    $vMotionVlanId  = $variableObj.vMotionVlanId
    $mgtVlanId      = $variableObj.mgtVlanId
    $vsanVlanId     = $variableObj.vsanVlanId
    $esxiVer        = $variableObj.esxiVer
    $esxiUsername   = $variableObj.esxiRootCred.UserName
    $templateCklFile = $variableObj.templateCklFile

    # Setup for each ESXi Host
    # =============================================================================================
    if(!($vmhost -as [ipaddress])){
         $splitName        = $vmhost.Name.split(".")
         $shortName        = $splitName[0].ToUpper()   
    }else{
         $shortName        = $vmhost
    }
	
	$sshReportFile    = $variableObj.reportPath + '/' + $shortName + '_' + $variableObj.classification + '_VMware_vSphere_8.0_STIG_ESXi_Inspec_Report_' + $variableObj.dateStr + '_SSH.json'
    $vmwarereportFile = $variableObj.reportPath + '/' + $shortName + '_' + $variableObj.classification + '_VMware_vSphere_8.0_STIG_ESXi_Inspec_Report_' + $variableObj.dateStr + '_VMWARE.json'
	$sshCklFile       = $variableObj.reportPath + '/' + $shortName + '_' + $variableObj.classification + '_' + $variableObj.STIG_ver + '_' + $variableObj.dateStr + '_SSH.ckl'
    $cklFile          = $variableObj.reportPath + '/' + $shortName + '_' + $variableObj.classification + '_' + $variableObj.STIG_ver + '_' + $variableObj.dateStr + '.ckl'

    Start-Sleep -MilliSeconds (Get-Random -Minimum 2000 -Maximum 7000)
    
    # Reconnect to vCenter for parallel instance
    Connect-VIServer -Server $variableObj.vCenter_FQDN -Session $variableObj.SessionID -ErrorAction SilentlyContinue | Out-Null

    #Get management IP for CKL report
    $mgmtip = Get-VMHostNetworkAdapter -VMHost $vmhost | Where-Object {$_.Name -eq "vmk0"} | Select-Object -ExpandProperty IP
    #Get management MAC Address for CKL report
    $mgmtmac = Get-VMHostNetworkAdapter -VMHost $vmhost | Where-Object {$_.Name -eq "vmk0"} | Select-Object -ExpandProperty Mac

    if($sshReportFile){Remove-Item -Path $sshReportFile -erroraction 'silentlycontinue'}
    if($vmwarereportFile){Remove-Item -Path $vmwarereportFile -erroraction 'silentlycontinue'}
	
	# Enable Access by Disable Lockdown and Enable SSH and ESXi Password Age
    # =============================================================================================
    Try{EnableAccess -vmhost $vmhost}
    catch{Write-Error "Failed to Enable access to $($vmhost)... $_.Exception"}
	
	# INSPEC ESXi Host SSH transport
    # =============================================================================================
    Write-ToConsole "$($VCSAshortname) - Running SSH Inspec items on $($vmhost)..."
    if(!$variableObj.silent){
        cinc-auditor exec $variableObj.inspecEsxSSH -t ssh://$esxiUsername@$vmhost --password $variableObj.esxiRootCred.GetNetworkCredential().password --reporter json:$sshReportFile | Out-Null
    }else{
        cinc-auditor exec $variableObj.inspecEsxSSH -t ssh://$esxiUsername@$vmhost --password $variableObj.esxiRootCred.GetNetworkCredential().password --reporter json:$sshReportFile | Out-Null
    }

    # Closing Final STIG Items before check
    # =============================================================================================
    DisableAccess -vmhost $vmhost
    Start-Sleep -MilliSeconds 3000

    # INSPEC ESXi Host VMware transport
    # =============================================================================================
    Write-ToConsole "$($VCSAshortname) - Running CLI Inspec items on $($vmhost)..."
    if(!$variableObj.silent){
        cinc-auditor exec $variableObj.inspecPath -t vmware:// --input vmhostName=$vmhost exceptionUsers=$ExceptionUser sslIssueOrg=$sslIssueOrg snmpEnabled=$snmpEnabled syslogServer=$syslogServer adAdminGroup=$esxAdminsGroup esxiNtpServers=$esxiNtpServers vMotionVlanId=$vMotionVlanId mgtVlanId=$mgtVlanId vsanVlanId=$vsanVlanId esxiBuildNumber=$esxiVer --reporter json:$vmwarereportFile | Out-Null
    }else{
        cinc-auditor exec $variableObj.inspecPath -t vmware:// --input vmhostName=$vmhost exceptionUsers=$ExceptionUser sslIssueOrg=$sslIssueOrg snmpEnabled=$snmpEnabled syslogServer=$syslogServer adAdminGroup=$esxAdminsGroup esxiNtpServers=$esxiNtpServers vMotionVlanId=$vMotionVlanId mgtVlanId=$mgtVlanId vsanVlanId=$vsanVlanId esxiBuildNumber=$esxiVer --reporter json:$vmwarereportFile | Out-Null
    }

    # Create CKL Files
    # =============================================================================================
    Write-ToConsole "$($VCSAshortname) - Generating checklist for $($vmhost)..."  
    # Convert Report to CKL
    Write-ToConsole "$($VCSAshortname) - Creating CKL for $($vmhost)..."
    inspec_tools inspec2ckl -j $vmwarereportFile -o $cklFile
	inspec_tools inspec2ckl -j $sshReportFile -o $sshCklFile 

    # Create XML objects, Merge SSH CKL to STIG CKL, Tag Name & Date, and update CKL file
    # =============================================================================================
    Try{
        $xmlCkl = ( Select-Xml -Path $cklFile -XPath / ).Node
		$sshXmlCkl = ( Select-Xml -Path $sshCklFile -XPath / ).Node
    }Catch{Write-Error "Failed to import CKL.."}
	
	# Merge SSH CKL ITEMs with STIG CKL
    # =============================================================================================
    try{
        $sshXmlCkl.CHECKLIST.STIGS.iSTIG.VULN |  ForEach-Object {
            $sshVulnID       = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Vuln_Num"}).ATTRIBUTE_DATA
            $sshVulnSTATUS   = $_.STATUS
            $sshVulnFindDet  = $_.FINDING_DETAILS

            $cklNode         = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $sshVulnID }
            $cklNode.STATUS            = $sshVulnSTATUS
            $cklNode.FINDING_DETAILS   = $sshVulnFindDet
        }
    }Catch{Write-Error "Failed to merge CKLs for $($vmhost)... $_.Exception"}

    # Find and Markup Known Issues
    # =============================================================================================
    foreach ($KnownID in $variableObj.KnownIDs){
        $Vuln_Node          = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $KnownID }
        $Vuln_Object        = $variableObj.KnownIssues | where-object VULN_ID -contains $KnownID
        if (($Vuln_Node.STATUS -eq "Not_Reviewed") -or ($Vuln_Node.STATUS -eq "NotAFinding") -or ($Vuln_Node.STATUS -eq "Open")){
            $Vuln_Node.COMMENTS = $Vuln_Object.COMMENT
            $Vuln_Node.STATUS   = $Vuln_Object.STATUS
        }
    }

    # Add Name and Date to comments
    # =============================================================================================
    $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | ForEach-Object {
        $CommentValue = $_.COMMENTS
        $_.COMMENTS = $CommentValue + $variableObj.NameDateTag
    }

    # Update CKL FILE With ASSET Info
    # =============================================================================================
    $xmlCkl.CHECKLIST.ASSET.ROLE            = "Member Server"
    $xmlCkl.CHECKLIST.ASSET.ASSET_TYPE      = "Computing"
    # $xmlCkl.CHECKLIST.ASSET.MARKING         = $MARKING
    $xmlCkl.CHECKLIST.ASSET.HOST_NAME       = $shortName
    $xmlCkl.CHECKLIST.ASSET.HOST_IP         = $mgmtip
    $xmlCkl.CHECKLIST.ASSET.HOST_MAC        = $mgmtmac
    $xmlCkl.CHECKLIST.ASSET.HOST_FQDN       = $vmhost
    $xmlCkl.CHECKLIST.ASSET.WEB_OR_DATABASE = "false"

    # Save XML data to CKL file
    # =============================================================================================
    Write-ToConsole "$($VCSAshortname) - Saving Checklist for $($vmhost)..."
    $xmlCkl.Save($cklFile)

    # CleanUp
    # =============================================================================================
	if($sshReportFile){Remove-Item -Path $sshReportFile -erroraction 'silentlycontinue'}
    if($sshCklFile){Remove-Item -Path $sshCklFile -erroraction 'silentlycontinue'}
    if($vmwarereportFile){Remove-Item -Path $vmwarereportFile -erroraction 'silentlycontinue'}
     
    if($cklFile){
        $variableObj.hostCklTable.add($vmhost,$cklFile)
    }else{Write-Error "Failed to run Inspec profile against $($vmhost)... $_.Exception"}

    # Create List Open Items
    # =============================================================================================    
    $OpenItems = @()
    $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
        $RuleID = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Rule_Ver"}).ATTRIBUTE_DATA
        $OpenItems += $RuleID
        if($RuleID -in $KnownIDs){$Known = "True"}
        else {$Known = "False"}
    }
    $esxiResultTable.add($($vmhost),$OpenItems)
}

Function RemediateItem () {
    param(
	    [object]$SSHItems,
        [array]$OpenItems,
        [object]$vmhost,
        [array]$xmlCkl
    )
	
    $esxiUsername   = $esxiRootCred.UserName

    # Test for Ansible and ESXi Stig Playbook
    CheckAnsible

    # Create subsets for remediation
	$SSHFixItems = Compare-Object $OpenItems $SSHItems -IncludeEqual -PassThru | where-object {$_.SideIndicator -eq '=='}
    $FixItems = Compare-Object $OpenItems $FinalItems -includeEqual -passthru | where-object {$_.SideIndicator -eq '<='}
	$FixItems = Compare-Object $FixItems $SSHItems -includeEqual -passthru | where-object {$_.SideIndicator -eq '<='}
	
	if($SSHFixItems){
        # Enable Access by Disable Lockdown and Enable SSH and ESXi Password Age
        try{EnableAccess -vmhost $vmhost}
        catch{Write-Error "Failed to Enable access to $($vmhost)... $_.Exception"}
         
        # Run Ansible SSH STIG Items
        # =============================================================================================
        if($ansible -ne "NotInstalled"){
            $SSHFixItemsString = $SSHFixItems -join ","
            ansible-playbook -i "$vmhost," -u $esxiUsername $ansiblePlaybook --tags $SSHFixItemsString -e "ansible_ssh_pass=$($esxiRootCred.GetNetworkCredential().password)"    
        }
    
        # Running Inspec to Verify SSH Items
        # =============================================================================================
        Write-ToConsole "Re-Generating SSH STIG Checklist for $($vmhost)"
        cinc-auditor exec $inspecEsxSSH -t ssh://$esxiUsername@$vmhost --password $esxiRootCred.GetNetworkCredential().password --show-progress --reporter json:$fixsshReportFile --controls $SSHFixItems | Out-Null
        inspec_tools inspec2ckl -j $fixsshReportFile -o $fixsshCklFile
    }

    # Running Powershell STIG items
    # =============================================================================================
    foreach ($FixItem in $FixItems){
        try{
            if(($FixItem -eq "ESXI-80-000094") -or ($FixItem -eq "ESXI-80-000238") -or ($FixItem -eq "ESXI-80-000085")){
                $msg = "$(Get-Date -Format T) Do you want to remediate SECURE BOOT $($FixItem) settings? [y/n]"
                do {$fix = Read-Host -Prompt $msg
                }until ($fix -eq "y" -or $fix -eq "n")
                if ($fix -eq "y"){ & $FixItem $vmhost $stigsettings }
            }
            elseif($FixItem -eq "ESXI-80-000239"){
                #Write-ToConsole "Skipping Firewall settings"
                $msg = "$(Get-Date -Format T) Do you want to remediate FIREWALL settings? [y/n]"
                do {$fix = Read-Host -Prompt $msg
				}until ($fix -eq "y" -or $fix -eq "n")
				if ($fix -eq "y"){ & $FixItem $vmhost $stigsettings }
            }
            else{ & $FixItem $vmhost $stigsettings }

        }catch{Write-Error "Failed remediate $($FixItem) on $($vmhost)... $_.Exception"}
    }

    # Enable Access by Disable Lockdown and Enable SSH and ESXi Password Age
    try{DisableAccess -vmhost $vmhost}
    catch{Write-Error "Failed to Enable access to $($vmhost)... $_.Exception"}

    # Running Inspec to Verify Powershell Items
    # =============================================================================================
    Write-ToConsole "Re-Generating STIG Checklist for $($vmhost)"
    cinc-auditor exec $inspecPath -t vmware:// --input vmhostName=$vmhost exceptionUsers=$ExceptionUser sslIssueOrg=$sslIssueOrg snmpEnabled=$snmpEnabled syslogServer=$syslogServer adAdminGroup=$esxAdminsGroup esxiNtpServers=$esxiNtpServers vMotionVlanId=$vMotionVlanId mgtVlanId=$mgtVlanId vsanVlanId=$vsanVlanId esxiBuildNumber=$esxiVer --show-progress --reporter json:$fixreportFile --controls $FixItems | Out-Null
    inspec_tools inspec2ckl -j $fixreportFile -o $FixCklFile

    # Updating CKL with fixed items
    # =============================================================================================
    Write-ToConsole "Updating STIG Checklist with fixed items..."
    $xmlFixCkl = ( Select-Xml -Path $FixCklFile -XPath / ).Node
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
	
	if($SSHFixItems){
		$xmlsshFixCkl = ( Select-Xml -Path $fixsshCklFile -XPath / ).Node
		$xmlsshFixCkl.CHECKLIST.STIGS.iSTIG.VULN | ForEach-Object {
			$CommentValue = $_.COMMENTS
			$_.COMMENTS = $CommentValue + $NameDateTag
		}
		foreach ($SSHFixItem in $SSHFixItems){
			$SSH_Fix_Node                = $xmlsshFixCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $SSHFixItem }
			$xmlCkl_Node                 = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $SSHFixItem }
			$xmlCkl_Node.STATUS          = $SSH_Fix_Node.STATUS
			$xmlCkl_Node.COMMENTS        = $SSH_Fix_Node.COMMENTS
			$xmlCkl_Node.FINDING_DETAILS = $SSH_Fix_Node.FINDING_DETAILS
		}
	}

    # Save XML data to CKL file
    # =============================================================================================
    Write-ToConsole "Saving File..."
    $xmlCkl.Save($cklFile)
}

Function VulnID2StigID () {
    param(
        [hashtable]$hostCklTable
    )
    # Replace update VULN_ID with proper ID
    # =============================================================================================
    if ($hostCklTable){
        $VulnIDTable = @{}
        Import-CSV $($VulnID_mapper) | % { $VulnIDTable[$_.STIGID] = $_.VulnID }
        $hostCklTable.keys | ForEach-Object {
            $vmhost = $_
            $cklFile = $hostCklTable[$_]
            $xmlCkl = ( Select-Xml -Path $cklFile -XPath / ).Node
            $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Vuln_Num"} | ForEach-Object {
                $NodeID = $_.ATTRIBUTE_DATA
                $Vuln_ID = $VulnIDTable.Item($NodeID)
                if($Vuln_ID){
	                $_.ATTRIBUTE_DATA = $Vuln_ID
                }
            }
            # Save XML data to CKL file
            $xmlCkl.Save($cklFile)
        }
    }
}

Function ListOpenItems () {
    param(
        [array]$KnownIDs,
        [hashtable]$hostCklTable,
        [hashtable]$RemediateTable
    )
    # List Open Items
    # =============================================================================================
    if ($hostCklTable){
        $summary = @()
        $hostCklTable.keys | ForEach-Object {
            $vmhost = $_
            $remediated = $RemediateTable[$vmhost]
            $cklFile = $hostCklTable[$_]
            $xmlCkl = ( Select-Xml -Path $cklFile -XPath / ).Node
            $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
				$RuleID = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Rule_Ver"}).ATTRIBUTE_DATA
				$VulnID = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Vuln_Num"}).ATTRIBUTE_DATA
				#$OpenItems += $RuleID.ATTRIBUTE_DATA
				if($RuleID -in $KnownIDs){$Known = "True"}
                else {$Known = "False"}
                $obj = New-Object -TypeName PSObject
                $obj | Add-Member -MemberType NoteProperty -Name Date -Value (Get-Date -format "dd-MMM-yyyy HH:mm")
	            $obj | Add-Member -MemberType NoteProperty -Name Host -Value $vmhost 
	            $obj | Add-Member -MemberType NoteProperty -Name VulnID -Value $VulnID
	            $obj | Add-Member -MemberType NoteProperty -Name STIGID -Value $RuleID
                $obj | Add-Member -MemberType NoteProperty -Name Known -value $Known
                $obj | Add-Member -MemberType NoteProperty -Name Remediated -value $remediated
                $summary += $obj
            }
        }
        Write-ToConsole "*********************************************"
        Write-ToConsole "               SUMMARY                       "
        Write-ToConsole "*********************************************"
        Write-Host ($summary | Sort-Object Host | Format-Table | Out-String)
        $summary | Export-Csv $csvPath -Append -Force -NoTypeInformation
    }
}

Function MergeTemplate () {  
    param(
        [hashtable]$hostCklTable,
	[string]$templateCklFile
    )
    $templateXmlCkl = ( Select-Xml -Path $templateCklFile -XPath / ).Node

    # Merge CKL to Template
    # =============================================================================================
    if ($hostCklTable){
        $hostCklTable.keys | ForEach-Object {
            $vmhost = $_
            $cklFile = $hostCklTable[$_]
            $finalCklFile = $hostCklTable[$_]
            $xmlCkl = ( Select-Xml -Path $cklFile -XPath / ).Node
         
            # Merge Assest info to template
            # =============================================================================================
            $templateXmlCkl.CHECKLIST.ASSET.ROLE            = $xmlCkl.CHECKLIST.ASSET.ROLE
            $templateXmlCkl.CHECKLIST.ASSET.ASSET_TYPE      = $xmlCkl.CHECKLIST.ASSET.ASSET_TYPE
            $templateXmlCkl.CHECKLIST.ASSET.MARKING         = $MARKING
            $templateXmlCkl.CHECKLIST.ASSET.HOST_NAME       = $xmlCkl.CHECKLIST.ASSET.HOST_NAME
            $templateXmlCkl.CHECKLIST.ASSET.HOST_IP         = $xmlCkl.CHECKLIST.ASSET.HOST_IP
            $templateXmlCkl.CHECKLIST.ASSET.HOST_MAC        = $xmlCkl.CHECKLIST.ASSET.HOST_MAC
            $templateXmlCkl.CHECKLIST.ASSET.HOST_FQDN       = $xmlCkl.CHECKLIST.ASSET.HOST_FQDN
            $templateXmlCkl.CHECKLIST.ASSET.WEB_OR_DATABASE = $xmlCkl.CHECKLIST.ASSET.WEB_OR_DATABASE

            # Merge VULN Details info to template
            # =============================================================================================
            try{
                $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN |  ForEach-Object {  
                    $xmlVulnID       = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Vuln_Num"}).ATTRIBUTE_DATA
                    $xmlVulnSTATUS   = $_.STATUS
                    $xmlVulnFindDet  = $_.FINDING_DETAILS
                    $xmlVulnCOMMENTS = $_.COMMENTS

                    $templateCklNode = $templateXmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $xmlVulnID }
                    $templateCklNode.STATUS           = $xmlVulnSTATUS
                    $templateCklNode.FINDING_DETAILS  = $xmlVulnFindDet
                    $templateCklNode.COMMENTS         = $xmlVulnCOMMENTS
                }
            }Catch{Write-Error "Failed to merge into Template CKL for $($vmhost)... $_.Exception"}

            # Save XML data to CKL file
            # =============================================================================================
            $tempCklFile = $reportPath + '/' + 'temp_' + $vmhost + '.ckl'
            Move-Item -Path $cklFile $tempCklFile -Force

            $templateXmlCkl.Save($finalCklFile)
            if($tempCklFile){Remove-Item -Path $tempCklFile -erroraction 'silentlycontinue'}
        }
    }
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////////////// INSPEC SCRIPT ////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Connect to vCenter
# =============================================================================================
Connect-VIServer -Server $vCenter_FQDN -Credential $vcsaAdmnCred -ErrorAction SilentlyContinue | Out-Null
$SessionId = $global:DefaultVIServer.SessionId

get-vmhost | foreach-object {   
    # Enable Root SSH No longer a STIG
    $esxcli = Get-EsxCli -v2 -VMhost $_
    $arguments = $esxcli.system.ssh.server.config.set.CreateArgs()
    $arguments.value = 'yes'
    $arguments.keyword = 'permitrootlogin'
    $esxcli.system.ssh.server.config.set.Invoke($arguments) | out-null
}

Try{
    If($hostname){
        $vmhosts = Get-VMHost -Name $hostname -ErrorAction Stop | Sort-Object Name
    }ElseIf($cluster){
        $vmhosts = Get-Cluster -Name $cluster -ErrorAction Stop | Get-VMHost -ErrorAction Stop | Sort-Object Name
    }Else{
        $vmhosts = Get-VMHost -ErrorAction Stop | Sort-Object Name
    }
}
Catch{
    Write-ToConsole "$($VCSAshortname) - Failed to gather information on target hosts in $($vCenter_FQDN)"
    Write-ToConsole $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $($vCenter_FQDN)"
    Disconnect-VIServer -Server $($vCenter_FQDN) -Force -Confirm:$false
    Exit -1
}

# Verify report folder
# =============================================================================================
If(Test-Path -Path $reportPath){
    Write-ToConsole "$($VCSAshortname) - Validated path for report at $reportPath"
}Else{
    Write-ToConsole "$($VCSAshortname) - Report path $reportPath doesn't exist...attempting to create..."
    New-Item -ItemType Directory -Path $reportPath -Force
}

# Run Inspec on each host on target
# =============================================================================================
Write-ToConsole "$($VCSAshortname) - Running Inspec $($STIG_ver) Profile" -ForegroundColor Yellow
Write-ToConsole ""

$WriteToConsole = ${Function:Write-ToConsole}.ToString()
$EnableAccess   = ${Function:EnableAccess}.ToString()
$DisableAccess  = ${Function:DisableAccess}.ToString()
$InspecESXi     = ${Function:InspecESXi}.ToString()

$variableObj = [PSCustomObject]@{
  
    # Functions
    WriteToConsole = [string]$WriteToConsole
    EnableAccess   = [string]$EnableAccess
    DisableAccess  = [string]$DisableAccess
    
    # Varibles
    reportPath      = [string]$reportPath
    classification  = [string]$classification
    dateStr         = [string]$dateStr
    STIG_ver        = [string]$STIG_ver
    templateCklFile = [string]$templateCklFile
    MARKING       = [string]$MARKING
    VulnID_mapper = [string]$VulnID_mapper
    vCenter_FQDN  = [string]$vCenter_FQDN
    SessionID     = [string]$SessionID
    esxiRootCred  = [PSCredential]$esxiRootCred
    vcsaAdmnCred  = [PSCredential]$vcsaAdmnCred
    inspecEsxSSH  = [string]$inspecEsxSSH
    inspecPath    = [string]$inspecPath
    hostCklTable  = [hashtable]$hostCklTable
    NameDateTag   = [string]$NameDateTag
    KnownIDs      = [array]$KnownIDs
    KnownIssues   = [array]$KnownIssues
    silent        = [switch]$silent

    # STIG Varibles
    ExceptionUser  = [array]$ExceptionUser
    sslIssueOrg    = [array]$sslIssueOrg 
    snmpEnabled    = [boolean]$snmpEnabled
    syslogServer   = [array]$syslogServer
    esxAdminsGroup = [string]$esxAdminsGroup
    esxiNtpServers = [array]$esxiNtpServers
    vMotionVlanId  = [array]$vMotionVlanId
    mgtVlanId      = [array]$mgtVlanId
    vsanVlanId     = [array]$vsanVlanId
    esxiVer        = [string]$esxiVer
    
}
   
$vmhosts | Foreach-Object -ThrottleLimit 10 -Parallel {

    ${function:InspecESXi} = $using:InspecESXi
    InspecESXi -vmhost $_ -variableObj $using:variableObj -esxiResultTable $using:esxiResultTable -VCSAshortname $using:VCSAshortname
}

$FormatEnumerationLimit=-1
Write-ToConsole " "
Write-ToConsole "$($VCSAshortname) - OPENS: "
foreach ($r in $esxiResultTable.GetEnumerator() ) {
    Write-Host "$($r.Name) : `t$($r.Value)"
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#/////////////////////// REMEDIATION OPEN ITEMS //////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Remediate
# =============================================================================================
if ($hostCklTable -and (!$skipFix)){
    $silent = $null
    Write-ToConsole
    Write-ToConsole "*********************************************"
    Write-ToConsole "Starting Remediation Process..."
    Write-ToConsole "*********************************************"

    $hostCklTable.keys | Sort-Object | ForEach-Object {
        $vmhost             = $_
        $cklFile            = $hostCklTable[$_]
        $fixreportFile      = $reportPath + "/" + "FIX_" + $shortName + "_" + $classification + "_" + $STIG_ver + "_" + $dateStr + ".json"
        $fixCklFile         = $reportPath + "/" + "FIX_" + $shortName + "_" + $classification + "_" + $STIG_ver + "_" + $dateStr + ".ckl"
		$fixsshReportFile   = $reportPath + "/" + "FIX_SSH_" + $shortName + "_" + $classification + "_" + $STIG_ver + "_" + $dateStr + ".json"
        $fixsshCklFile      = $reportPath + "/" + "FIX_SSH_" + $shortName + "_" + $classification + "_" + $STIG_ver + "_" + $dateStr + ".ckl"
    
        Try{
            $xmlCkl = ( Select-Xml -Path $cklFile -XPath / ).Node
        }
        Catch{
            Write-Error "Failed to import $($vmhost) CKL to remediate.. $_.Exception"
        }

        # Find all OPEN ITEMS compare to known issues
        # =============================================================================================
        $AllOpenItems = @()
        $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
	    $RuleID = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Rule_Ver"}).ATTRIBUTE_DATA
            $AllOpenItems += $RuleID
        }
        if($KnownIDs){
            $OpenItems = Compare-Object $AllOpenItems $KnownIDs -includeEqual -passthru | where-object {$_.SideIndicator -eq '<='}
        }else{
            $OpenItems = $AllOpenItems
        }
        if($OpenItems){
            Write-ToConsole " "
            Write-ToConsole "The Following Items will need to Remediated on $($vmhost): "
            Write-ToConsole $OpenItems

            #$msg = "$(Get-Date -Format T) Run ESX STIG to remediate items on $($vmhost)? [y/n]"
            #do {$response = Read-Host -Prompt $msg
            #}until ($response -eq "y" -or $response -eq "n")
            $response = "y"
            
            if (($vmhost.ConnectionState -ne "Maintenance") -and ($response -eq "y")){
                $msg = "$(Get-Date -Format T) HOST IS NOT IN MAINTENANCE MODE, CONTINUE? [y/n]"
                do {$response = Read-Host -Prompt $msg
                }until ($response -eq "y" -or $response -eq "n")
            }

            # Running Ansible on Open Items
            # =============================================================================================
            if($response -eq "y"){
                Try{
					RemediateItem $SSHItems $OpenItems $vmhost $xmlCkl
					$remediated = "Ansible run on $($OpenItems)"
				}
                Catch{
					Write-Error "Failed to Remediate Items on $($vmhost).. $_.Exception"
				}
            
                # CleanUp
                # =============================================================================================
                if($fixsshReportFile){Remove-Item -Path $fixsshReportFile -erroraction 'silentlycontinue'}
                if($fixsshCklFile){Remove-Item -Path $fixsshCklFile -erroraction 'silentlycontinue'}
                if($fixreportFile){Remove-Item -Path $fixreportFile -erroraction 'silentlycontinue'}
                if($fixCklFile){Remove-Item -Path $fixCklFile -erroraction 'silentlycontinue'} 
            }
            elseif($response -eq "n"){
                Write-ToConsole "Finializing $($vmhost) STIG CKL without remediating open items..."
                $remediated = "Ansible skipped"
            }
        }
        else{
            Write-ToConsole "All $($vmhost) STIG items are remediated" 
            Write-ToConsole "Finializing $($vmhost) STIG CKL..."
            $remediated = "No open items"
        }
        $RemediateTable.add($vmhost,$remediated)
    }
}

VulnID2StigID -hostCklTable $hostCklTable

ListOpenItems -KnownIDs $KnownIDs -hostCklTable $hostCklTable -RemediateTable $RemediateTable

MergeTemplate -hostCklTable $hostCklTable -templateCklFile $templateCklFile

# Change permission
# =============================================================================================    
$login = logname
chmod -R 755 $workingdir/Reports/
chown -R $login $workingdir/Reports/

# Calculate elapsed time in minutes and seconds
$elapsedTime = (Get-Date) - $startTime
$elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
$elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

Write-ToConsole ""
Write-ToConsole "$($VCSAshortname) - END SCRIPT"
Write-ToConsole "$($VCSAshortname) - Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"

Stop-Transcript
chmod -R 755 /opt/stigtools/vsphere8/transcript/
chown -R $login /opt/stigtools/vsphere8/transcript/
