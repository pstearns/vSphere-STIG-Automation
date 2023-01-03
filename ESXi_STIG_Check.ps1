<# 
#==========================================================================
# NAME: ESXi_STIG_Check.ps1, v3.0.0
# AUTHOR: Peter Stearns
# UPDATED: 12/14/2022
# PROFILE: VMware_vSphere_7.0_ESXi_SRG_v1r4
# DESCRIPTION:
#    -This script runs the Inspec Profile against all ESXi in a VCSA
#    -Then calls Ansible and Powershell to fix open findings
#    -Outputs a STIG Viewer Checklist file per ESXi host
#==========================================================================

    Tested against
    -PowerCLI 12.6
    -Powershell 5/Core 7.2.6
    -vCenter/ESXi 7.0 U3g

    Example command to run script
    .\VMware_vSphere_7.0_STIG_ESXi_Remediation.ps1 -vcenter vcentername.test.local -hostname myhost.test.local

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
    [ValidateSet("y")]
    [string]$vdi
)

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#/////////////////////DECLARE VARIABLES///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$workingdir     = "/opt/stigtools/"
$STIG_ver       = "VMware_vSphere_7.0_ESXI_SRG_v1r4"

$classification = "U"
$MARKING        = "CUI"
$NTPServers     = "x.x.x.x","x.x.x.x"
$syslogServer   = 'udp://x.x.x.x:514'
$esxAdminGroup  = 'ESXI_GROUP'
$allowedIPs     = "x.x.x.x/16","x.x.x.x/16","x.x.x.x/16"
$esxiVer        = '20036589'
$ExceptionUser  = 'domain\service_account'   # If service account is used to scan
$domainName     = 'domain'
$CanonicalOU    = 'domain/OU/OU/OU'
$OU             = "OU=OU,OU=OU,OU=OU,DC=domain,DC=com"

$vMotionVlanId  = 'xxxx','yyy','zzz'            # Define different vMotion VLAN Tags are used
$mgtVlanId      = '0','xx','yy','zz'            # Define different mgmt Tags
$sslIssueOrg    = 'U.S. Government','DoD','xyz' # Define Certificate ORG Issue
$nativeVLAN     = "1"
$Scratch        = '[syslog] '

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////COMMENTS and MARKUPS//////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# ESXI-70-000038
# =============================================================================================
$ESX038 = @{
    VULN_ID = "ESXI-70-000038"

    COMMENT = '     All Automated tests passed for the control 
     
    There are no attached host profiles to this host so this control is Not Applicable'

    STATUS = "Not_Applicable"
}

# ESXI-70-000050
# =============================================================================================
$ESX050 = @{
    VULN_ID = "ESXI-70-000050"

    COMMENT = '
All IP-Based Storage is configured on seperate VLANs per our standard configuration during inital setup.
This item needs to be manually verifed.'
    
    STATUS = "NotAFinding"
}

# ESXI-70-000054
# =============================================================================================
$ESX054 = @{
    VULN_ID = "ESXI-70-000054"

    COMMENT = '
There are no iSCSI HBAs present so this control is Not Applicable'
    
    STATUS = "Not_Applicable"
}

# ESXI-70-000070
# =============================================================================================
$ESX070 = @{
    VULN_ID = "ESXI-70-000070"

    COMMENT = '
CIM monitoring is not implemented, this is Not Applicable.'
    
    STATUS = "Not_Applicable"
} 

# ESXI-70-000086
# =============================================================================================
$ESX086 = @{
    VULN_ID = "ESXI-70-000086"

    COMMENT = '
No SSL syslog targets, this check is Not Applicable'
    
    STATUS = "Not_Applicable"
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////Known Open Items///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$KnownIssues = @($ESX038,$ESX050,$ESX054,$ESX070,$ESX086)
$KnownIDs   += $KnownIssues | ForEach-Object { $_.VULN_ID }

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////////////STIG Values//////////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
$stigsettings = [ordered]@{

    ##### Environment Specific STIG Values #####

    ExceptionUser           = $ExceptionUser                                           #ESXI-70-000003
    syslogHost              = @{"Syslog.global.logHost" = $syslogServer}               #ESXI-70-000004
    CanonicalOU             = $CanonicalOU                                             #ESXI-70-000037
    domainName              = $domainName                                              #ESXI-70-000037
    esxAdminsGroup          = @{"Config.HostAgent.plugins.hostsvc.esxAdminsGroup" = $esxAdminGroup} #ESXI-70-000039
    syslogScratch           = @{"Syslog.global.logDir" = "$($Scratch)scratch/log"}     #ESXI-70-000045
    syslogUnique            = @{"Syslog.global.logDirUnique" = "True"}                 #ESXI-70-000045
    ntpServers              = $NTPServers                                              #ESXI-70-000046
    allowedips              = $allowedIPs                                              #ESXI-70-000056 Allows IP ranges for the ESXi firewall
    esxiLatestBuild         = $esxiVer                                                 #ESXI-70-000072
    nativeVLANid            = $nativeVLAN                                              #ESXI-70-000063
    
    ##### Default STIG Values #####

    lockdownlevel           = "lockdownNormal"                                         #ESXI-70-000001 Lockdown level: lockdownDisabled,lockdownNormal,lockdownStrict
    DCUIAccess              = @{"DCUI.Access" = "root"}                                #ESXI-70-000002
    accountLockFailures     = @{"Security.AccountLockFailures" = "3"}                  #ESXI-70-000005
    accountUnlockTime       = @{"Security.AccountUnlockTime" = "900"}                  #ESXI-70-000006
    logLevel                = @{"Config.HostAgent.log.level" = "info"}                 #ESXI-70-000030
    passwordComplexity      = @{"Security.PasswordQualityControl" = "similar=deny retry=3 min=disabled,disabled,disabled,disabled,15"} #ESXI-70-000031
    passwordHistory         = @{"Security.PasswordHistory" = "5"}                      #ESXI-70-000032
    enableMob               = @{"Config.HostAgent.plugins.solo.enableMob" = "False"}   #ESXI-70-000034
    sshEnabled              = $false                                                   #ESXI-70-000035
    shellEnabled            = $false                                                   #ESXI-70-000036
    shellIntTimeout         = @{"UserVars.ESXiShellInteractiveTimeOut" = "120"}        #ESXI-70-000041
    shellTimeout            = @{"UserVars.ESXiShellTimeOut" = "600"}                   #ESXI-70-000042
    DCUITImeout             = @{"UserVars.DcuiTimeOut" = "120"}                        #ESXI-70-000043
    vibacceptlevel          = "PartnerSupported"                                       #ESXI-70-000047 VIB Acceptance level CommunitySupported,PartnerSupported,VMwareAccepted,VMwareCertified
    snmpEnabled             = $false                                                  #ESXI-70-000053
    ShareForceSalting       = @{"Mem.ShareForceSalting" = "2"}                         #ESXI-70-000055
    ShareForceSaltingVDI    = @{"Mem.ShareForceSalting" = "0"}                         #ESXI-70-000055
    BlockGuestBPDU          = @{"Net.BlockGuestBPDU" = "1"}                            #ESXI-70-000058
    DVFilterBindIpAddress   = @{"Net.DVFilterBindIpAddress"= ""}                       #ESXI-70-000062
    sslProtocols            = @{"UserVars.ESXiVPsDisabledProtocols" = "sslv3,tlsv1,tlsv1.1"} #ESXI-70-000074
    suppressShellWarning    = @{"UserVars.SuppressShellWarning" = "0"}                 #ESXI-70-000079
    executeVibs             = @{"VMkernel.Boot.execInstalledOnly" = "true"}            #ESXI-70-000080
    suppressHyperWarning    = @{"UserVars.SuppressHyperthreadWarning" = "0"}           #ESXI-70-000081
    auditRecords            = [ordered]@{
                                "size" = "100"
                                "dir" = "/scratch/auditLog"
                                }                                                      #ESXI-70-000084
    slpdEnabled             = $false                                                   #ESXI-70-000083
    syslogCertCheck         = @{"Syslog.global.logCheckSSLCerts" = "true"}             #ESXI-70-000086
    memEagerZero            = @{"Mem.MemEagerZero" = "1"}                              #ESXI-70-000087
    apiTimeout              = @{"Config.HostAgent.vmacore.soap.sessionTimeout" = "30"} #ESXI-70-000088
    hostClientTimeout       = @{"UserVars.HostClientSessionTimeout"       = "600"}     #ESXI-70-000089
    passwordMaxAge          = @{"Security.PasswordMaxDays"                = "90"}      #ESXI-70-000091
    cimEnabled              = $false                                                   #ESXI-70-000097
    ConfigEtcIssue          = @{"Config.Etc.issue" = 'You are accessing a U.S. Government (USG) Information System (IS) that is provided for USG-authorized use only. By using this IS (which includes any device attached to this IS), you consent to the following conditions: -The USG routinely intercepts and monitors communications on this IS for purposes including, but not limited to, penetration testing, COMSEC monitoring, network operations and defense, personnel misconduct (PM), law enforcement (LE), and counterintelligence (CI) investigations. -At any time, the USG may inspect and seize data stored on this IS. -Communications using, or data stored on, this IS are not private, are subject to routine monitoring, interception, and search, and may be disclosed or used for any USG-authorized purpose. -This IS includes security measures (e.g., authentication and access controls) to protect USG interests--not for your personal benefit or privacy. -Notwithstanding the above, using this IS does not constitute consent to PM, LE or CI investigative searching or monitoring of the content of privileged communications, or work product, related to personal representation or services by attorneys, psychotherapists, or clergy, and their assistants. Such communications and work product are private and confidential. See User Agreement for details.'}
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
#//////////////////// INTIALIZE SCRIPT //////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

if($vcenter){$vTarget = "$($vcenter)"}
if($hostname -or $cluster){$SUBTARGET = "$($hostname)$($cluster)"}
if($vdi -eq "y"){
   $VDISet = "Page Sharing Allowed For VDI"
}else{$VDISet = "NON-VDI Cluster - Page Sharing not allowed"}

cls; Write-Host "
#==========================================================================
# NAME:         ESXI STIG CHECK and REMEDIATION
# PROFILE:      VMware_vSphere_7.0_ESXI_SRG_v1r4
# DESCRIPTION:  Runs Inspec and Ansible to STIG ESXI
# WORKING DIR:  $($workingdir)
#
# VCENTER:      $($vTarget) 
# SUB-TARGET:   $($SUBTARGET)
# VDI:          $($VDISet)
#=========================================================================="

#Prompt for vCenter
# =============================================================================================
if(!$vcenter){
    $msgvCenter = "Enter vCenter FQDN"
    do {
        $vcenter  = Read-Host $msgvCenter
        $splitName     = $vcenter.split(".") 
        $connection    = Test-Connection -ComputerName $vcenter -Count 1 -Quiet
    }
    until ($vcenter -ne $null -and $vcenter -ne "" -and $splitName[1] -ne $null -and $connection -eq "True")
}

$vcsacred      = Get-Credential -Message "Enter Creds for $($vcenter):" -UserName 'administrator@vsphere.local'
$esxcred       = Get-Credential -Message "Enter Creds for ESXADMIN:" -UserName 'esxadmin' 
#$domainCred    = Get-Credential -Message "Enter Domain Creds:"

# Check the Connectivity of vCenter Server
# =============================================================================================
Connect-VIServer -Server $vcenter -Credential $vcsacred -ErrorAction SilentlyContinue | Out-Null

If($global:DefaultVIServer -or $global:DefaultVIServers) {
    $vmhosts = Get-VMHost | Sort-Object Name
}
else{
     Write-host "Could not connected to $vcenter"
     Exit -1
}

# Initialize
# =============================================================================================

# Import ESXi Remediation Module
Import-Module "$($workingdir)/ESXi_STIG_Module/vmware-esxi-7.0-stig-module.ps1" -DisableNameChecking -force

# Get Current Date and Time
$date = Get-Date

Write-ToConsole "Setting environment variables..."

$splitName       = $vcenter.split(".")
$VCSAshortname   = $splitName[0].ToUpper()

$ENV:RUBYOPT     = 'rubygems'
$ENV:RUBY_DIR    = '/opt/inspec/embedded'
$ENV:GEM_PATH    = '/opt/inspec/embedded/lib/ruby/gems/2.7.0/gems'
$ENV:PATH        = '/opt/inspec/embedded/bin;' + $ENV:PATH
$ENV:NO_COLOR    = $true

$ENV:VISERVER           = $vcenter
$ENV:VISERVER_USERNAME  = $vcsacred.UserName
$ENV:VISERVER_PASSWORD  = $vcsacred.GetNetworkCredential().password

$inspecPath      = "$($workingdir)/ESXi_STIG_Module/vmware-esxi-7.0-stig-inspec/esxi/"
$inspecEsxSSH    = "$($workingdir)/ESXi_STIG_Module/vmware-esxi-7.0-stig-inspec/esxi-ssh/"
$reportPath      = "$($workingdir)/Reports/" + $VCSAshortname 

$hostCklTable    = [ordered]@{}
$ansiblePlaybook = "$($workingdir)/ESXi_STIG_Module/vmware-esxi-7.0-stig-ansible/playbook.yml"

$FinalItems      = @('ESXI-70-000036','ESXI-70-000035','ESXI-70-000001','ESXI-70-000091')
$controls        = inspec export $inspecPath | where-object {$_ -like "*- ESXI-70-00*"} | ForEach-Object {$_ -Replace "  -" -replace ' ',''}
$SSHItems        = inspec export $inspecEsxSSH | where-object {$_ -like "*- ESXI-70-00*"} | ForEach-Object {$_ -Replace "  -" -replace ' ',''}
$ESXItems        = Compare-Object $controls $SSHItems -includeEqual -passthru | where-object {$_.SideIndicator -eq '<='}

# Verify report folder
# =============================================================================================
If(Test-Path -Path $reportPath){
    Write-ToConsole "Validated path for report at $reportPath"
}Else{
    Write-ToConsole "Report path $reportPath doesn't exist...attempting to create..."
    New-Item -ItemType Directory -Path $reportPath -Force
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#///////////////////////////// FUNCTIONS ////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Function EnableAccess ($vmhost) {
    # Disable Lockdown and Enable SSH and ESXi Password Age
    $vmhostv = $vmhost | Get-View 
    $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
    If($vmhostv.config.LockdownMode -ne 'lockdownDisabled'){$lockdown.ChangeLockdownMode('lockdownDisabled')}
    $PasswordAge = $vmhost | Get-AdvancedSetting -Name Security.PasswordMaxDays
    If($PasswordAge -ne '99999'){$vmhost | Get-AdvancedSetting -Name Security.PasswordMaxDays | Set-AdvancedSetting -Value 99999 -Confirm:$false | out-null}
    $vmhost | Foreach {Start-VMHostService -Confirm:$false -HostService ($_ | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"} )} | out-null
}

Function DisableAccess ($vmhost) {
    # Disable Lockdown and Enable SSH and ESXi Password Age
    $vmhostv = $vmhost | Get-View 
    $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
    If($vmhostv.config.LockdownMode -ne 'lockdownNormal'){$lockdown.ChangeLockdownMode('lockdownNormal')}
    $PasswordAge = $vmhost | Get-AdvancedSetting -Name Security.PasswordMaxDays
    If($PasswordAge -ne '90'){$vmhost | Get-AdvancedSetting -Name Security.PasswordMaxDays | Set-AdvancedSetting -Value 90 -Confirm:$false | out-null}
    $vmhost | Foreach {Stop-VMHostService -Confirm:$false -HostService ($_ | Get-VMHostService | Where { $_.Key -eq "TSM-SSH"} )} | out-null
}

Function InspecESXiHost ($vmhost){
    # INSPEC ESXi Host SSH transport
    # =============================================================================================
    inspec exec $inspecEsxSSH -t ssh://esxadmin@$vmhost --password $esxcred.GetNetworkCredential().password --show-progress --reporter json:$sshReportFile | Out-Null

    # Closing Final STIG Items before check
    # =============================================================================================
    DisableAccess $vmhost
    
    # INSPEC ESXi Host VMware transport
    # =============================================================================================
    inspec exec $inspecPath -t vmware:// --input vmhostName=$vmhost exceptionUsers=$ExceptionUser sslIssueOrg=$sslIssueOrg syslogServer=$syslogServer adAdminGroup=$esxAdminGroup ntpServers=$NTPServers VMotionVLAN=$vMotionVlanId mgtVlanId=$mgtVlanId esxiBuildNumber=$esxiVer --show-progress --reporter json:$reportFile | Out-Null
    
    # Create CKL Files
    # =============================================================================================    
    inspec_tools inspec2ckl -j $reportFile -o $cklFile
    inspec_tools inspec2ckl -j $sshReportFile -o $sshCklFile 
}

Function cklMerge ($xmlCkl,$sshXmlCkl){
    # Merge SSH CKL ITEMs with STIG CKL
    # =============================================================================================
    $sshXmlCkl.CHECKLIST.STIGS.iSTIG.VULN |  ForEach-Object {
            
        $sshVulnID       = $_.STIG_DATA.ATTRIBUTE_DATA[0]
        $sshVulnSTATUS   = $_.STATUS
        $sshVulnFindDet  = $_.FINDING_DETAILS

        $cklNode         = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $sshVulnID }
        $cklNode.STATUS            = $sshVulnSTATUS
        $cklNode.FINDING_DETAILS   = $sshVulnFindDet
    }
}

Function cklMarkup ($xmlCkl){
    # Update CKL FILE With ASSET Info
    # =============================================================================================
    $xmlCkl.CHECKLIST.ASSET.ROLE            = "Member Server"
    $xmlCkl.CHECKLIST.ASSET.ASSET_TYPE      = "Computing"
    $xmlCkl.CHECKLIST.ASSET.HOST_NAME       = $shortName
    $xmlCkl.CHECKLIST.ASSET.HOST_IP         = $esxi_IP
    $xmlCkl.CHECKLIST.ASSET.HOST_FQDN       = $vmhost.Name
    $xmlCkl.CHECKLIST.ASSET.WEB_OR_DATABASE = "false"

    # Find and Markup Known Issues
    # =============================================================================================
    foreach ($KnownID in $KnownIDs){
            $Vuln_Node          = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $KnownID }
            $Vuln_Object        = $KnownIssues | where-object VULN_ID -contains $KnownID
            if (($Vuln_Node.STATUS -eq "Not_Reviewed") -or ($Vuln_Node.STATUS -eq "NotAFinding")){
                $Vuln_Node.COMMENTS = $Vuln_Object.COMMENT
                $Vuln_Node.STATUS   = $Vuln_Object.STATUS
            }
    }

    # Save XML data to CKL file
    # =============================================================================================
    # Write-ToConsole "Saving File..."
    $xmlCkl.Save($cklFile)

    # Find and Replace Loop
    # =============================================================================================
    $FindTitle    = 'Untitled - Checklist Created from Automated InSpec Results'
    $ReplaceTitle = "$STIG_ver - Checklist Created from Automated InSpec Results"
       
    (Get-Content $cklFile -Raw).
    Replace($FindTitle,$ReplaceTitle).
    Replace('CUI',$MARKING)| 
    Set-Content $cklFile
}

Function RemediateItem ($SSHItems,$OpenItems,$vmhost,$xmlCkl){
    # Test for Ansible and ESXi Stig Playbook
    CheckAnsible

    # Create subsets for remediation
    $SSHFixItems = Compare-Object $OpenItems $SSHItems -IncludeEqual -PassThru | where-object {$_.SideIndicator -eq '=='}
    $FixItems = Compare-Object $OpenItems $FinalItems -includeEqual -passthru | where-object {$_.SideIndicator -eq '<='}
    $FixItems = Compare-Object $FixItems $SSHItems -includeEqual -passthru | where-object {$_.SideIndicator -eq '<='}

    # Enable Access by Disable Lockdown and Enable SSH and ESXi Password Age
    try{EnableAccess $vmhost}
    catch{Write-Error "Failed to Enable access to $($vmhost)... $_.Exception"}
         
    # Run Ansible SSH STIG Items
    # =============================================================================================
    if($ansible -ne "NotInstalled"){
        $SSHFixItemsString = $SSHFixItems -join ","
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $SSHFixItemsString -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"    
    }
    
    # Running Inspec to Verify SSH Items
    # =============================================================================================
    inspec exec $inspecEsxSSH -t ssh://esxadmin@$vmhost --password $esxcred.GetNetworkCredential().password --reporter json:$fixsshReportFile --controls $SSHFixItems | Out-Null
    inspec_tools inspec2ckl -j $fixsshReportFile -o $fixsshCklFile

    # Running Powershell STIG items
    # =============================================================================================
    foreach ($FixItem in $FixItems){
        try{
            & $FixItem $vmhost $stigsettings
        }catch{Write-Error "Failed remediate $($FixItem) on $($vmhost)... $_.Exception"}
    }

    # Enable Access by Disable Lockdown and Enable SSH and ESXi Password Age
    try{DisableAccess $vmhost}
    catch{Write-Error "Failed to Enable access to $($vmhost)... $_.Exception"}

    # Running Inspec to Verify Powershell Items
    # =============================================================================================
    inspec exec $inspecPath -t vmware:// --input vmhostName=$vmhost exceptionUsers=$ExceptionUser sslIssueOrg=$sslIssueOrg syslogServer=$syslogServer adAdminGroup=$esxAdminGroup ntpServers=$NTPServers VMotionVLAN=$vMotionVlanId mgtVlanId=$mgtVlanId esxiBuildNumber=$esxiVer --reporter json:$fixreportFile --controls $FixItems
    inspec_tools inspec2ckl -j $fixreportFile -o $fixcklFile

    # Updating CKL with fixed items
    # =============================================================================================
    $xmlFixCkl = ( Select-Xml -Path $FixCklFile -XPath / ).Node
    foreach ($FixItem in $FixItems){
        $Fix_Node                    = $xmlFixCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $FixItem }
        $xmlCkl_Node                 = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $FixItem }
        $xmlCkl_Node.STATUS          = $Fix_Node.STATUS
        $xmlCkl_Node.COMMENTS        = $Fix_Node.COMMENTS
        $xmlCkl_Node.FINDING_DETAILS = $Fix_Node.FINDING_DETAILS
    }
    $xmlsshFixCkl = ( Select-Xml -Path $fixsshCklFile -XPath / ).Node
    foreach ($SSHFixItem in $SSHFixItems){
        $SSH_Fix_Node                = $xmlsshFixCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $SSHFixItem }
        $xmlCkl_Node                 = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $SSHFixItem }
        $xmlCkl_Node.STATUS          = $SSH_Fix_Node.STATUS
        $xmlCkl_Node.COMMENTS        = $SSH_Fix_Node.COMMENTS
        $xmlCkl_Node.FINDING_DETAILS = $SSH_Fix_Node.FINDING_DETAILS
    }
    
    # Save XML data to CKL file
    # =============================================================================================
    # Write-ToConsole "Saving File..."
    $xmlCkl.Save($cklFile)
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////////////////// SCRIPT //////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#Gather Info
Try{
    If($hostname){
        $vmhosts = Get-VMHost -Name $hostname -ErrorAction Stop | Sort-Object Name
    }
    ElseIf($cluster){
        $vmhosts = Get-Cluster -Name $cluster -ErrorAction Stop | Get-VMHost -ErrorAction Stop | Sort-Object Name
    }
    Else{
        $vmhosts = Get-VMHost -ErrorAction Stop | Sort-Object Name
    }
}
Catch{
    Write-ToConsoleRed "Failed to gather information on target hosts in $($vcenter)"
    Write-ToConsoleRed $_.Exception
    Write-ToConsole "...Disconnecting from vCenter Server $($vcenter)"
    Disconnect-VIServer -Server $($vcenter) -Force -Confirm:$false
    Exit -1
}

foreach ($vmhost in $vmhosts){

    Write-ToConsole "Running Inspec exec against $($vmhost)"
    
    $splitName        = $vmhost.Name.split(".")
    $shortName        = $splitName[0].ToUpper()
    $reportFile       = $reportPath + "/" + $shortName + "_" + $classification + "_" + $STIG_ver + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".json"
    $cklFile          = $reportPath + "/" + $shortName + "_" + $classification + "_" + $STIG_ver + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".ckl"
    $sshReportFile    = $reportPath + "/" + "SSH_" + $shortName + "_" + $classification + "_" + $STIG_ver + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".json"
    $sshCklFile       = $reportPath + "/" + "SSH_" + $shortName + "_" + $classification + "_" + $STIG_ver + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".ckl"
    $esxi_IP          = [system.net.dns]::GetHostByName($vmhost.name).AddressList[0].IPAddressToString

    # Enable Access by Disable Lockdown and Enable SSH and ESXi Password Age
    Try{EnableAccess $vmhost}
    catch{Write-Error "Failed to Enable access to $($vmhost)... $_.Exception"}

    # Verify local admin
    Try{LocalESXAdmin $vmhost $stigsettings}
    catch{Write-Error "Failed to verify local admin of $($vmhost)... $_.Exception"}
    
    # Run Inspec profile against Host
    # =============================================================================================
        
    InspecESXiHost $vmhost
    if (!$cklFile){
        Write-Error "Failed to run Inspec profile against $($vmhost)... $_.Exception"
    }

    # Create XML object from CKL
    # =============================================================================================
    Try{
        $xmlCkl = ( Select-Xml -Path $cklFile -XPath / ).Node
        $sshXmlCkl = ( Select-Xml -Path $sshCklFile -XPath / ).Node
    }
    Catch{
        Write-Error "Failed to import CKL.."
    }

    # Update and Merge CKL file
    # =============================================================================================
    if($xmlCkl){

        # Merge SSH CKL ITEMs with STIG CKL
        # =============================================================================================
        try{
            cklMerge $xmlCkl $sshXmlCkl
        }
        Catch{
            Write-Error "Failed to merge CKLs for $($vmhost)... $_.Exception"
        }

        # Update CKL FILE With ASSET Info
        # =============================================================================================
        try{
            cklMarkup $xmlCkl
        }
        Catch{
            Write-Error "Failed to update CKL Asset info for $($vmhost)... $_.Exception"
        }
        # Write-ToConsole "STIG Check for $($shortName) completed output file: $($cklFile)"
        $hostCklTable.add($vmhost,$cklFile)
    }
    else{Write-Error "Failed Update and Merge CKL file..."; Exit -1}

    # CleanUp
    # =============================================================================================
    if($sshReportFile){Remove-Item -Path $sshReportFile -erroraction 'silentlycontinue'}
    if($sshCklFile){Remove-Item -Path $sshCklFile -erroraction 'silentlycontinue'}
    if($reportFile){Remove-Item -Path $reportFile -erroraction 'silentlycontinue'}
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#/////////////////////// REMEDIATION OPEN ITEMS //////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
if ($hostCklTable){

    Write-ToConsole
    Write-ToConsole "*********************************************"
    Write-ToConsole "Starting Remediation Process..."
    Write-ToConsole "*********************************************"

    $hostCklTable.keys | ForEach-Object {
        $vmhost             = $_
        $cklFile            = $hostCklTable[$_]
        $fixreportFile      = $reportPath + "/" + "FIX_" + $shortName + "_" + $classification + "_" + $STIG_ver + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".json"
        $fixcklFile         = $reportPath + "/" + "FIX_" + $shortName + "_" + $classification + "_" + $STIG_ver + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".ckl"
        $fixsshReportFile   = $reportPath + "/" + "FIX_SSH_" + $shortName + "_" + $classification + "_" + $STIG_ver + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".json"
        $fixsshCklFile      = $reportPath + "/" + "FIX_SSH_" + $shortName + "_" + $classification + "_" + $STIG_ver + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".ckl"
    
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
            $AllOpenItems += $_.STIG_DATA[0].ATTRIBUTE_DATA
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

            $msg = "$(Get-Date -Format T) Run ESX STIG to remediate items on $($vmhost)? [y/n]"
            do {$response = Read-Host -Prompt $msg
            }until ($response -eq "y" -or $response -eq "n")
            
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
            }
        }
        else{
            Write-ToConsole "All $($vmhost) STIG items are remediated" 
            Write-ToConsole "Finializing $($vmhost) STIG CKL..."
        }
    }
}

# List Open Items
# =============================================================================================
if ($hostCklTable){
    $summary = @()
    $hostCklTable.keys | ForEach-Object {
        $vmhost = $_
        $cklFile = $hostCklTable[$_]
        $xmlCkl = ( Select-Xml -Path $cklFile -XPath / ).Node
        $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
    
            $OpenItems += $_.STIG_DATA[0].ATTRIBUTE_DATA
            if($_.STIG_DATA[0].ATTRIBUTE_DATA -in $KnownIDs){$Known = "True"}
            else {$Known = "False"}

            $obj = New-Object -TypeName PSObject
		    $obj | Add-Member -MemberType NoteProperty -Name Host -Value $vmhost 
		    $obj | Add-Member -MemberType NoteProperty -Name OpenID -Value $_.STIG_DATA[0].ATTRIBUTE_DATA
		    $obj | Add-Member -MemberType NoteProperty -Name Known -value $Known
		    $summary += $obj
        }
    }
    Write-ToConsole "*********************************************"
    Write-ToConsole "              SUMMARY                        "
    Write-ToConsole "*********************************************"
    Write-Host ($summary | Sort-Object Host | Format-Table | Out-String)
}

Remove-Module vmware-esxi-7.0-stig-module

Disconnect-VIServer * -Confirm:$false

Write-ToConsole ""
Write-ToConsole "END SCRIPT"