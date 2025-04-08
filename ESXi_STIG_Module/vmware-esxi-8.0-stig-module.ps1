#==========================================================================
# NAME: ESXi8_STIG_Module.ps1, v1.0.0
# AUTHOR: Peter Stearns
# UPDATED: 10/16/2024
# DESCRIPTION:
#    -Contains ESXi STIG functions 
#    -Functions use Advanced Settings, Powercli scripts, and Ansible
#    -Can import modules or call functions to perform individual checks. 
#    -stigsetting varibles need to be passed to functions

#==========================================================================
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#///////////////////////////// Functions ////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

Function Write-ToConsole ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate) $Details"
}

Function Write-ToConsoleRed ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate) $Details" -ForegroundColor Red
}

Function Write-ToConsoleGreen ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate) $Details" -ForegroundColor Green
}

Function Write-ToConsoleYellow ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate) $Details" -ForegroundColor Yellow
}

Function Write-ToConsoleBlue ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate) $Details" -ForegroundColor Blue
}

Function AdvancedSettingSTIG ($vmhost,$name,$value){
    If($asetting = Get-AdvancedSetting -Entity $vmhost -Name $name){
        If([string]$asetting.value -eq $value){
            Write-ToConsoleGreen "...Setting $($name) is already configured correctly to $value on $($vmhost.name)"
        }Else{
            Write-ToConsoleYellow "...Setting $($name) was incorrectly set to $($asetting.value) on $($vmhost.name)...setting to $($value)"
            $asetting | Set-AdvancedSetting -Value $($value) -Confirm:$false
        }
    }Else{
        Write-ToConsoleYellow "...Setting $($name) does not exist on $($vmhost.name)...creating setting..."
        New-AdvancedSetting -Entity $vmhost -Name $name -Value $($value) -Confirm:$false
    }
}

Function CheckAnsible {
    try{
        $ansible = ansible --version

        if(-not (Test-Path -Path $ansiblePlaybook)){
            $ansible = $null
            Write-ToCOnsoleBlue "ESXi Stig Playbook not available... SKIPPING SSH STIG ITEMS..."
        }
    }catch{
        $ansible = $null
        Write-ToConsoleBlue "Ansible is not available... SKIPPING SSH STIG ITEMS..."
    }
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////////// STIG FUNCTIONS ////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#===============================================================================================
# PowerCLI Advanced Settings Remediations
#===============================================================================================

# DCUI.Access
Function ESXI-80-000189($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000189"
    $Title = "The ESXi host DCUI.Access list must be verified."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.DCUIAccess.Keys
    $value = $stigsettings.DCUIAccess.Values
    AdvancedSettingSTIG $vmhost $name $value
} 

# Syslog
Function ESXI-80-000114($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000114"
    $Title = " The ESXi host must offload logs via syslog."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.syslogHost.Keys
    $value = [string]$stigsettings.syslogHost.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Account Lock Failures
Function ESXI-80-000005($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000005"
    $Title = "The ESXi host must enforce the limit of three consecutive invalid logon attempts by a user."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.accountLockFailures.Keys
    $value = [string]$stigsettings.accountLockFailures.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Account Unlock Timeout
Function ESXI-80-000111($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000111"
    $Title = "The ESXi host must enforce an unlock timeout of 15 minutes after a user account is locked out."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.accountUnlockTime.Keys
    $value = [string]$stigsettings.accountUnlockTime.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Welcome banner   Annotations.WelcomeMessage
Function ESXI-80-000006($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000006"
    $Title = "TThe ESXi host must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via the Direct Console User Interface (DCUI)."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.AnnotationsMessage.Keys
    $value = [string]$stigsettings.AnnotationsMessage.Values
    AdvancedSettingSTIG $vmhost $name $value
}    

# /etc/issue Banner
Function ESXI-80-000191($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000191"
    $Title = "The ESXi host must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system via Secure Shell (SSH)."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.ConfigEtcIssue.Keys
    $value = [string]$stigsettings.ConfigEtcIssue.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Log Level
Function ESXI-80-000015($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000015"
    $Title = "The ESXi must produce audit records containing information to establish what type of events occurred."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.logLevel.Keys
    $value = [string]$stigsettings.logLevel.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Password Complexity
Function ESXI-80-000035($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000035"
    $Title = "The ESXi host must enforce password complexity by configuring a password quality policy."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.passwordComplexity.Keys
    $value = [string]$stigsettings.passwordComplexity.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Password Reuse
Function ESXI-80-000043($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000043"
    $Title = " The ESXi host must prohibit password reuse for a minimum of five generations."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.passwordHistory.Keys
    $value = [string]$stigsettings.passwordHistory.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Disable MOB per host
Function ESXI-80-000047($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000047"
    $Title = "The ESXi host must be configured to disable nonessential capabilities by disabling the Managed Object Browser (MOB)."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.enableMob.Keys
    $value = [string]$stigsettings.enableMob.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Shell Interactive Timeout
Function ESXI-80-000068($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000068"
    $Title = "The ESXi host must set a timeout to automatically end idle shell sessions after fifteen minutes."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.shellIntTimeout.Keys
    $value = [string]$stigsettings.shellIntTimeout.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Audit Record Capacity  Note: ESXI-80-000113 and ESXI-80-000243 must be configured and validated prior to ESXI-80-000232.
Function ESXI-80-000113($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000113"
	$Title = "The ESXi host must allocate audit record storage capacity to store at least one week's worth of audit records."
	Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
	$name = $stigsettings.auditRecordStorageCap.Keys
    $value = [string]$stigsettings.auditRecordStorageCap.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Audit Logging Enable  Note: ESXI-80-000113 and ESXI-80-000243 must be configured and validated prior to to ESXI-80-000232.
Function ESXI-80-000232($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000232"
	$Title = "The ESXi host must enable audit logging."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
	$name = $stigsettings.syslogAuditEnable.Keys
    $value = [boolean]$stigsettings.syslogAuditEnable.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Log Persistent Location  Note: ESXI-80-000113 and ESXI-80-000243 must be configured and validated prior to to ESXI-80-000232.
Function ESXI-80-000243($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000243"
    $Title = "The ESXi host must configure a persistent log location for all locally stored logs."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name1 = $stigsettings.syslogUnique.Keys
    $value1 = [string]$stigsettings.syslogUnique.Values
    $name2 = $stigsettings.syslogScratch.Keys
    $value2 = [string]$stigsettings.syslogScratch.Values
    $asetting = Get-AdvancedSetting -Entity $vmhost -Name $name2
    If(-not $asetting.Value.ToLower().Contains($value2)){
        # Set Unique log location
        AdvancedSettingSTIG $vmhost $name1 $value1
        # Check and set syslog
        AdvancedSettingSTIG $vmhost $name2 $value2
    }Else{
        Write-ToConsoleGreen "...Setting $name2 is already configured correctly to $($asetting.Value) on $($vmhost.name)"
    }
}

## syslog audit remote
Function ESXI-80-000233($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000233"
	$Title = "The ESXi host must off-load audit records via syslog."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.syslogAuditRemote.Keys
    $value = [boolean]$stigsettings.syslogAuditRemote.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Shell Timeout
Function ESXI-80-000195($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000195"
    $Title = "The ESXi host must automatically stop shell services after 10 minutes."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.shellTimeout.Keys
    $value = [string]$stigsettings.shellTimeout.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# DCUI Timeout
Function ESXI-80-000196($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000196"
    $Title = "The ESXi host must set a timeout to automatically end idle DCUI sessions after 10 minutes."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.DcuiTimeOut.Keys
    $value = [string]$stigsettings.DcuiTimeOut.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Page Sharing
Function ESXI-80-000213($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000213"
	$Title = "The ESXi host must disable Inter-Virtual Machine (VM) Transparent Page Sharing."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if ($vdi -eq "y"){
        $name = $stigsettings.ShareForceSaltingVDI.Keys
        $value = [string]$stigsettings.ShareForceSaltingVDI.Values
    }else{
        $name = $stigsettings.ShareForceSalting.Keys
        $value = [string]$stigsettings.ShareForceSalting.Values
    }
    AdvancedSettingSTIG $vmhost $name $value
}

# BPDU filter
Function ESXI-80-000215($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000215"
	$Title = "he ESXi host must enable Bridge Protocol Data Units (BPDU) filter on the host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.BlockGuestBPDU.Keys
    $value = [string]$stigsettings.BlockGuestBPDU.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# DVFilter IP Addresses
Function ESXI-80-000219($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000219"
	$Title = "The ESXi host must restrict use of the dvFilter network application programming interface (API)."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.DVFilterBindIpAddress.Keys
    $value = [string]$stigsettings.DVFilterBindIpAddress.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# TLS 1.2
Function ESXI-80-000161($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000161"
	$Title = "The ESXi host must maintain the confidentiality and integrity of information during transmission by exclusively enabling Transport Layer Security (TLS) 1.2."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.sslProtocols.Keys
    $value = [string]$stigsettings.sslProtocols.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Suppress Shell Warning 
Function ESXI-80-000222($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000222"
	$Title = "The ESXi host must not suppress warnings that the local or remote shell sessions are enabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.suppressShellWarning.Keys
    $value = [string]$stigsettings.suppressShellWarning.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Suppress Hyperthreading Warning
Function ESXI-80-000223($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000223"
    $Title = "The ESXi host must not suppress warnings about unmitigated hyperthreading vulnerabilities."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.suppressHyperWarning.Keys
    $value = [string]$stigsettings.suppressHyperWarning.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Syslog Cert Check
Function ESXI-80-000224($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000224"
	$Title = "The ESXi host must verify certificates for SSL syslog endpoints."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.syslogCertCheck.Keys
    $value = [string]$stigsettings.syslogCertCheck.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Volatile key destruction
Function ESXI-80-000225($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000225"
	$Title = "The ESXi host must enable volatile key destruction."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.memEagerZero.Keys
    $value = [string]$stigsettings.memEagerZero.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# API timeout
Function ESXI-80-000226($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000226"
	$Title = "The ESXi host must configure a session timeout for the vSphere API."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.apiTimeout.Keys
    $value = [string]$stigsettings.apiTimeout.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Syslog Cert strict x509 verification
Function ESXI-80-000234($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000234"
	$Title = "The ESXi host must enable strict x509 verification for SSL syslog endpoints."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
	$name = $stigsettings.syslogCertStrict.Keys
    $value = [boolean]$stigsettings.syslogCertStrict.Values
	AdvancedSettingSTIG $vmhost $name $value
}

## syslog log level
Function ESXI-80-000235($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000235"
	$Title = "The ESXi host must forward audit records containing information to establish what type of events occurred."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.syslogLogLevel.Keys
    $value = [string]$stigsettings.syslogLogLevel.Values
	AdvancedSettingSTIG $vmhost $name $value
}

# Host Client timeout
Function ESXI-80-000010($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000010"
	$Title = "The ESXi host client must be configured with an idle session timeout."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.hostClientTimeout.Keys
    $value = [string]$stigsettings.hostClientTimeout.Values
    AdvancedSettingSTIG $vmhost $name $value
}

## ESXi Admins
Function ESXI-80-000241($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000241"
	$Title = "The ESXi host must not use the default Active Directory ESX Admin group."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.esxAdminsGroup.Keys
    $value = [string]$stigsettings.esxAdminsGroup.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Execute Approved VIBs
Function ESXI-80-000244($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000244"
	$Title = "The ESXi host must enforce the exclusive running of executables from approved VIBs."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.executeVibs.Keys
    $value = [string]$stigsettings.executeVibs.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Net.BMCNetworkEnable
Function ESXI-80-000250($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000250"
	$Title = "The ESXi host must disable virtual hardware management network interfaces."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.bmcNetworkEnable.Keys
    $value = [string]$stigsettings.bmcNetworkEnable.Values
    AdvancedSettingSTIG $vmhost $name $value
}

#===============================================================================================
# PowerCLI Script Remediations
#===============================================================================================

## Set the NTP Settings for all hosts
Function ESXI-80-000124($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000124"
    $Title = "The ESXi host must synchronize internal information system clocks to an authoritative time source."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $CurrentNTP = Get-VmHostNtpServer -VMHost $vmhost
    if (!$CurrentNTP){
        $vmhost | Add-VmHostNtpServer -NtpServer $stigsettings.esxiNtpServers 
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -policy On 
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService 
    }
    elseif (Compare-object $CurrentNTP $stigsettings.esxiNtpServers) {
        Write-ToConsoleYellow "...Setting NTP on $($vmhost)..."
        ForEach($ntp in $currentntp){
            $vmhost | Remove-VMHostNtpServer -NtpServer $ntp -Confirm:$false -ErrorAction Stop
        }
        $vmhost | Add-VmHostNtpServer -NtpServer $stigsettings.esxiNtpServers 
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -policy On 
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService 
    }else{
        Write-ToConsoleGreen "NTP Already Set $CurrentNTP on $($vmhost.name)"
    }
}

# Active Directory
Function ESXI-80-000049($vmhost, $stigsettings){
    if(!$domainCred){$domainCred = Get-Credential -Message "Enter Domain Creds:"}
    $STIGID = "ESXI-80-000049"
    $Title = "The ESXi host must uniquely identify and must authenticate organizational users by using Active Directory."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $adJoin = Get-VMHostAuthentication -VMHost $vmhost.name 
    if($adJoin.domain -eq $stigsettings.domainName){
        Write-ToConsoleGreen "...$($vmhost.name) is already joined to the Domain."
    }else{
        Write-ToConsoleYellow "...Joining $($vmhost.name) to the Domain."    
        $vmhost | Get-VMHostService | Where {$_.Name -eq "lwsmd"} | Restart-VMHostService -Confirm:$false -ErrorAction SilentlyContinue
        $vmhost | Get-VMHostAuthentication | Set-VMHostAuthentication -Domain $stigsettings.CanonicalOU -JoinDomain -Username $domainCred.UserName -Password $domainCred.Password -Confirm:$false
    }
}

## SSH .rhosts
Function ESXI-80-000052($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000052"
	$Title = "The ESXi host Secure Shell (SSH) daemon must ignore .rhosts files."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = [string]$stigsettings.sshIgnorerhosts.Keys
    $value = [string]$stigsettings.sshIgnorerhosts.Values
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    If($results -eq $value){
        Write-Host "...SSH $name set correctly to $results on $($vmhost.name)" -ForegroundColor Green
    }Else{
        Write-ToConsoleYellow "...Configuring SSH $name on $($vmhost.name) to $value"
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
    }
}

## SSH Ciphers
Function ESXI-80-000187($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000187"
	$Title = "The ESXi host Secure Shell (SSH) daemon must be configured to only use FIPS 140-2 validated ciphers."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = [string]$stigsettings.sshCiphers.Keys
    $value = [string]$stigsettings.sshCiphers.Values
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    If($results -eq $value){
        Write-Host "...SSH $name set correctly to $results on $($vmhost.name)" -ForegroundColor Green
    }Else{
        Write-ToConsoleYellow "...Configuring SSH $name on $($vmhost.name) to $value"
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
    }
} 

## SSH Banner
Function ESXI-80-000192($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000192"
	$Title = "The ESXi host Secure Shell (SSH) daemon must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = [string]$stigsettings.sshBanner.Keys
    $value = [string]$stigsettings.sshBanner.Values
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    If($results -eq $value){
        Write-Host "...SSH $name set correctly to $results on $($vmhost.name)" -ForegroundColor Green
    }Else{
        Write-ToConsoleYellow "...Configuring SSH $name on $($vmhost.name) to $value"
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
    }
}

# SSH hostbasedauth
Function ESXI-80-000202($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000202"
	$Title = "The ESXi host Secure Shell (SSH) daemon must not allow host-based authentication."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = [string]$stigsettings.sshHostbasedauth.Keys
    $value = [string]$stigsettings.sshHostbasedauth.Values
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    If($results -eq $value){
        Write-Host "...SSH $name set correctly to $results on $($vmhost.name)" -ForegroundColor Green
    }Else{
        Write-ToConsoleYellow "...Configuring SSH $name on $($vmhost.name) to $value"
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
    }
}

# SSH permitemptyuserenv
Function ESXI-80-000204($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000204"
	$Title = "The ESXi host Secure Shell (SSH) daemon must not permit user environment settings."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = [string]$stigsettings.sshPermituserenv.Keys
    $value = [string]$stigsettings.sshPermituserenv.Values
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    If($results -eq $value){
        Write-Host "...SSH $name set correctly to $results on $($vmhost.name)" -ForegroundColor Green
    }Else{
        Write-ToConsoleYellow "...Configuring SSH $name on $($vmhost.name) to $value"
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
    }
}

# SSH gatewayports
Function ESXI-80-000207($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000207"
	$Title = "The ESXi host Secure Shell (SSH) daemon must be configured to not allow gateway ports."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = [string]$stigsettings.sshGatewayports.Keys
    $value = [string]$stigsettings.sshGatewayports.Values
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    If($results -eq $value){
        Write-Host "...SSH $name set correctly to $results on $($vmhost.name)" -ForegroundColor Green
    }Else{
        Write-ToConsoleYellow "...Configuring SSH $name on $($vmhost.name) to $value"
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
    }
}

# SSH permit tunnel
Function ESXI-80-000209($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000209"
	$Title = "The ESXi host Secure Shell (SSH) daemon must not permit tunnels."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = [string]$stigsettings.sshPermittunnel.Keys
    $value = [string]$stigsettings.sshPermittunnel.Values
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    If($results -eq $value){
        Write-Host "...SSH $name set correctly to $results on $($vmhost.name)" -ForegroundColor Green
    }Else{
        Write-ToConsoleYellow "...Configuring SSH $name on $($vmhost.name) to $value"
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
    }
}

# SSH clientalivecountmax
Function ESXI-80-000210($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000210"
	$Title = "The ESXi host Secure Shell (SSH) daemon must set a timeout count on idle sessions."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = [string]$stigsettings.sshClientalivecountmax.Keys
    $value = [string]$stigsettings.sshClientalivecountmax.Values
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    If($results -eq $value){
        Write-ToConsoleGreen "...SSH $name set correctly to $results on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring SSH $name on $($vmhost.name) to $value"
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
    }
}

# SSH clientalivecinterval
Function ESXI-80-000211($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000211"
	$Title = "The ESXi host Secure Shell (SSH) daemon must set a timeout interval on idle sessions."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = [string]$stigsettings.sshClientaliveinterval.Keys
    $value = [string]$stigsettings.sshClientaliveinterval.Values
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    If($results -eq $value){
        Write-ToConsoleGreen "...SSH $name set correctly to $results on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring SSH $name on $($vmhost.name) to $value"
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
    }
}

# SSH allowtcpforwarding
Function ESXI-80-000230($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000230"
	$Title = "The ESXi host Secure Shell (SSH) daemon must disable port forwarding."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = [string]$stigsettings.sshAllowtcpforwarding.Keys
    $value = [string]$stigsettings.sshAllowtcpforwarding.Values
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.ssh.server.config.list.invoke() | Where-Object {$_.Key -eq $name} | Select-Object -ExpandProperty Value
    If($results -eq $value){
        Write-ToConsoleGreen "...SSH $name set correctly to $results on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring SSH $name on $($vmhost.name) to $value"
        $sshsargs = $esxcli.system.ssh.server.config.set.CreateArgs()
        $sshsargs.keyword = $name
        $sshsargs.value = $value
        $esxcli.system.ssh.server.config.set.Invoke($sshsargs)
    }
}

## Lockdown Exception Users
Function ESXI-80-000201($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000201"
    $Title = "The ESXi host lockdown mode exception users list must be verified."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $vmhostv = $vmhost | Get-View 
    $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop
    $exceptions = $lockdown.QueryLockdownExceptions()
    if ($exceptions.count -eq "1" -and $lockdown.QueryLockdownExceptions() -contains $stigsettings.ExceptionUser) {
        Write-Host $vmhost.name "Exception User List already contains" $exceptions  -ForegroundColor Green
    }else{
        $lockdown.UpdateLockdownExceptions($stigsettings.ExceptionUser)
        Write-ToConsoleYellow "$($stigsettings.ExceptionUser) added to the Exception User List on $($vmhost.name)"
    }
}

# FIPS 140-2 SSH daemon
Function ESXI-80-000014($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000014"
    $Title = "The ESXi host Secure Shell (SSH) daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.security.fips140.ssh.get.invoke()
    if($results.enable -eq "true"){
        Write-ToConsoleGreen "...FIPS140 for ssh is enabled on $($vmhost.name)"
    }else{
        Write-ToConsoleYellow "...Enabling FIPS140 for ssh on $($vmhost.name)"
        $arguments = $esxcli.system.security.fips140.ssh.set.CreateArgs()
        $arguments.enable = $true
        $esxcli.system.security.fips140.ssh.set.Invoke($arguments)
    }
}

# VIB Acceptance
Function ESXI-80-000133($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000133"
    $Title = "The ESXi Image Profile and vSphere Installation Bundle (VIB) acceptance level must be verified."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.software.acceptance.get.Invoke()
    if($results -ne "CommunitySupported"){
        Write-ToConsoleGreen "...VIB Acceptance level is set correctly to $results on $($vmhost.name)"
    }else{
        Write-ToConsoleYellow "...Configuring VIB Acceptance level back to the default of PartnerSupported on $($vmhost.name)"
        $vibargs = $esxcli.software.acceptance.set.CreateArgs()
        $vibargs.level = "PartnerSupported"
        $esxcli.software.acceptance.set.Invoke($vibargs)
    }
}

# SNMP
Function ESXI-80-000212($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000212"
    $Title = "The ESXi host must disable Simple Network Management Protocol (SNMP) v1 and v2c."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.snmp.get.Invoke()
    if($results.enable -eq "false"){
        Write-ToConsoleGreen "...SNMP is not being used and is disabled on $($vmhost.name)"
    }else{
        Write-ToConsoleYellow "...Disabling SNMP on $($vmhost.name)"
        $vibargs = $esxcli.system.snmp.set.CreateArgs()
        $vibargs.enable = "false"
        $esxcli.system.snmp.set.Invoke($vibargs)
    }
}

# Firewall Rules
Function  ESXI-80-000239($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000239"
	$Title = "The ESXi host must configure the firewall to restrict access to services running on the host."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $fwsys = Get-View $vmhost.ExtensionData.ConfigManager.FirewallSystem
    # Get a list of all enabled firewall rules that are user configurable that allow all IP addresses
    $fwservices = $fwsys.FirewallInfo.Ruleset | Where-Object {($_.IpListUserConfigurable -eq $true) -and ($_.Enabled -eq $true) -and ($_.AllowedHosts.AllIp -eq $true) } | Sort-Object Key
    If(-not $fwservices){
	    Write-ToConsoleGreen "...ESXi Firewall Policy set correctly on $vmhost"
    }Else{
	    # Populate new allowed IP networks object
		$newIpNetworks = @()
		ForEach ($allowedIpNetwork in $stigsettings.allowedips) {
			$allowedNetwork,$allowedNetworkPrefix = $allowedIpNetwork.split('/')
			$tmp = New-Object VMware.Vim.HostFirewallRulesetIpNetwork
			$tmp.network = $allowedNetwork
			$tmp.prefixLength = $allowedNetworkPrefix
			$newIpNetworks+=$tmp
		}
		# Loop through each firewall service that is user configurable, enabled, and currently set to allow all IPs
		ForEach($fwservice in $fwservices){
			Write-ToConsoleYellow "...Configuring ESXi Firewall Policy on service $($fwservice.Label) to $($stigsettings.allowedips) on $vmhost"
			# Add 169.254.0.0/16 range to hyperbus service if NSX is in use for internal communication
			If($fwservice.Key -eq "hyperbus"){
				$nsxIpNetworks = @()
				ForEach ($allowedIpNetwork in $stigsettings.allowedips) {
					$allowedNetwork,$allowedNetworkPrefix = $allowedIpNetwork.split('/')
					$tmp = New-Object VMware.Vim.HostFirewallRulesetIpNetwork
					$tmp.network = $allowedNetwork
					$tmp.prefixLength = $allowedNetworkPrefix
					$nsxIpNetworks+=$tmp
				}
				$tmp = New-Object VMware.Vim.HostFirewallRulesetIpNetwork
				$tmp.network = "169.254.0.0"
				$tmp.prefixLength = "16"
				$nsxIpNetworks+=$tmp
				# Create new object for rule IP list and disable allow all IPs
				$rulesetIpListSpec = New-Object VMware.Vim.HostFirewallRulesetIpList
				$rulesetIpListSpec.allIp = $false
				$rulesetIpListSpec.ipNetwork = $nsxIpNetworks
				# Create new object for update firewall rules with new IP ranges
				$rulesetSpec = New-Object VMware.Vim.HostFirewallRulesetRulesetSpec
				$rulesetSpec.allowedHosts = $rulesetIpListSpec

				$fwsys.UpdateRuleset($fwservice.Key, $rulesetSpec)
			}Else{
				# Create new object for rule IP list and disable allow all IPs
				$rulesetIpListSpec = New-Object VMware.Vim.HostFirewallRulesetIpList
				$rulesetIpListSpec.allIp = $false
				$rulesetIpListSpec.ipNetwork = $newIpNetworks
				# Create new object for update firewall rules with new IP ranges
				$rulesetSpec = New-Object VMware.Vim.HostFirewallRulesetRulesetSpec
				$rulesetSpec.allowedHosts = $rulesetIpListSpec
				$fwsys.UpdateRuleset($fwservice.Key, $rulesetSpec)
			}
		}
	}
}

# Default Firewall Policy
Function ESXI-80-000214($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000214"
	$Title = "The ESXi host must configure the firewall to block network traffic by default."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.network.firewall.get.invoke()
    If($results.DefaultAction -ne "DROP" -or  $results.Enabled -ne "true"){
        Write-ToConsoleYellow "...Default firewall policy not configured correctly on $($vmhost.name)...disabling inbound/outbound traffic by default"
        $fwargs = $esxcli.network.firewall.set.CreateArgs()
        $fwargs.enabled = $true
        $fwargs.defaultaction = $false
        $esxcli.network.firewall.set.Invoke($fwargs)
    }Else{
        Write-ToConsoleGreen "...Default firewall policy configured correctly on $($vmhost.name)"
    }
}

# Forged Transmits
Function ESXI-80-000216($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000216"
    $Title = "The ESXi host must configure virtual switch security policies to reject forged transmits."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
    If($switches.count -eq 0){
        Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name)"
    }Else{
        ForEach($sw in $switches){
            $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.ForgedTransmits -eq $true){
                Write-ToConsoleYellow "...Forged Transmits enabled $($sw.name) on $($vmhost.name)"
                $secpol | Set-SecurityPolicy -ForgedTransmits $false -Confirm:$false -ErrorAction Stop
            }Else{
                Write-ToConsoleGreen "...Forged Transmits disabled $($sw.name) on $($vmhost.name)"
            }
        }
        $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
        ForEach($pg in $portgroups){
            $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.ForgedTransmits -eq $true -xor $secpol.ForgedTransmitsInherited -eq $false){
                Write-ToConsoleYellow "...Forged Transmits enabled $($pg.name) on $($vmhost.name)"
                $secpol | Set-SecurityPolicy -ForgedTransmitsInherited $true -Confirm:$false -ErrorAction Stop
            }Else{
                Write-ToConsoleGreen "...Forged Transmits disabled $($pg.name) on $($vmhost.name)"
            }
        }
    }            
}

# MAC Changes
Function ESXI-80-000217($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000217"
	$Title = " The ESXi host must configure virtual switch security policies to reject Media Access Control (MAC) address changes."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
    If($switches.count -eq 0){
        Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name)"
    }Else{
        ForEach($sw in $switches){
            $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.MacChanges -eq $true){
                Write-ToConsoleYellow "...MAC changes enabled $($sw.name) on $($vmhost.name)"
                $secpol | Set-SecurityPolicy -MacChanges $false -Confirm:$false -ErrorAction Stop
            }Else{
                Write-ToConsoleGreen "...MAC changes disabled $($sw.name) on $($vmhost.name)"
            }
        }
        $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
        ForEach($pg in $portgroups){
            $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.MacChanges -eq $true -xor $secpol.MacChangesInherited -eq $false){
                Write-ToConsoleYellow "...MAC changes enabled $($pg.name) on $($vmhost.name)"
                $secpol | Set-SecurityPolicy -MacChangesInherited $true -Confirm:$false -ErrorAction Stop
            }Else{
                Write-ToConsoleGreen "...MAC changes disabled $($pg.name) on $($vmhost.name)"
            }
        }
    }            
}

# Promiscious Mode
Function ESXI-80-000218($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000218"
	$Title = "The ESXi host must configure virtual switch security policies to reject promiscuous mode requests."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
    If($switches.count -eq 0){
        Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name)"
    }Else{
        ForEach($sw in $switches){
            $secpol = $sw | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.AllowPromiscuous -eq $true){
                Write-ToConsoleYellow "...Promiscious mode enabled $($sw.name) on $($vmhost.name)"
                $secpol | Set-SecurityPolicy -AllowPromiscuous $false -Confirm:$false -ErrorAction Stop
            }Else{
                Write-ToConsoleGreen "...Promiscious mode disabled $($sw.name) on $($vmhost.name)"
            }
        }
        $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard
        ForEach($pg in $portgroups){
            $secpol = $pg | Get-SecurityPolicy -ErrorAction Stop
            If($secpol.AllowPromiscuous -eq $true -xor $secpol.AllowPromiscuousInherited -eq $false){
                Write-ToConsoleYellow "...Promiscious mode enabled $($pg.name) on $($vmhost.name)"
                $secpol | Set-SecurityPolicy -AllowPromiscuousInherited $true -Confirm:$false -ErrorAction Stop
            }Else{
                Write-ToConsoleGreen "...Promiscious mode disabled $($pg.name) on $($vmhost.name)"
            }
        }
    }            
}

# SLPD Disabled
Function ESXI-80-000231($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000231"
	$Title = "The ESXi host OpenSLP service must be disabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $servicename = "slpd"
    $esxHostservice = $vmhost | Get-VMHostService -ErrorAction Stop | Where-Object {$_.Label -eq $servicename}
    If($esxHostservice.Running -eq $true){
        If($stigsettings.slpdEnabled -eq $false){
            Write-ToConsoleYellow "...Stopping service $servicename on $($vmhost.name)"
            $esxHostservice | Set-VMHostService -Policy Off -Confirm:$false -ErrorAction Stop
            $esxHostservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop
        }Else{
            Write-ToConsoleRed "...Service $servicename is configured to be running on $($vmhost.name). Ensure a waiver is on file."
        }
	}Else{
		Write-ToConsoleGreen "...Service $servicename on $($vmhost.name) already stopped"
	} 
}

# TPM Encryption
Function ESXI-80-000238($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000238"
	$Title = "The ESXi host must require TPM-based configuration encryption."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.settings.encryption.get.invoke()
    If($results.Mode -eq "TPM"){
        Write-ToConsoleGreen "...Configuration encryption set correctly to $($results.Mode) on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring configuration encryption on $($vmhost.name)"
        $tpmencarg = $esxcli.system.settings.encryption.set.CreateArgs()
        $tpmencarg.mode = "TPM"
        $esxcli.system.settings.encryption.set.Invoke($tpmencarg)
    }
}

# Require Secure Boot
Function ESXI-80-000085($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000085"
    $Title = "The ESXi host must implement Secure Boot enforcement."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.settings.encryption.get.invoke()
    If($results.RequireSecureBoot -eq "true"){
        Write-ToConsoleGreen "...Secure Boot required set correctly to $(results.RequireSecureBoot) on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring Secure Boot required on $($vmhost.name)"
        $sbarg = $esxcli.system.settings.encryption.set.CreateArgs()
        $sbarg.requiresecureboot = $true
        $esxcli.system.settings.encryption.set.Invoke($sbarg)
    }
}

# CIM Disabled
Function ESXI-80-000228($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000228"
	$Title = "The ESXi CIM service must be disabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $servicename = "CIM Server"
    $esxservice = $vmhost | Get-VMHostService -ErrorAction Stop | Where-Object {$_.Label -eq $servicename}
    If(($esxservice.Running -eq $true) -or ($esxservice.policy -ne 'off')){
        If($stigsettings.cimEnabled -eq $false){
            Write-ToConsoleYellow "...Stopping service $servicename on $($vmhost.name)"
            $esxservice | Set-VMHostService -Policy off -Confirm:$false -ErrorAction Stop
            $esxservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop
        }Else{
            Write-ToConsoleGreen "...Service $servicename is configured to be running on $($vmhost.name). Ensure a waiver is on file."
        }
    }Else{
        Write-ToConsoleGreen "...Service $servicename on $($vmhost.name) already stopped"
    }
}

# Create Local ESXAdmin
Function LocalESXAdmin($vmhost, $stigsettings){
    $node = Connect-VIServer -Server $vmhost -User root -Password $esxcred.GetNetworkCredential().password -NotDefault
    $users = Get-VIPermission -Server $node
    if ($users.principal -NotContains $esxcred.UserName) {
        Write-ToConsoleYellow "...Adding $($users.principal) on $($vmhost.name)"
        New-VMHostAccount -Id $esxcred.UserName -Password $esxcred.GetNetworkCredential().password -Description $esxcred.UserName -Server $node
        New-VIPermission -Entity $node.name -Principal $esxcred.UserName -Role Admin -Propagate:$true -Server $node
   }
   Disconnect-VIServer $vmhost.name -Confirm:$false 
}

# Entropy
Function ESXI-80-000245($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000245"
	$Title = "The ESXi host must use sufficient entropy for cryptographic operations."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    # hwrng
    $results = $esxcli.system.settings.kernel.list.invoke() | Where-Object {$_.Name -eq "disableHwrng"} | Select-Object -ExpandProperty Configured
    If($results -eq "FALSE"){
        Write-ToConsoleGreen "...disableHwrng set correctly to $results on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring disableHwrng on $($vmhost.name)"
        $enthwargs = $esxcli.system.settings.kernel.set.CreateArgs()
        $enthwargs.setting = "disableHwrng"
        $enthwargs.value = "FALSE"
        $esxcli.system.settings.kernel.set.invoke($enthwargs)
    }
    # sources
    $results = $esxcli.system.settings.kernel.list.invoke() | Where-Object {$_.Name -eq "entropySources"} | Select-Object -ExpandProperty Configured
    If($results -eq "0"){
        Write-ToConsoleGreen "...entropySources set correctly to $results on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring entropySources on $($vmhost.name)"
        $entsrcargs = $esxcli.system.settings.kernel.set.CreateArgs()
        $entsrcargs.setting = "entropySources"
        $entsrcargs.value = "0"
        $esxcli.system.settings.kernel.set.invoke($entsrcargs)
    }
}

# Log Filtering
Function ESXI-80-000246($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000246"
	$Title = "The ESXi host must not enable log filtering."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.syslog.config.logfilter.get.invoke() | Select-Object -ExpandProperty LogFilteringEnabled
    If($results -eq $false){
        Write-ToConsoleGreen "...log filtering set correctly to $results on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring log filtering on $($vmhost.name)"
        $lfargs = $esxcli.system.syslog.config.logfilter.set.CreateArgs()
        $lfargs.logfilteringenabled = $false
        $esxcli.system.syslog.config.logfilter.set.invoke($lfargs)
    }
}

# TLS Profiles
Function ESXI-80-000247($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000247"
	$Title = "The ESXi host must use DOD-approved encryption to protect the confidentiality of network sessions."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $tlscheckargs = $esxcli.system.tls.server.get.CreateArgs()
    $tlscheckargs.showprofiledefaults = $true
    $tlscheckargs.showcurrentbootprofile = $true
    $results = $esxcli.system.tls.server.get.invoke($tlscheckargs) | Select-Object -ExpandProperty Profile
    If($results -eq $stigsettings.tlsServerProfile ){
        Write-ToConsoleGreen "...TLS server profile set correctly to $results on $($vmhost.name)"
    }Else{
        If($vmhost.ConnectionState -eq "Maintenance"){
          Write-ToConsoleYellow "...Host is in Maintenance Mode...Configuring TLS server profile to ($stigsettings.tlsServerProfile) on $($vmhost.name)"
          $tlsargs = $esxcli.system.tls.server.set.CreateArgs()
          $tlsargs.profile = "NIST_2024"
          $esxcli.system.tls.server.set.invoke($tlsargs)
        }Else{
          Write-ToConsoleBlue "...Host $($vmhost.name) is not in Maintenance Mode...skipping control STIG ID:$STIGID with Title: $Title"
        }
    }
}

# Key Persistence
Function ESXI-80-000248($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000248"
	$Title = "The ESXi host must disable key persistence."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.security.keypersistence.get.invoke() | Select-Object -ExpandProperty Enabled
    If($results -eq $false){
        Write-ToConsoleGreen "...key persistence set correctly to $results on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring key persistence on $($vmhost.name)"
        $kpargs = $esxcli.system.security.keypersistence.disable.CreateArgs()
        $kpargs.removeallstoredkeys = $true
        $esxcli.system.security.keypersistence.disable.invoke($kpargs)
    }
}

# DCUI Shell Access
Function ESXI-80-000249($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000249"
	$Title = "The ESXi host must deny shell access for the dcui account."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.account.list.Invoke() | Where-Object {$_.UserID -eq 'dcui'} | Select-Object -ExpandProperty Shellaccess
    If($results -eq $false){
        Write-ToConsoleGreen "...dcui shell access set correctly to $results on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring dcui shell access on $($vmhost.name)"
        $dcuisaargs = $esxcli.system.account.set.CreateArgs()
        $dcuisaargs.id = "dcui"
        $dcuisaargs.shellaccess = "false"
        $esxcli.system.account.set.invoke($dcuisaargs)
    }
}

#===============================================================================================
# Ansible Remediation
#===============================================================================================

# SSH Banner - MOVED TO POWERSHELL MODULE
<#Function ESXI-80-000192($vmhost){
    $STIGID = "ESXI-80-000192"
    $Title = "The ESXi host Secure Shell (SSH) daemon must display the Standard Mandatory DOD Notice and Consent Banner before granting access to the system."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    CheckAnsible
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}#>

# SSH .rhosts - MOVED TO POWERSHELL MODULE
<#Function ESXI-80-000052($vmhost){
    $STIGID = "ESXI-80-000052"
    $Title = "The ESXi host SSH daemon must ignore .rhosts files."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}#>

# SSH hostbasedauth - MOVED TO POWERSHELL MODULE
<#Function ESXI-80-000202($vmhost){
    $STIGID = "ESXI-80-000202"
    $Title = "The ESXi host SSH daemon must not allow host-based authentication."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
} #>


# SSH PermitUserEnvironment - MOVED TO POWERSHELL MODULE
<# Function ESXI-80-000204($vmhost){
    $STIGID = "ESXI-80-000204"
    $Title = "The ESXi host SSH daemon must not permit user environment settings."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}#>

# SSH Gateway Ports - MOVED TO POWERSHELL MODULE
<# Function ESXI-80-000207($vmhost){
    $STIGID = "ESXI-80-000207"
    $Title = "The ESXi host SSH daemon must be configured to not allow gateway ports."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
} #>

# SSH PermitTunnel - MOVED TO POWERSHELL MODULE
<# Function ESXI-80-000209($vmhost){
    $STIGID = "ESXI-80-000209"
    $Title = "The ESXi host SSH daemon must not permit tunnels."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
} #>

# SSH ClientAliveCount - MOVED TO POWERSHELL MODULE
<# Function ESXI-80-000210($vmhost){
    $STIGID = "ESXI-80-000210"
    $Title = "The ESXi host SSH daemon must set a timeout count on idle sessions."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
} #>

# SSH ClientAliveInterval - MOVED TO POWERSHELL MODULE
<# Function ESXI-80-000211($vmhost){
    $STIGID = "ESXI-80-000211"
    $Title = "The ESXi host SSH daemon must set a timeout interval on idle sessions."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
} #>

# SSH allowtcpforwardning - MOVED TO POWERSHELL MODULE
<# Function ESXI-80-000230($vmhost){
    $STIGID = "ESXI-80-000230"
    $Title = "The ESXi host SSH daemon must disable port forwarding."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
} #>

# SSH ciphers - MOVED TO POWERSHELL MODULE
<#Function ESXI-80-000187($vmhost){
    $STIGID = "ESXI-80-000187"
    $Title = "The ESXi host SSH daemon must be configured to only use FIPS 140-2 validated ciphers."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}#>

# Secure Boot
Function ESXI-80-000094($vmhost){
    $STIGID = "ESXI-80-000094"
    $Title = "The ESXi host must enable Secure Boot."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# VM Override
Function ESXI-80-000236($vmhost){
    $STIGID = "ESXI-80-000236"
    $Title = "The ESXi host must not be configured to override virtual machine configurations."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# VM Override Logs
Function ESXI-80-000237($vmhost){
    $STIGID = "ESXI-80-000237"
    $Title = "The ESXi host must not be configured to override virtual machine logger settings."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

#===============================================================================================
# Disable Services and Lockdown Remediations
#===============================================================================================

# SSH Disabled
Function ESXI-80-000193($vmhost){
    $STIGID = "ESXI-80-000193"
    $Title = "The ESXi host must be configured to disable non-essential capabilities by disabling SSH."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $servicename = "SSH"
    $esxservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
    If(($esxservice.Running -eq $true) -or ($esxservice.policy -eq "on")){
        Write-ToConsoleYellow "...Stopping service $servicename on $($vmhost.name)"
        $esxservice | Set-VMHostService -Policy Off -Confirm:$false -ErrorAction Stop 
        $esxservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop 
    }
    Else{
        Write-ToConsoleGreen "...SSH Service already disabled on $($vmhost.name)"
    }
}

# Shell Disabled
Function ESXI-80-000194($vmhost){
    $STIGID = "ESXI-80-000194"
    $Title = "The ESXi host must be configured to disable nonessential capabilities by disabling the ESXi shell."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $servicename = "ESXi Shell"
    $esxservice = $vmhost | Get-VMHostService | Where-Object {$_.Label -eq $servicename} -ErrorAction Stop
    If(($esxservice.Running -eq $true) -or ($esxservice.policy -eq "on")){
        Write-ToConsoleYellow "...Stopping service $servicename on $($vmhost.name)"
        $esxservice | Set-VMHostService -Policy Off -Confirm:$false -ErrorAction Stop 
        $esxservice | Stop-VMHostService -Confirm:$false -ErrorAction Stop 
    }
    Else{
        Write-ToConsoleGreen "...ESXi SHell Service already disabled on $($vmhost.name)"
    }
}

# Enable lockdown mode
Function ESXI-80-000008($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000008"
	$Title = "Access to the ESXi host must be limited by enabling Lockdown Mode."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $vmhostv = $vmhost | Get-View 
    If($vmhostv.config.LockdownMode -ne $stigsettings.lockdownlevel){
        Write-ToConsoleYellow "...Enabling Lockdown mode with level $($stigsettings.lockdownlevel) on $($vmhost.name)"
        $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager -ErrorAction Stop 
        $lockdown.ChangeLockdownMode($stigsettings.lockdownlevel) 
    }
    Else{
        Write-ToConsoleGreen "...Lockdown mode already set to $($stigsettings.lockdownlevel) on $($vmhostv.name)"
    }
}

# Password age
Function ESXI-80-000227($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000227"
    $Title = "The ESXi host must be configured with an appropriate maximum password age."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.passwordMaxAge.Keys
    $value = [string]$stigsettings.passwordMaxAge.Values
    AdvancedSettingSTIG $vmhost $name $value
}

#===============================================================================================
# Manual Remediations
#===============================================================================================

# Active Directory Host Profiles
Function ESXI-80-000240($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000240"
    $Title = "The ESXi host must use the vSphere Authentication Proxy to protect passwords when adding ESXi hosts to Active Directory."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $AuthProxy = $vmhost | Select Name, ` @{N="HostProfile";E={$_ | Get-VMHostProfile}}, ` @{N="JoinADEnabled";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N="JoinDomainMethod";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id}}
    if ($AuthProxy.HostProfile -ne $null -and $AuthProxy.JoinADEnabled -ne $null) {
        Write-ToConsoleRed "...!!!Manually remove HostProfiles from $($vmhost.name)..."
	    Get-VMHostProfile -Name Profile | Remove-VMHostProfile -Confirm:$false
    }else{
        Write-ToConsoleGreen "...HostProfile not used with Domain Creds on $($vmhost.name)"
    }
}

# vMotion Separation
Function ESXI-80-000160($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000160"
    $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by isolating vMotion traffic."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $vmks = $vmhost | Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop
    ForEach($vmk in $vmks){
        If(($vmk.VMotionEnabled -eq "True" -and $vmk.FaultToleranceLoggingEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.ManagementTrafficEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.VsanTrafficEnabled -eq "True")){
            Write-ToConsoleRed "...VMKernel $($vmk.name) appears to have vMotion and another function enabled on the same VMKernel on $($vmhost.name).  Investigate and separate functions to another network and VMKernel."
            # This is a networking setting that should be set during installation. 
        }ElseIf($vmk.VMotionEnabled -eq "True"){
            Write-ToConsoleGreen "...VMKernel $($vmk.name) appears to have vMotion only enabled on $($vmhost.name)"
        }
    }
}

# Management Separation
Function ESXI-80-000198($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000198"
    $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting ESXi management traffic."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $vmks = $vmhost | Get-VMHostNetworkAdapter -VMKernel -ErrorAction Stop
    ForEach($vmk in $vmks){
        If(($vmk.ManagementTrafficEnabled -eq "True" -and $vmk.FaultToleranceLoggingEnabled -eq "True") -xor ($vmk.VMotionEnabled -eq "True" -and $vmk.ManagementTrafficEnabled -eq "True") -xor ($vmk.ManagementTrafficEnabled -eq "True" -and $vmk.VsanTrafficEnabled -eq "True")){
            Write-ToConsoleRed "...VMKernel $($vmk.name) appears to have vMotion and another function enabled on the same VMKernel on $($vmhost.name).  Investigate and separate functions to another network and VMKernel."
        }ElseIf($vmk.VMotionEnabled -eq "True"){
            Write-ToConsoleGreen "...VMKernel $($vmk.name) appears to have vMotion only enabled on $($vmhost.name)"
        }
    }
}

# Storage Separation
Function ESXI-80-000199($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000199"
    $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting IP based management traffic."
    Write-ToConsoleRed "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
}

# iSCSI CHAP
Function ESXI-80-000145($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000145"
    $Title = "The ESXi host must enable bidirectional CHAP authentication for iSCSI traffic."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $iscsi = $vmhost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties
    If($iscsi -ne $null){
        Write-ToConsoleRed "...!!iSCSI in use: This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    }ElseIf($iscsi -eq $null){
        Write-ToConsoleGreen "...iSCSI not in use on $($vmhost.name)"
    }
}

# VLAN Trunk
Function ESXI-80-000220($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000220"
	$Title = "The ESXi host must restrict the use of Virtual Guest Tagging (VGT) on standard switches."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
    If($switches.count -eq 0){
        Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for trunked port groups"
    }Else{
        $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction Stop | Where-Object {$_.VlanId -eq "4095"}
        If($portgroups.count -eq 0){
            Write-ToConsoleGreen "...No standard port groups found with trunked VLANs on $($vmhost.name)"
        }Else{
            ForEach($pg in $portgroups){
                Write-ToConsoleRed "...Portgroup $($pg.name) found with VLAN ID set to 4095 on $($vmhost.name).  Investigate and change or document waiver."
            }
        } 
    }            
}

# ESXi Patches
Function ESXI-80-000221($vmhost, $stigsettings){
	$STIGID = "ESXI-80-000221"
	$Title = "The ESXi host must have all security patches and updates installed."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $build = $vmhost.ExtensionData.Config.Product.build
    If($build -gt $stigsettings.esxiLatestBuild){
        Write-ToConsoleGreen "...ESXi patch $build is newer than $esxiLatestBuild on $($vmhost.name)"
    }ElseIf($build -eq $stigsettings.esxiLatestBuild){
        Write-ToConsoleGreen "...ESXi is the latest build $build on $($vmhost.name)"
    }Else{
        Write-ToConsoleRed "...ESXi is not the latest build $($stigsettings.esxiLatestBuild) on $($vmhost.name)...patch the host with the latest updates!!"
    }
}

# Replace Certs
Function ESXI-80-000229($vmhost, $stigsettings){
    $STIGID = "ESXI-80-000229"
    $Title = "The ESXi host must use DoD-approved certificates."
    Write-ToConsoleBlue "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
}