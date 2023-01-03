#==========================================================================
# NAME: ESXi_STIG_Module.ps1, v1.0.0
# AUTHOR: Peter Stearns
# UPDATED: 12/06/2022
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
            Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $($vmhost.name)"
        }Else{
            Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $($vmhost.name)...setting to $($value)"
            $asetting | Set-AdvancedSetting -Value $value -Confirm:$false
        }
    }Else{
        Write-ToConsoleYellow "...Setting $($name) does not exist on $($vmhost.name)...creating setting..."
        New-AdvancedSetting -Entity $vmhost -Name $name -Value $value -Confirm:$false
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
Function ESXI-70-000002($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000002"
    $Title = "The ESXi host must verify the DCUI.Access list."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.DCUIAccess.Keys
    $value = $stigsettings.DCUIAccess.Values
    AdvancedSettingSTIG $vmhost $name $value
} 

# Syslog
Function ESXI-70-000004($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000004"
    $Title = "Remote logging for ESXi hosts must be configured."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.syslogHost.Keys
    $value = [string]$stigsettings.syslogHost.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Account Lock Failures
Function ESXI-70-000005($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000005"
    $Title = "Remote logging for ESXi hosts must be configured."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.accountLockFailures.Keys
    $value = [string]$stigsettings.accountLockFailures.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Account Unlock Timeout
Function ESXI-70-000006($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000006"
    $Title = "Remote logging for ESXi hosts must be configured."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.accountUnlockTime.Keys
    $value = [string]$stigsettings.accountUnlockTime.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Welcome banner   Annotations.WelcomeMessage
Function ESXI-70-000007($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000007"
    $Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.AnnotationsMessage.Keys
    $value = [string]$stigsettings.AnnotationsMessage.Values
    AdvancedSettingSTIG $vmhost $name $value
}    

# /etc/issue Banner
Function ESXI-70-000008($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000008"
    $Title = "The ESXi host must display the Standard Mandatory DoD Notice and Consent Banner before granting access to the system."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.ConfigEtcIssue.Keys
    $value = [string]$stigsettings.ConfigEtcIssue.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Log Level
Function ESXI-70-000030($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000030"
    $Title = "The ESXi host must produce audit records containing information to establish what type of events occurred."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.logLevel.Keys
    $value = [string]$stigsettings.logLevel.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Password Complexity
Function ESXI-70-000031($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000031"
    $Title = "The ESXi host must enforce password complexity by requiring that at least one upper-case character be used."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.passwordComplexity.Keys
    $value = [string]$stigsettings.passwordComplexity.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Password Reuse
Function ESXI-70-000032($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000032"
    $Title = "The ESXi host must prohibit the reuse of passwords within five iterations."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.passwordHistory.Keys
    $value = [string]$stigsettings.passwordHistory.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Disable MOB per host
Function ESXI-70-000034($vmhost, $stigsettings){
    $STIGID = "ESXI-70-0000034"
    $Title = "The ESXi host must verify the DCUI.Access list."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.enableMob.Keys
    $value = [string]$stigsettings.enableMob.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Shell Interactive Timeout
Function ESXI-70-000041($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000041"
    $Title = "The ESXi host must set a timeout to automatically disable idle shell sessions after two minutes."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.shellIntTimeout.Keys
    $value = [string]$stigsettings.shellIntTimeout.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Shell Timeout
Function ESXI-70-000042($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000042"
    $Title = "The ESXi host must terminate shell services after 10 minutes."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.shellTimeout.Keys
    $value = [string]$stigsettings.shellTimeout.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# DCUI Timeout
Function ESXI-70-000043($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000043"
    $Title = "The ESXi host must log out of the console UI after two minutes."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.DcuiTimeOut.Keys
    $value = [string]$stigsettings.DcuiTimeOut.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Log Persistent Location
Function ESXI-70-000045($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000045"
    $Title = "The ESXi host must enable a persistent log location for all locally stored logs."
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

# Page Sharing
Function ESXI-70-000055($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000055"
	$Title = "The ESXi host must disable Inter-VM transparent page sharing."
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
Function ESXI-70-000058($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000058"
	$Title = "The ESXi host must enable BPDU filter on the host to prevent being locked out of physical switch ports with Portfast and BPDU Guard enabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.BlockGuestBPDU.Keys
    $value = [string]$stigsettings.BlockGuestBPDU.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# DVFilter IP Addresses
Function ESXI-70-000062($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000062"
	$Title = "The ESXi host must prevent unintended use of the dvFilter network APIs."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.DVFilterBindIpAddress.Keys
    $value = [string]$stigsettings.DVFilterBindIpAddress.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# TLS 1.2
Function ESXI-70-000074($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000074"
	$Title = "The ESXi host must exclusively enable TLS 1.2 for all endpoints."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.sslProtocols.Keys
    $value = [string]$stigsettings.sslProtocols.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Suppress Shell Warning 
Function ESXI-70-000079($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000079"
	$Title = "The ESXi host must not suppress warnings that the local or remote shell sessions are enabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.suppressShellWarning.Keys
    $value = [string]$stigsettings.suppressShellWarning.Values
    AdvancedSettingSTIG $vmhost $name $value
}

<# Commenting out until this setting does not break vLCM
## Execute Approved VIBs
Function ESXI-70-000080($vmhost, $stigsettings){
 	$STIGID = "ESXI-70-000080"
 	$Title = "The ESXi host must only run executables from approved VIBs."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.executeVibs.Keys
    $value = [string]$stigsettings.executeVibs.Values
    AdvancedSettingSTIG $vmhost $name $value
}#>

# Suppress Hyperthreading Warning
Function ESXI-70-000081($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000081"
    $Title = "The ESXi host must not suppress warnings about unmitigated hyperthreading vulnerabilities."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.suppressHyperWarning.Keys
    $value = [string]$stigsettings.suppressHyperWarning.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Syslog Cert Check
Function ESXI-70-000086($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000086"
	$Title = "The ESXi host must verify certificates for SSL syslog endpoints."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.syslogCertCheck.Keys
    $value = [string]$stigsettings.syslogCertCheck.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Volatile key destruction
Function ESXI-70-000087($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000087"
	$Title = "The ESXi host must enable volatile key destruction."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.memEagerZero.Keys
    $value = [string]$stigsettings.memEagerZero.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# API timeout
Function ESXI-70-000088($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000088"
	$Title = "The ESXi host must configure a session timeout for the vSphere API."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.apiTimeout.Keys
    $value = [string]$stigsettings.apiTimeout.Values
    AdvancedSettingSTIG $vmhost $name $value
}

# Host Client timeout
Function ESXI-70-000089($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000089"
	$Title = "The ESXi Host Client must be configured with a session timeout."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.hostClientTimeout.Keys
    $value = [string]$stigsettings.hostClientTimeout.Values
    AdvancedSettingSTIG $vmhost $name $value
}

#===============================================================================================
# PowerCLI Script Remediations
#===============================================================================================

## Set the NTP Settings for all hosts
Function ESXI-70-000046($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000046"
    $Title = "The ESXi host must configure NTP time synchronization."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $CurrentNTP = Get-VmHostNtpServer -VMHost $vmhost
    if (!$CurrentNTP){
        $vmhost | Add-VmHostNtpServer -NtpServer $stigsettings.ntpServers 
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -policy On 
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService 
    }
    elseif (Compare-object $CurrentNTP $stigsettings.ntpServers) {
        Write-ToConsoleYellow "...Setting NTP on $($vmhost)..."
        ForEach($ntp in $currentntp){
            $vmhost | Remove-VMHostNtpServer -NtpServer $ntp -Confirm:$false -ErrorAction Stop
        }
        $vmhost | Add-VmHostNtpServer -NtpServer $stigsettings.ntpServers 
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Set-VMHostService -policy On 
        $vmhost | Get-VMHostService | Where-Object {$_.Label -eq "NTP Daemon"} | Start-VMHostService 
    }else{
        Write-ToConsoleGreen "NTP Already Set $CurrentNTP on $($vmhost.name)"
    }
}

# Active Directory
Function ESXI-70-000037($vmhost, $stigsettings){
    if(!$domainCred){$domainCred = Get-Credential -Message "Enter Domain Creds:"}
    $STIGID = "ESXI-70-000037"
    $Title = "The ESXi host must use Active Directory for local user authentication."
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
 
## Lockdown Exception Users
Function ESXI-70-000003($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000003"
    $Title = "The ESXi host must verify the exception users list for lockdown mode."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $vmhostv = $vmhost | Get-View 
    $lockdown = Get-View $vmhostv.ConfigManager.HostAccessManager
    $exceptions = $lockdown.QueryLockdownExceptions()
    if ($exceptions.count -eq "1" -and $lockdown.QueryLockdownExceptions() -contains $stigsettings.ExceptionUser) {
        Write-Host $vmhost.name "Exception User List already contains" $exceptions  -ForegroundColor Green
    }else{
        $lockdown.UpdateLockdownExceptions($stigsettings.ExceptionUser)
        Write-ToConsoleYellow "$($stigsettings.ExceptionUser) added to the Exception User List on $($vmhost.name)"
    }
}

# FIPS 140-2 SSH daemon
Function ESXI-70-000010($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000010"
    $Title = "he ESXi host SSH daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions."
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
Function ESXI-70-000047($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000047"
    $Title = "The ESXi Image Profile and vSphere Installation Bundle (VIB) Acceptance Levels must be verified."
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
Function ESXI-70-000053($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000053"
    $Title = "SNMP must be configured properly on the ESXi host."
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
Function ESXI-70-000056($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000056"
	$Title = "The ESXi host must configure the firewall to restrict access to services running on the host."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    #vSphere Web Client, VMware vCenter Agent, and the Dell VxRail services are excluded from the script due to the order PowerCLI does firewall rules which removes all allowed IPs briefly before setting new allowed ranges which breaks connectivity from vCenter to ESXi so these must be manually done.
    $fwservices = $vmhost | Get-VMHostFirewallException -ErrorAction Stop | Where-Object {($_.Enabled -eq $True) -and ($_.extensiondata.allowedhosts.allip -eq "enabled") -and ($_.Name -ne "vSphere Web Client") -and ($_.Name -ne "dellptagenttcp") -and ($_.Name -ne "dellsshServer") -and ($_.Name -ne "VMware vCenter Agent")}
    $esxcli = $vmhost | Get-EsxCli  -ErrorAction Stop
    ForEach($fwservice in $fwservices){
        $fwsvcname = $fwservice.extensiondata.key
        Write-ToConsoleYellow "...Configuring ESXi Firewall Policy on service $fwsvcname to $($stigsettings.allowedips) on $($vmhost.name)"
        $esxcli.network.firewall.ruleset.set($false,$true,$fwsvcname)
        ForEach($allowedip in $stigsettings.allowedips){
            $esxcli.network.firewall.ruleset.allowedip.add($allowedip,$fwsvcname)
        }
        #Add 169.254.0.0/16 range to hyperbus service if NSX-T is in use for internal communication
        If($fwsvcname -eq "hyperbus"){
            $esxcli.network.firewall.ruleset.set($false,$true,$fwsvcname)
            $esxcli.network.firewall.ruleset.allowedip.add("169.254.0.0/16",$fwsvcname)
        }
    }
    If(-not $fwservices){
        Write-ToConsoleGreen "...ESXi Firewall Policy set correctly on $($vmhost.name)"
    }
}

# Default Firewall Policy
Function ESXI-70-000057($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000057"
	$Title = "The ESXi host must configure the default firewall to block network traffic by default."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $results = $vmhost | Get-VMHostFirewallDefaultPolicy -ErrorAction Stop
    If($results.IncomingEnabled -eq "True" -xor $results.OutgoingEnabled -eq "True"){
        Write-ToConsoleYellow "...Default firewall policy not configured correctly on $($vmhost.name)...disabling inbound/outbound traffic by default"
        $results | Set-VMHostFirewallDefaultPolicy -AllowIncoming $false -AllowOutgoing $false -Confirm:$false -ErrorAction Stop
    }Else{
        Write-ToConsoleGreen "...Default firewall policy configured correctly on $($vmhost.name)"
    }
}

# Forged Transmits
Function ESXI-70-000059($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000059"
    $Title = "The virtual switch Forged Transmits policy must be set to reject on the ESXi host."
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
Function ESXI-70-000060($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000060"
	$Title = "The virtual switch MAC Address Change policy must be set to reject on the ESXi host."
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
Function ESXI-70-000061($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000061"
	$Title = "The virtual switch Promiscuous Mode policy must be set to reject on the ESXi host."
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
Function ESXI-70-000083($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000083"
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

# Audit Logging
Function ESXI-70-000084($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000084"
	$Title = "The ESXi host must enable audit logging."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.auditrecords.get.invoke()
    If(($results.AuditRecordStorageActive -eq "true") -and ($results.AuditRecordStorageCapacity -eq $stigsettings.auditRecords.size) -and ($results.AuditRecordStorageDirectory -like "*$($stigsettings.auditRecords.dir)*" -and ($results.AuditRecordRemoteTransmissionActive -eq "true")){
        Write-ToConsoleGreen "...Audit Records are enabled correctly on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring Audit Record logging on $($vmhost.name)"
        $auditargs = $esxcli.system.auditrecords.local.set.CreateArgs()
        #Commenting out directory option since it is configured correctly if not specified. Must exist if specified.
        #$auditargs.directory = $stigsettings.auditRecords.dir
        $auditargs.size="100"
        $esxcli.system.auditrecords.local.set.Invoke($auditargs)
        $esxcli.system.auditrecords.local.enable.Invoke()
        $esxcli.system.auditrecords.remote.enable.Invoke()
    }
}

# Syslog Cert strict x509 verification
Function ESXI-70-000085($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000085"
	$Title = "The ESXi host must enable strict x509 verification for SSL syslog endpoints."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.syslog.config.get.invoke()
    If($results.StrictX509Compliance -eq "true"){
        Write-ToConsoleGreen "...Syslog x509 strict verification enabled correctly on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring SSH FipsMode on $($vmhost.name)"
        $syslogargs = $esxcli.system.syslog.config.set.CreateArgs()
        $syslogargs.x509strict = $true
        $esxcli.system.syslog.config.set.Invoke($syslogargs)
        $esxcli.system.syslog.reload.Invoke()
    }
}

# Rhttpproxy FIPs
Function ESXI-70-000090($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000090"
	$Title = "The ESXi host rhttpproxy daemon must use FIPS 140-2 validated cryptographic modules to protect the confidentiality of remote access sessions."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $esxcli = Get-EsxCli -VMHost $vmhost -V2 -ErrorAction Stop
    $results = $esxcli.system.security.fips140.rhttpproxy.get.invoke()
    If($results.Enabled -eq "true"){
        Write-ToConsoleGreen "...SSH FipsMode set correctly to $results on $($vmhost.name)"
    }Else{
        Write-ToConsoleYellow "...Configuring SSH FipsMode on $($vmhost.name)"
        $fipsargs = $esxcli.system.security.fips140.rhttpproxy.set.CreateArgs()
        $fipsargs.enable = $true
        $esxcli.system.security.fips140.rhttpproxy.set.Invoke($fipsargs)
    }
}

# TPM Encryption
Function ESXI-70-000094($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000094"
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
Function ESXI-70-000095($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000095"
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
Function ESXI-70-000097($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000097"
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

# CIM Root Access Disabled
Function ESXI-70-000070($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000070"
	$Title = "ESXi host must not provide root/administrator-level access to CIM-based hardware monitoring tools."
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

#===============================================================================================
# Ansible Remediation
#===============================================================================================

# SSH Banner
Function ESXI-70-000009($vmhost){
    $STIGID = "ESXI-70-000009"
    $Title = "The ESXi host SSH daemon must be configured with the DoD logon banner."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    CheckAnsible
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH .rhosts
Function ESXI-70-000012($vmhost){
    $STIGID = "ESXI-70-000012"
    $Title = "The ESXi host SSH daemon must ignore .rhosts files."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH hostbasedauth
Function ESXI-70-000013($vmhost){
    $STIGID = "ESXI-70-000013"
    $Title = "The ESXi host SSH daemon must not allow host-based authentication."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH PermitRootLogin
Function ESXI-70-000014($vmhost){
    $STIGID = "ESXI-70-000014"
    $Title = "The ESXi host SSH daemon must not permit root logins."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH PermitEmptyPasswords
Function ESXI-70-000015($vmhost){
    $STIGID = "ESXI-70-000015"
    $Title = "The ESXi host SSH daemon must not allow authentication using an empty password."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH PermitUserEnvironment
Function ESXI-70-000016($vmhost){
    $STIGID = "ESXI-70-000016"
    $Title = "The ESXi host SSH daemon must not permit user environment settings."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH StrictMode
Function ESXI-70-000020($vmhost){
    $STIGID = "ESXI-70-000020"
    $Title = "The ESXi host SSH daemon must perform strict mode checking of home directory configuration files."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH StrictMode
Function ESXI-70-000021($vmhost){
    $STIGID = "ESXI-70-000021"
    $Title = "The ESXi host SSH daemon must not allow compression or must only allow compression after successful authentication."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH Gateway Ports
Function ESXI-70-000022($vmhost){
    $STIGID = "ESXI-70-000022"
    $Title = "The ESXi host SSH daemon must be configured to not allow gateway ports."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH X11
Function ESXI-70-000023($vmhost){
    $STIGID = "ESXI-70-000023"
    $Title = "The ESXi host SSH daemon must be configured to not allow X11 forwarding."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH PermitTunnel
Function ESXI-70-000025($vmhost){
    $STIGID = "ESXI-70-000025"
    $Title = "The ESXi host SSH daemon must not permit tunnels."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH ClientAliveCount
Function ESXI-70-000026($vmhost){
    $STIGID = "ESXI-70-000026"
    $Title = "The ESXi host SSH daemon must set a timeout count on idle sessions."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH ClientAliveInterval
Function ESXI-70-000027($vmhost){
    $STIGID = "ESXI-70-000027"
    $Title = "The ESXi host SSH daemon must set a timeout interval on idle sessions."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH allowtcpforwardning
Function ESXI-70-000082($vmhost){
    $STIGID = "ESXI-70-000082"
    $Title = "The ESXi host SSH daemon must disable port forwarding."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# SSH ciphers
Function ESXI-70-000274($vmhost){
    $STIGID = "ESXI-70-000274"
    $Title = "The ESXi host SSH daemon must be configured to only use FIPS 140-2 validated ciphers."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# Secure Boot
Function ESXI-70-000076($vmhost){
    $STIGID = "ESXI-70-000076"
    $Title = "The ESXi host must enable Secure Boot."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# VM Override
Function ESXI-70-000092($vmhost){
    $STIGID = "ESXI-70-000092"
    $Title = "The ESXi host must not be configured to override virtual machine configurations."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    if($ansible -ne $null){
        ansible-playbook -i $vmhost, -u $esxcred.UserName $ansiblePlaybook --tags $STIGID -e "ansible_ssh_pass=$($esxcred.GetNetworkCredential().password)"
    }
}

# VM Override Logs
Function ESXI-70-000093($vmhost){
    $STIGID = "ESXI-70-000093"
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
Function ESXI-70-000035($vmhost){
    $STIGID = "ESXI-70-000035"
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
Function ESXI-70-000036($vmhost){
    $STIGID = "ESXI-70-000036"
    $Title = "The ESXi host must disable ESXi Shell unless needed for diagnostics or troubleshooting."
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
Function ESXI-70-000001($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000001"
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
Function ESXI-70-000091($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000091"
    $Title = "The ESXi host must be configured with an appropriate maximum password age."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.passwordMaxAge.Keys
    $value = [string]$stigsettings.passwordMaxAge.Values
    AdvancedSettingSTIG $vmhost $name $value $e
}

#===============================================================================================
# Manual Remediations
#===============================================================================================

# Active Directory Host Profiles
Function ESXI-70-000038($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000038"
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
Function ESXI-70-000048($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000048"
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
Function ESXI-70-000049($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000049"
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
Function ESXI-70-000050($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000050"
    $Title = "The ESXi host must protect the confidentiality and integrity of transmitted information by protecting IP based management traffic."
    Write-ToConsoleRed "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
}

# iSCSI CHAP
Function ESXI-70-000054($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000054"
    $Title = "The ESXi host must enable bidirectional CHAP authentication for iSCSI traffic."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $iscsi = $vmhost | Get-VMHostHba | Where {$_.Type -eq "iscsi"} | Select AuthenticationProperties -ExpandProperty AuthenticationProperties
    If($iscsi -ne $null){
        Write-ToConsoleRed "...!!iSCSI in use: This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
    }ElseIf($iscsi -eq $null){
        Write-ToConsoleGreen "...iSCSI not in use on $($vmhost.name)"
    }
}

# VLAN IDs
Function ESXI-70-000063($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000063"
	$Title = "For the ESXi host all port groups must be configured to a value other than that of the native VLAN."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
    If($switches.count -eq 0){
        Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for native VLAN Id: $($stigsettings.nativeVLANid)"
    }Else{
        $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction Stop | Where-Object {$_.VlanId -eq $stigsettings.nativeVLANid}
        If($portgroups.count -eq 0){
            Write-ToConsoleGreen "...No port groups found with native VLAN Id $($stigsettings.nativeVLANid) on $($vmhost.name)"
        }Else{
            ForEach($pg in $portgroups){
                Write-ToConsoleRed "...Portgroup $($pg.name) found with native VLAN Id: $($stigsettings.nativeVLANid) on $($vmhost.name).  Investigate and change or document waiver."
            }
        } 
    }            
}

# VLAN Trunk
Function ESXI-70-000064($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000064"
	$Title = "For the ESXi host all port groups must not be configured to VLAN 4095 unless Virtual Guest Tagging (VGT) is required."
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

# Reserved VLANs
Function ESXI-70-000065($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000065"
	$Title = "For the ESXi host all port groups must not be configured to VLAN values reserved by upstream physical switches."
    $switches = Get-VirtualSwitch -VMHost $vmhost -Standard -ErrorAction Stop
    If($switches.count -eq 0){
        Write-ToConsoleGreen "...No Standard Switches exist on $($vmhost.name) to check for reserved VLAN IDs on port groups"
    }Else{
        $portgroups = Get-VirtualPortGroup -VMHost $vmhost -Standard -ErrorAction Stop | Where-Object {$_.VlanId -In 1001..1024 -or $_.VlanId -In 3968...4047 -or $_.VlanId -In 4094}
        If($portgroups.count -eq 0){
            Write-ToConsoleGreen "...No standard port groups found with reserved VLAN IDs on $($vmhost.name)"
        }Else{
            ForEach($pg in $portgroups){
                Write-ToConsoleRed "...Portgroup $($pg.name) found with reserved VLAN ID: $($pg.VlanId) on $($vmhost.name).  Investigate and change or document waiver."
            }
        } 
    }            
}

# ESXi Patches
Function ESXI-70-000072($vmhost, $stigsettings){
	$STIGID = "ESXI-70-000072"
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
Function ESXI-70-000078($vmhost, $stigsettings){
    $STIGID = "ESXI-70-000078"
    $Title = "The ESXi host must use DoD-approved certificates."
    Write-ToConsoleBlue "...!!This control must be remediated manually!! Remediating STIG ID:$STIGID with Title: $Title"
}