cls; Write-Host '
#==========================================================================
# NAME: VCSA_STIG_Check.ps1, v2.7.5
# AUTHOR: Peter Stearns
# UPDATED: 11/01/2022
# PROFILE: VMware_vSphere_7.0_VCSA_SRG_v1r4
# DESCRIPTION:
#    -This script runs the Inspec Profile against the VCSA
#    -Then calls Ansible to fix open findings
#    -Outputs a STIG Viewer Checklist file
#    -Prompts to call ESXi and VM STIG Scripts
#==========================================================================
'
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#/////////////////////DECLARE VARIABLES///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$STIG_ver = "VMware_vSphere_7.0_VCSA_SRG_v1r4"

$classification = "U"
$MARKING        = "CUI"
#$vCenter_FQDN  = "domain.com"
#$vCenter_IP    = "x.x.x.x"
$syslogServer   = "x.x.x.x:514"
$ntpServer1     = "x.x.x.x" 
$ntpServer2     = "x.x.x.x"
$authprivlog    = "/var/log/audit/auth.log"

#Prompt for vCenter
# =============================================================================================
$msgvCenter = "Enter vCenter FQDN"
do {
    $vCenter_FQDN  = Read-Host $msgvCenter
    $splitName     = $vCenter_FQDN.split(".") 
    $connection    = Test-Connection -ComputerName $vCenter_FQDN -Count 1 -Quiet
}
until ($vCenter_FQDN -ne $null -and $vCenter_FQDN -ne "" -and $splitName[1] -ne $null -and $connection -eq "True")

$vCenter_IP   = [system.net.dns]::GetHostByName($vCenter_FQDN).AddressList[0].IPAddressToString
$vcsacred     = Get-Credential -UserName 'administrator@vsphere.local'

# Check the Connectivity of vCenter Server
# =============================================================================================
Connect-VIServer -Server $vCenter_FQDN -Credential $vcsacred -ErrorAction SilentlyContinue | Out-Null

If($global:DefaultVIServer -or $global:DefaultVIServers) {
    Disconnect-VIServer * -Confirm:$false
}
else{
     Write-host "Could not connected to $vCenter_FQDN"
     Exit -1
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////COMMENTS and MARKUPS//////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# VCEM-70-000008
# =============================================================================================
$VCEM008 = @{
    VULN_ID = "VCEM-70-000008"

    COMMENT = '
This is NOT A FINDING since the command should exclude configuration files and the file listed is a configuration file, notated by the "c" in the output:
S.5....T.  c /etc/vmware-eam/version

The version file was updated during the last patch.

Proper Commands
rpm -V vmware-eam|grep "^..5......" | grep -v "c /" | grep -v -E ".installer|.properties|.xml"'

    STATUS = "NotAFinding"
}

# VCLU-70-000007
# =============================================================================================
$VCLU007 = @{
    VULN_ID = "VCLU-70-000007"

    COMMENT = '
Lookup Service log files permissions are not set by default. The corrections to permissions have been set but when the logs are recreated they have the wrong permissions.
This will have to be addressed by VMware.'

    STATUS = "Open"
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////Known Open Items///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$KnownIssues = @($VCEM008, $VCLU007)
$KnownIDs   += $KnownIssues | ForEach-Object { $_.VULN_ID } 

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////////INTIALIZE VARIABLES//////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#Get Current Date and Time
$date = Get-Date

Function Write-ToConsole ($Details){
	$LogDate = Get-Date -Format T
	Write-Host "$($LogDate):  $Details"
} 

Write-ToConsole "Setting environment variables...";

$inspecPath      = "$(pwd)/VCSA_STIG_Module/vcsa/inspec/vmware-vcsa-7.0-stig-baseline"
$ansiblePlaybook = "$(pwd)/VCSA_STIG_Module/vcsa/ansible/vmware-vcsa-7.0-stig-ansible-hardening/playbook.yml"
$reportPath      = "$(pwd)/Reports"

$splitName       = $vCenter_FQDN.split(".")
$VCSAshortname   = $splitName[0].ToUpper()

$ENV:RUBYOPT     = 'rubygems'
$ENV:RUBY_DIR    = '/opt/inspec/embedded'
$ENV:GEM_PATH    = '/opt/inspec/embedded/lib/ruby/gems/2.7.0/gems'
$ENV:PATH        = '/opt/inspec/embedded/bin;' + $ENV:PATH

$reportFile      = $reportPath + "/" + $VCSAshortname + "_" + $classification + "_" + $STIG_ver + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".json"
$cklFile         = $reportPath + "/" + $VCSAshortname + "_" + $classification + "_" + $STIG_ver + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".ckl"
$FixReport       = $reportPath + "/" + $VCSAshortname + "_" + "Remediation" + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".json"
$FixCklFile      = $reportPath + "/" + $VCSAshortname + "_" + "Remediation" + "-" + $Date.Month + "-" + $Date.Day + "-" + $Date.Year + ".ckl"

$ENV:VISERVER           = $vCenter_FQDN
$ENV:VISERVER_USERNAME  = $vcsacred.UserName
$ENV:VISERVER_PASSWORD  = $vcsacred.GetNetworkCredential().password

ln -sf "$(pwd)/VCSA_STIG_Module/photon/inspec/vmware-photon-3.0-stig-inspec-baseline"                  "$(pwd)/VCSA_STIG_Module/vcsa/inspec/vmware-photon-3.0-stig-inspec-baseline"
ln -sf "$(pwd)/VCSA_STIG_Module/photon/ansible/vmware-photon-3.0-stig-ansible-hardening/roles/photon3" "$(pwd)/VCSA_STIG_Module/vcsa/ansible/vmware-vcsa-7.0-stig-ansible-hardening/roles/photon3"

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////// RUN INSPEC TO FIND OPEN ITEMS ////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Check to see if current CKL File exists (Matches date and server name)
# =============================================================================================
If(Test-Path -Path $cklFile){

    Write-ToConsole "*********************************************"
    Write-ToConsole "Current CKL File found $($cklFile)..."
    $msgInspec = "$(Get-Date -Format T):  Re-Run Inspec for $($VCSAshortname)? [y/n]"
    do {
        $responseInspec = Read-Host -Prompt $msgInspec
    }
    until ($responseInspec -eq "y" -or $responseInspec -eq "n")
}

Else{
    $responseInspec = "y"
}

# Run Inspec profile against vCenter
# =============================================================================================
If($responseInspec -eq "y"){
    Try{
        Write-ToConsole "Running Inspec exec against $($VCSAshortname)"
        inspec exec $inspecPath -t ssh://root@$vCenter_FQDN --password $vcsacred.GetNetworkCredential().password --input authprivlog=$authprivlog syslogServer=$syslogServer ntpServer1=$ntpServer1 ntpServer2=$ntpServer2 --show-progress --reporter json:$reportFile
        Write-ToConsole "Generating STIG Checklist for $($VCSAshortname)"
        inspec_tools inspec2ckl -j $reportFile -o $cklFile
    }Catch{Write-Error "Failed to run Inspec profile against $($VCSAshortname)... $_.Exception"; Exit -1}
}

# Continue remediating with current CKL File
# =============================================================================================
elseif($responseInspec -eq "n"){
    Write-ToConsole "*********************************************"
    Write-ToConsole "Using current CKL File to remediate open items..."
}

# Create XML object from CKL
# =============================================================================================
Try{$xmlCkl = ( Select-Xml -Path $cklFile -XPath / ).Node}
Catch{Write-Error "Failed to import CKL.."; Exit -1}

# Find all OPEN ITEMS compare to known issues
# =============================================================================================

$OpenItems = @()
$xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
    $OpenItems += $_.STIG_DATA[0].ATTRIBUTE_DATA
}

$FixItems = $OpenItems | Where-Object { $KnownIDs -notcontains $_ }

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#/////////////////////// REMEDIATION OPEN ITEMS //////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

if($FixItems){

    Write-ToConsole
    Write-ToConsole "*********************************************"
    Write-ToConsole "The Following Items will need to Remediated"
    Write-ToConsole "*********************************************"
    Write-ToConsole $FixItems

    $msg = "$(Get-Date -Format T):  Run Ansible to remediate items? [y/n]"
    do {$response = Read-Host -Prompt $msg
    }until ($response -eq "y" -or $response -eq "n")

    if($response -eq "y"){
        
        # Running Ansible on Open Items
        # =============================================================================================
       
        $FixItemString = $FixItems -join ","
        ansible-playbook -i $vCenter_FQDN, -u root $ansiblePlaybook --tags $FixItemString -e "ansible_ssh_pass=$($vcsacred.GetNetworkCredential().password)"

        # Running Inspec to Verify Items
        # =============================================================================================
        
        inspec exec $inspecPath -t ssh://root@$vCenter_FQDN --password $vcsacred.GetNetworkCredential().password --input authprivlog=$authprivlog syslogServer=$syslogServer ntpServer1=$ntpServer1 ntpServer2=$ntpServer2 --show-progress --reporter json:$FixReport --controls $FixItems
        inspec_tools inspec2ckl -j $FixReport -o $FixCklFile

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
    }

    elseif($response -eq "n"){
        Write-ToConsole "*********************************************"
        Write-ToConsole "Finializing STIG CKL without remediating open items..."
    }
}

else{
    Write-ToConsole "*********************************************"
    Write-ToConsole "All STIG items are remediated" 
    Write-ToConsole "Finializing STIG CKL..."
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#/////////////////UPDATE CKL ASSEST INFO and MARKUPS//////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Update CKL FILE With ASSET Info
# =============================================================================================
# Find Asset String
if($xmlCkl){

    Write-ToConsole "Updating Assest Info..."
    $xmlCkl.CHECKLIST.ASSET.ROLE            = "Member Server"
    $xmlCkl.CHECKLIST.ASSET.ASSET_TYPE      = "Computing"
    $xmlCkl.CHECKLIST.ASSET.HOST_NAME       = $VCSAshortname
    $xmlCkl.CHECKLIST.ASSET.HOST_IP         = $vCenter_IP
    $xmlCkl.CHECKLIST.ASSET.HOST_FQDN       = $vCenter_FQDN
    $xmlCkl.CHECKLIST.ASSET.WEB_OR_DATABASE = "false"

    # Find and Markup Known Issues
    # =============================================================================================

    foreach ($KnownID in $KnownIDs)
        {
            Write-ToConsole "Updating $KnownID..."
            $Vuln_Node          = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $KnownID }
            $Vuln_Object        = $KnownIssues | where-object VULN_ID -contains $KnownID
            $Vuln_Node.COMMENTS = $Vuln_Object.COMMENT
            $Vuln_Node.STATUS   = $Vuln_Object.STATUS
        }

    # Save XML data to CKL file
    # =============================================================================================
    Write-ToConsole "Saving File..."
    $xmlCkl.Save($cklFile)

    # =============================================================================================
    # Find and Replace Loop

    $FindTitle    = 'Untitled - Checklist Created from Automated InSpec Results'
    $ReplaceTitle = "$STIG_ver - Checklist Created from Automated InSpec Results"
       
    (Get-Content $cklFile -Raw).
    Replace($FindTitle,$ReplaceTitle).
    Replace('CUI',$MARKING)| 
    Set-Content $cklFile

    chmod 755 $cklFile
    Write-ToConsole "STIG Check completed output file: $($cklFile)"

    # List Open Items
    # =============================================================================================
    $xmlCkl = ( Select-Xml -Path $cklFile -XPath / ).Node
    $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
    
        $OpenItems += $_.STIG_DATA[0].ATTRIBUTE_DATA
        if($_.STIG_DATA[0].ATTRIBUTE_DATA -in $KnownIDs){$Known = "True"}
        else {$Known = "False"}
    
        [pscustomobject]@{
	        OpenID = $_.STIG_DATA[0].ATTRIBUTE_DATA
            Known = $Known
	        }
    }
}
else{Write-Error "Failed to run read XML..."; Exit -1}

# CleanUp
# =============================================================================================
if($FixReport){Remove-Item -Path $FixReport -erroraction 'silentlycontinue'}
if($FixcklFile){Remove-Item -Path $FixcklFile -erroraction 'silentlycontinue'}
if($reportFile){Remove-Item -Path $reportFile -erroraction 'silentlycontinue'}
rm -df "$(pwd)/VCSA_STIG_Module/vcsa/ansible/vmware-vcsa-7.0-stig-ansible-hardening/roles/photon3" "$(pwd)/VCSA_STIG_Module/vcsa/inspec/vmware-photon-3.0-stig-inspec-baseline"
