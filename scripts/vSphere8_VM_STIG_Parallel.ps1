<# 
#==========================================================================
# NAME: vSphere_VM_STIG.ps1, v3.0 (Parallel)
# AUTHOR: Peter Stearns
# UPDATED: 10/16/2024 - vSphere 8 updates
# PROFILE: VMware_vSphere_8.0_VM_STG_v2r1
# DESCRIPTION:
#    -This script runs the Inspec Profile against all VMs in a VCSA
#    -Then calls Ansible and Powershell to fix open findings
#    -Outputs a STIG Viewer Checklist file per VM
#==========================================================================

    Tested against
    -PowerCLI 12.6
    -Powershell 5/Core 7.2.6
    -vCenter/ESXi 8.0 U3

    Example command to run script
    .\vSphere_VM_STIG.ps1 -vcenter vcentername.test.local -vm vm.name

    .PARAMETER vcenter
    Enter the FQDN or IP of the vCenter Server to connect to
    .PARAMETER vm
    Enter the name of a single VM to remediate
    .PARAMETER cluster
    Enter the cluster name of a vSphere cluster to remediate all VMs in a targeted cluster
#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$vcenter,
    [Parameter()]
    [string]$cluster,
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
Start-Transcript -path /opt/stigtools/vsphere8/transcript/vm.log -append -Force

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#/////////////////////DECLARE VARIABLES///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$STIG_ver = "VMW_VSPHERE_8-0_VM_V2R1"
$NAME = "vSphere_VM_STIG.ps1, v3.0 (Parallel)"
$UPDATED = "10/16/2024"
$workingdir = "/opt/stigtools/vsphere8"

$classification = "U"
$MARKING        = "CUI"

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////////////STIG Values//////////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#Hardening/STIG Settings
$stigsettings = [ordered]@{
    copyDisable            = @{"isolation.tools.copy.disable"           = $true}        #VMCH-80-000189
    dndDisable             = @{"isolation.tools.dnd.disable"            = $true}        #VMCH-80-000191
    pasteDisable           = @{"isolation.tools.paste.disable"          = $true}        #VMCH-80-000192
    diskShrink             = @{"isolation.tools.diskShrink.disable"     = $true}        #VMCH-80-000193
    diskWiper              = @{"isolation.tools.diskWiper.disable"      = $true}        #VMCH-80-000194
    RemoteDisplayMax       = @{"RemoteDisplay.maxConnections"           = "1"}          #VMCH-80-000195
    setinfoSizeLimit       = @{"tools.setinfo.sizeLimit"                = "1048576"}    #VMCH-80-000196
    deviceConnectable      = @{"isolation.device.connectable.disable"   = $true}        #VMCH-80-000197
    guestlibEnableHostInf  = @{"tools.guestlib.enableHostInfo"          = $false }      #VMCH-80-000198
    desktopAutolock        = @{"tools.guest.desktop.autolock"           = $true}        #VMCH-80-000201
    mksEnable3d            = @{"mks.enable3d"                           = $false}       #VMCH-80-000202
    logRotateSize          = @{"log.rotateSize"                         = "2048000"}    #VMCH-80-000205
    logKeepOld             = @{"log.keepOld"                            = "10"}         #VMCH-80-000206
    schedMemPshareSalt     = "sched.mem.pshare.salt"      								#VMCH-80-000199
    vmotionEncryption      = "opportunistic"              								#VMCH-80-000203 #disabled, required, opportunistic  
    ftEncryption           = "ftEncryptionOpportunistic"  								#VMCH-80-000204 #ftEncryptionRequired,ftEncryptionOpportunistic 
    vmLogging              = $true                        								#VMCH-80-000207
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////COMMENTS and MARKUPS//////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# VMCH-80-000213
# =============================================================================================
$VMCH213 = @{
    VULN_ID = "VMCH-80-000213"

    COMMENT = '     
USB smart card readers are used to pass smart cards through the VM console to a VM.
The use of a USB controller and USB devices is for that purpose, this is not a finding'

    STATUS = "NotAFinding"
}

# VMCH-80-000202
# =============================================================================================
$VMCH202 = @{
    VULN_ID = "VMCH-80-000202"

    COMMENT = '     
The discussion states: For performance reasons, it is RECOMMENDED that 3D acceleration be disabled on virtual machines that DO NOT require 3D functionality.
3D support is required for VDI desktops in the training environment for applications such as mapping applications. Therefore this is NOT A FINDING.

3D Features are disabled on non-VDI VMs that do not require 3D support.
'

    STATUS = "NotAFinding"
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////Known Open Items///////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

$KnownIssues = @($VMCH213,$VMCH202)
$KnownIDs   += $KnownIssues | ForEach-Object { $_.VULN_ID }

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////// INTIALIZE VARIABLES ///////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
Write-Host "
#==========================================================================
# NAME: $NAME
# AUTHOR: Peter Stearns
# UPDATED: $UPDATED
# PROFILE: $($STIG_ver)
# DESCRIPTION: Runs Inspec and Ansible to STIG VMs
# WORKING DIR: $($workingdir)
#==========================================================================
"

# Intialize Varibles
# =============================================================================================
if($vcenter){$vCenter_FQDN = "$($vcenter)"}
if($cluster){$SUBTARGET = "$($cluster)"}

#Prompt Varibles
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

if(!$vcsaAdmnCred){ $vcsaAdmnCred = Get-Credential -Message "Enter administrator@vsphere Creds:" }
if(!$RunBy){ $RunBy = Read-Host -Prompt "Enter your full name" }

# Import VM Remediation Module
Import-Module "$($workingdir)/VMs_STIG_Module/vmware-vm-8.0-stig-module.ps1" -DisableNameChecking -force

If($global:DefaultVIServer -or $global:DefaultVIServers) {
    Disconnect-VIServer * -Confirm:$false
}

# Get Current Date and Time
$date = Get-Date
$dateStr = (Get-Date -Format "yyyMMdd")

$splitName       = $vCenter_FQDN.split(".")
$VCSAshortname   = $splitName[0].ToUpper()

$ENV:RUBYOPT    = 'rubygems'
$ENV:RUBY_DIR   = '/opt/cinc-auditor/embedded'
$ENV:GEM_PATH   = '/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems'
$ENV:PATH       = '/opt/cinc-auditor/embedded/bin;' + $ENV:PATH
$ENV:NO_COLOR   = $true

$ENV:VISERVER           = $vCenter_FQDN
$ENV:VISERVER_USERNAME  = $vcsaAdmnCred.UserName
$ENV:VISERVER_PASSWORD  = $vcsaAdmnCred.GetNetworkCredential().password

$inspecPath      = "$($workingdir)/dod-compliance-and-automation-master/vsphere/8.0/v2r1-stig/vsphere/inspec/vmware-vsphere-8.0-stig-baseline/vm"
$VulnID_mapper   = "$($workingdir)/VulnID_mapper8.csv"
$reportPath      = "$($workingdir)/Reports/" + $VCSAshortname + "/VMs"
$csvPath         = "$($workingdir)/Reports/" + $VCSAshortname + "/Open_VM_STIGs_Report.csv"
$templateCklFile = "/opt/stigtools/vsphere8/CKL_Templates/U_VMW_vSphere_8-0_Virtual_Machine_STIG_V2R1.ckl"

$vmVarTable      = [ordered]@{}
$vmVarTable      = [System.Collections.Hashtable]::Synchronized($vmVarTable)
$vmResultTable   = [ordered]@{}
$vmResultTable   = [System.Collections.Hashtable]::Synchronized($vmResultTable)
$OpenReport      = [ordered]@{}
$remediateTable  = [ordered]@{}

$NameDateTag = "

Automated checks run by: $RunBy on $(date +%F)"

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#///////////////////////////// FUNCTIONS ////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
if(!$silent){
    Function Write-ToConsole ($Details) {
	    $LogDate = Get-Date -Format T
	    Write-Host "$($LogDate): $Details"
    }
}Else{Function Write-ToConsole ($Details) { write-host . -NoNewline}}

Function InspecVM () {
    param (
        [object]$vm,
        [hashtable]$vmVarTable,
        [hashtable]$vmResultTable,
        [string]$VCSAshortname
    )

    $variableObj = $vmVarTable[$vm]
    ${function:Write-ToConsole} = $variableObj.WriteToConsole
    $inspecPath   = $variableObj.inspecPath
    $MARKING      = $variableObj.MARKING
    $KnownIDs     = $variableObj.KnownIDs
    $KnownIssues  = $variableObj.KnownIssues
    $NameDateTag  = $variableObj.NameDateTag
    $vmName       = $vm.Name
    $vmShortName  = $variableObj.vmShortName
    $vmDNSName    = $variableObj.vmDNSName
    $vm_IP        = $variableObj.vm_IP
    $macaddress   = $variableObj.macaddress
    $reportFile   = $variableObj.reportFile
    $cklFile      = $variableObj.cklFile
    $fixreportFile = $variableObj.fixreportFile
    $fixcklFile    = $variableObj.fixcklFile

    Start-Sleep -Seconds (Get-Random -Minimum 0 -Maximum 5)

    if($reportFile){Remove-Item -Path $reportFile -erroraction 'silentlycontinue'}

    # INSPEC VMs VMware transport
    # =============================================================================================
    Write-ToConsole "$($VCSAshortname) - Running CLI Inspec for $($vmName)..."
    cinc-auditor exec $inspecPath -t vmware:// --input vmName="$vmName" --reporter json:$reportFile | Out-Null

        # Create CKL Files
    # =============================================================================================
    Write-ToConsole "$VCSAshortname - Generating checklist for $($vm)..."    
    inspec_tools inspec2ckl -j $reportFile -o $cklFile

    # Create XML object from CKL
    # =============================================================================================
    Try{ 
        $xmlCkl = ( Select-Xml -Path $cklFile -XPath / ).Node
    }Catch{ Write-Error "Failed to import CKL.." }

    # Update CKL FILE With ASSET Info
    # =============================================================================================
    $xmlCkl.CHECKLIST.ASSET.ROLE            = "Member Server"
    $xmlCkl.CHECKLIST.ASSET.ASSET_TYPE      = "Computing"
    #$xmlCkl.CHECKLIST.ASSET.MARKING         = $MARKING    
    $xmlCkl.CHECKLIST.ASSET.HOST_NAME       = $vmName
    $xmlCkl.CHECKLIST.ASSET.HOST_IP         = $vm_IP
    $xmlCkl.CHECKLIST.ASSET.HOST_MAC        = $macaddress
    $xmlCkl.CHECKLIST.ASSET.HOST_FQDN       = $vmDNSName
    $xmlCkl.CHECKLIST.ASSET.WEB_OR_DATABASE = "false"

    # Find and Markup Known Issues
    # =============================================================================================
    foreach ($KnownID in $KnownIDs){
        $Vuln_Node          = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $KnownID }
        $Vuln_Object        = $KnownIssues | where-object VULN_ID -contains $KnownID
        if (($Vuln_Node.STATUS -eq "Not_Reviewed") -or ($Vuln_Node.STATUS -eq "NotAFinding") -or ($Vuln_Node.STATUS -eq "Open")){
            $Vuln_Node.COMMENTS = $Vuln_Object.COMMENT
            $Vuln_Node.STATUS   = $Vuln_Object.STATUS
        }
    }

    # Add Name and Date to comments
    # =============================================================================================
    $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | ForEach-Object {
        $CommentValue = $_.COMMENTS
        $_.COMMENTS = $CommentValue + $NameDateTag
    }

    # Save XML data to CKL file
    # =============================================================================================
    Write-ToConsole "$($VCSAshortname) - Saving Checklist for $($vm)..."
    $xmlCkl.Save($cklFile)

    # CleanUp
    # =============================================================================================
    if($reportFile){Remove-Item -Path $reportFile -erroraction 'silentlycontinue'}
    if(!$cklFile){Write-Error "Failed to run Inspec profile against $($vm)... $_.Exception"}

    # Create List Open Items
    # =============================================================================================    
    $OpenItems = @()
    $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
		$RuleID = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Rule_Ver"}).ATTRIBUTE_DATA
        $OpenItem = $RuleID
        $OpenItems += $OpenItem
        if($RuleID -in $KnownIDs){$Known = "True"}
        else {$Known = "False"}
    }
    $vmResultTable.add($variableObj.vmShortName,$OpenItems)
}

Function VulnID2StigID () {
    param(
        [hashtable]$vmVarTable
    )
    # Replace update VULN_ID with proper ID
    # =============================================================================================
    if ($vmVarTable){
        $VulnIDTable = @{}
        Import-CSV $($VulnID_mapper) | % { $VulnIDTable[$_.STIGID] = $_.VulnID }
        $vmVarTable.keys | ForEach-Object {
            $vm = $_
            $variableObj = $vmVarTable[$vm]
            $xmlCkl = ( Select-Xml -Path $variableObj.cklFile -XPath / ).Node
            $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Vuln_Num"} | ForEach-Object {
                $NodeID = $_.ATTRIBUTE_DATA
                $Vuln_ID = $VulnIDTable.Item($NodeID)
                if($Vuln_ID){
	                $_.ATTRIBUTE_DATA = $Vuln_ID
                }
            }
            # Save XML data to CKL file
            $xmlCkl.Save($variableObj.cklFile)
        }
    }
}

Function ListOpenItems () {
    param(
        [array]$KnownIDs,
        [hashtable]$vmVarTable,
        [hashtable]$remediateTable
    )
    # List Open Items
    # ============================================================================================
    $summary = @()
    $vmVarTable.keys | ForEach-Object {
        $vmName = $_
        $variableObj = $vmVarTable[$vmName]
        $remediated = $remediateTable[$vmName]
        $xmlCkl  = ( Select-Xml -Path $variableObj.cklFile -XPath / ).Node
        $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
			$RuleID = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Rule_Ver"}).ATTRIBUTE_DATA
			$VulnID = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Vuln_Num"}).ATTRIBUTE_DATA
            $OpenItems += $RuleID
            if($RuleID -in $variableObj.KnownIDs){$Known = "True"}
            else {$Known = "False"}
            $obj = New-Object -TypeName PSObject
            $obj | Add-Member -MemberType NoteProperty -Name Date -Value (Get-Date -format "dd-MMM-yyyy HH:mm")
            $obj | Add-Member -MemberType NoteProperty -Name VM -Value $vmName
            $obj | Add-Member -MemberType NoteProperty -Name VulnID -Value $VulnID
            $obj | Add-Member -MemberType NoteProperty -Name STIGID -Value $RuleID
            $obj | Add-Member -MemberType NoteProperty -Name Known -value $Known
            $obj | Add-Member -MemberType NoteProperty -Name Remediated -value $remediated
            $summary += $obj
        }
    }
    Write-ToConsole "*********************************************"
    Write-ToConsole "              SUMMARY                        "
    Write-ToConsole "*********************************************"
    Write-Host ($summary | Sort-Object VM | Format-Table | Out-String)
    $summary | Export-Csv $csvPath -Append -Force -NoTypeInformation
}

Function MergeTemplate () {
    param(
        [hashtable]$vmVarTable,
        [string]$templateCklFile
    )
    if ($vmVarTable){
        $vmVarTable.keys | ForEach-Object {
            $vmName = $_
            $variableObj = $vmVarTable[$vmName]
            $finalCklFile = $variableObj.cklFile
            $templateXmlCkl = ( Select-Xml -Path $templateCklFile -XPath / ).Node
            $xmlCkl = ( Select-Xml -Path $variableObj.cklFile -XPath / ).Node
            Write-ToConsole "Merging $($variableObj.cklFile) for $($vmName)"

            # Merge Assest info to template
            # =============================================================================================
            $templateXmlCkl.CHECKLIST.ASSET.ROLE            = $xmlCkl.CHECKLIST.ASSET.ROLE
            $templateXmlCkl.CHECKLIST.ASSET.ASSET_TYPE      = $xmlCkl.CHECKLIST.ASSET.ASSET_TYPE
            $templateXmlCkl.CHECKLIST.ASSET.MARKING         = $variableObj.MARKING
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
            }Catch{Write-Error "Failed to merge into Template CKL for $($vmName)... $_.Exception"}

            # Save XML data to CKL file
            # =============================================================================================
            $tempCklFile = $reportPath + '/' + 'temp_' + $vmName + '.ckl'
            Move-Item -Path $variableObj.cklFile $tempCklFile -Force

            $templateXmlCkl.Save($finalCklFile)
            if($tempCklFile){Remove-Item -Path $tempCklFile -erroraction 'silentlycontinue'}
        }
    }
}

Function RemediateItem () {
    param(
        [array]$OpenItems,
        [object]$vm,
        [array]$xmlCkl,
        [object]$stigsettings,
        [object]$variableObj
    )

    $variableObj = $vmVarTable[$vm]
    ${function:Write-ToConsole} = $variableObj.WriteToConsole
    $inspecPath   = $variableObj.inspecPath
    $MARKING      = $variableObj.MARKING
    $KnownIDs     = $variableObj.KnownIDs
    $KnownIssues  = $variableObj.KnownIssues
    $NameDateTag  = $variableObj.NameDateTag
    $vmName       = $vm.Name
    $vmDNSName    = $variableObj.vmDNSName
    $vm_IP        = $variableObj.vm_IP
    $macaddress   = $variableObj.macaddress
    $reportFile   = $variableObj.reportFile
    $cklFile      = $variableObj.cklFile
    $fixreportFile = $variableObj.fixreportFile
    $fixcklFile    = $variableObj.fixcklFile

    # Running Powershell STIG items
    # =============================================================================================
    write-host $vmName
    foreach ($FixItem in $OpenItems){
        try{
            & $FixItem $vmName $stigsettings
        }catch{Write-Error "Failed remediate $($FixItem) on $($vmName)... $_.Exception"}
    }

    # Running Inspec to Verify Powershell Items
    # =============================================================================================
    cinc-auditor exec $inspecPath -t vmware:// --input vmName="$vmName" --reporter progress-bar json:$fixreportFile --controls $OpenItems
    inspec_tools inspec2ckl -j $fixreportFile -o $fixcklFile

    # Updating CKL with fixed items
    # =============================================================================================
    $xmlFixCkl = ( Select-Xml -Path $FixCklFile -XPath / ).Node
    
    # Add Name and Date to comments
    # =============================================================================================
    $xmlFixCkl.CHECKLIST.STIGS.iSTIG.VULN | ForEach-Object {
        $CommentValue = $_.COMMENTS
        $_.COMMENTS = $CommentValue + $NameDateTag
    }
    
    foreach ($FixItem in $OpenItems){
        $Fix_Node                    = $xmlFixCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $FixItem }
        $xmlCkl_Node                 = $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object { $_.STIG_DATA.ATTRIBUTE_DATA -eq $FixItem }
        $xmlCkl_Node.STATUS          = $Fix_Node.STATUS
        $xmlCkl_Node.COMMENTS        = $Fix_Node.COMMENTS
        $xmlCkl_Node.FINDING_DETAILS = $Fix_Node.FINDING_DETAILS
    }

    # Save XML data to CKL file
    # =============================================================================================
    Write-ToConsole "$($VCSAshortname) - Saving File..."
    $xmlCkl.Save($cklFile)

    # CleanUp
    # =============================================================================================
    if($reportFile){Remove-Item -Path $reportFile -erroraction 'silentlycontinue'}

    if(!$cklFile){Write-Error "Failed to run Inspec profile against $($vmName)... $_.Exception"}
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#////////////////////////////// SCRIPT //////////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
# Verify report folder
# =============================================================================================
if (Test-Path -Path $reportPath -IsValid) {
    Write-ToConsole "$($VCSAshortname) - Validated path for report at $reportPath"
} else {
    Write-ToConsole "$($VCSAshortname) - Report path $reportPath doesn't exist...attempting to create..."
    New-Item -ItemType Directory -Path $reportPath -Force
}

# Connect to vCenter
# =============================================================================================
Connect-VIServer -Server $vCenter_FQDN -Credential $vcsaAdmnCred -ErrorAction SilentlyContinue | Out-Null

#Adjust for VDI
If($vCenter_FQDN -like "*vdi*"){
    Write-ToConsole "...Detected VDI vCenter, running with VDI settings."
    $stigsettings.mksEnable3d.'mks.enable3d' = $null
    $stigsettings.mksEnable3d.'mks.enable3d' = $true
}

Try {
    if ($cluster) {
        Write-ToConsole "$($VCSAshortname) - ...Getting PowerCLI objects for all virtual machines in cluster: $($cluster)"
        # Convert templates to VMs
        $templates = Get-Cluster -Name $cluster | Get-Template
        if ($templates) {
            $templates.name | foreach-object {Set-Template $_ -ToVM -Confirm:$false} | Out-Null
        }
        $vms = Get-Cluster -Name $cluster -ErrorAction Stop | Get-VM -ErrorAction Stop | Where-Object {!$_.Name.Contains("vCLS") -and !$_.Name.Contains("replica") -and !$_.Name.Contains("cp-template") -and !$_.Name.Contains("cp-parent")} | Sort-Object Name
    } else {
        Write-ToConsole "$($VCSAshortname) - ...Getting PowerCLI objects for all virtual machines in vCenter: $($vCenter_FQDN)"
        # Convert templates to VMs
        $templates = Get-Template
        if ($templates) {
            $templates.name | foreach-object {Set-Template $_ -ToVM -Confirm:$false} | Out-Null
        }
        $vms = Get-VM | Where-Object {!$_.Name.Contains("vCLS") -and !$_.Name.Contains("replica") -and !$_.Name.Contains("cp-template")} | Sort-Object Name
    }
} Catch {
    Write-ToConsole "$($VCSAshortname) - ...Failed to get PowerCLI objects"
    Write-ToConsole $_.Exception
    Disconnect-VIServer -Server $vCenter_FQDN -Force -Confirm:$false
    Exit -1
}

# Run Inspec on each VM on target
# =============================================================================================
Write-ToConsole "$($VCSAshortname) - Running Inspec $($STIG_ver) Profile against $($VCSAshortname) $($SUBTARGET)" -ForegroundColor Yellow
Write-ToConsole ""

$WriteToConsole = ${Function:Write-ToConsole}.ToString()
$InspecVM     = ${Function:InspecVM}.ToString()

$vms | Foreach-object {

   # Setup for each VM
    # =============================================================================================
    $vm = $_
    $vmName = $vm.Name.ToUpper()
    $vmShortName = $vmName -replace '^(.{0,25}).*','$1'
    # $vmShortName = ($vmName -split ("[^0-9a-zA-Z\s]"))[0]
    $vmDNSName = $vm.Guest.HostName
    $vm_IP = $vm.Guest.IPAddress | Select-Object -First 1
    $networkadapter = $vm | Get-NetworkAdapter | Select-Object -First 1
    $macaddress = $networkadapter.MacAddress

    $reportFile    = $reportPath + "/" + $vmShortName + "_" + $classification + "_" + $STIG_ver + "_" + $dateStr + ".json"
    $cklFile       = $reportPath + "/" + $vmShortName + "_" + $classification + "_" + $STIG_ver + "_" + $dateStr + ".ckl"
    $fixreportFile = $reportPath + "/" + "FIX_" + $vmShortName + "_" + $classification + "_" + $STIG_ver + "_" + $dateStr + ".json"
    $fixcklFile    = $reportPath + "/" + "FIX_" + $vmShortName + "_" + $classification + "_" + $STIG_ver + "_" + $dateStr + ".ckl"

    $variableObj = [PSCustomObject]@{
  
        # Functions
        WriteToConsole = [string]$WriteToConsole
    
        # Varibles
        MARKING       = [string]$MARKING
        VulnID_mapper = [string]$VulnID_mapper
        inspecPath    = [string]$inspecPath
        NameDateTag   = [string]$NameDateTag
        KnownIDs      = [array]$KnownIDs
        KnownIssues   = [array]$KnownIssues
        silent        = [switch]$silent

        # VM Specific Varibles
        vmName       = [string]$vmName
        vmShortName  = [string]$vmShortName
        vmDNSName    = [string]$vmDNSName
        vm_IP        = [string]$vm_IP
        macaddress   = [string]$macaddress
        reportFile   = [string]$reportFile
        cklFile      = [string]$cklFile
        fixreportFile = [string]$fixreportFile
        fixcklFile    = [string]$fixcklFile
    }

    $vmVarTable.add($vm,$variableObj)
}

$vms | Foreach-Object -ThrottleLimit 15 -Parallel {
    ${function:InspecVM} = $using:InspecVM
    InspecVM -vm $_ -vmVarTable $using:vmVarTable -vmResultTable $using:vmResultTable -VCSAshortname $using:VCSAshortname
}

$FormatEnumerationLimit=-1
Write-ToConsole " "
Write-ToConsole "$($VCSAshortname) - OPENS: "
foreach ($r in $vmResultTable.GetEnumerator() ) {
    if($r.Value -ne "" -or $r.Value -ne $null) {
        Write-Host "$($r.Name) : `t$($r.Value)"
    }
}
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#/////////////////////// REMEDIATION OPEN ITEMS //////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

# Remediate
# =============================================================================================
if ($vmVarTable -and (!$skipFix)){
    $silent = $null
    Write-ToConsole
    Write-ToConsole "*********************************************"
    Write-ToConsole "Starting Remediation Process..."
    Write-ToConsole "*********************************************"

    if(!$skipFix){
        #$msg = "$(Get-Date -Format T) Run VM STIG to remediate items? [y/n]"
        #do {$response = Read-Host -Prompt $msg
        #}until ($response -eq "y" -or $response -eq "n")
	$response = "y"
    }else{$response = "n"}

    $vmVarTable.keys | ForEach-Object {
        $vm = $_
        $variableObj = $vmVarTable[$vm]

        Try{
            $xmlCkl = ( Select-Xml -Path $variableObj.cklFile -XPath / ).Node
        }
        Catch{
            Write-Error "Failed to import $($vm) CKL to remediate.. $_.Exception"
        }

        # Find all OPEN ITEMS compare to known issues
        # =============================================================================================
        $OpenItems = @()
        $xmlCkl.CHECKLIST.STIGS.iSTIG.VULN | Where-Object STATUS -eq 'Open' |  ForEach-Object {
			$RuleID = ($_.STIG_DATA | Where-Object {$_.VULN_ATTRIBUTE -eq "Rule_Ver"}).ATTRIBUTE_DATA
            $OpenItems += $RuleID
        }
        if($OpenItems){

            Write-ToConsole " "
            Write-ToConsole "The Following Items will need to Remediated on $($vm): "
            Write-ToConsole $OpenItems

            # Running Powershell on Open Items
            # =============================================================================================
            if($response -eq "y"){
                Try{
                    RemediateItem $OpenItems $vm $xmlCkl $stigsettings $variableObj
                    $remediated = "Powershell run on $($OpenItems)"
                }
                Catch{
                    Write-Error "Failed to Remediate Items on $($vm).. $_.Exception"
                }
            
                # CleanUp
                # =============================================================================================
                if($variableObj.fixreportFile){Remove-Item -Path $variableObj.fixreportFile -erroraction 'silentlycontinue'}
                if($variableObj.fixCklFile){Remove-Item -Path $variableObj.fixCklFile -erroraction 'silentlycontinue'} 

            }
            elseif($response -eq "n"){
                Write-ToConsole "Finializing $($vm) STIG CKL without remediating open items..."
                $remediated = "Remediation skipped"
            }
        }
        else{
            Write-ToConsole "All $($vm) STIG items are remediated" 
            Write-ToConsole "Finializing $($vm) STIG CKL..."
            $remediated = "No open items"
        }
    $remediateTable.add($vm,$remediated)    
    }
}

#Convert template VMs back to templates
if($templates){
    $templates.name | foreach-object {Set-VM $_ -ToTemplate -Confirm:$false} | out-null
}

VulnID2StigID -vmVarTable $vmVarTable
ListOpenItems -KnownIDs $KnownIDs -vmVarTable $vmVarTable -remediateTable $remediateTable
MergeTemplate -vmVarTable $vmVarTable -templateCklFile $templateCklFile

# Change permission
# =============================================================================================    
$login = logname
chmod -R 755 /opt/stigtools/vsphere8/Reports/
chown -R $login /opt/stigtools/vsphere8/Reports/

Remove-Module vmware-vm-8.0-stig-module

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
