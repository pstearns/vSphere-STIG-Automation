<# 
#==========================================================================
# NAME: vSphere_ALL_STIGs_.ps1, v2.0.0
# AUTHOR: Peter Stearns
# UPDATED: 02/18/2025
# PROFILE: VMware_vSphere_8.0_VCSA_STIG_V2R2 (Services)
# PROFILE: VMware_vSphere_8.0_vCenter_STIG_V2R2
# PROFILE: VMware_vSphere_8.0_ESXi_STIG_V2R2
# PROFILE: VMware_vSphere_8.0_VM_STIG_V2R1
# DESCRIPTION:
#    -Runs the Inspec and Ansible Profiles against all vCenter assests
#    -Outputs a STIG Viewer Checklist file for each assest
#==========================================================================

    Tested against
    -PowerCLI 12.6
    -Powershell 5/Core 7.2.6
    -vCenter/ESXi 8.0 U3

    Example command to run script
    pwsh ./vSphere8_Stig_Menu.ps1 -RunBy "Peter Stearns"
 
    .PARAMETER vdi
    Enter yes, y, Yes if running against a VDI cluster. This will allow for MemPage Sharing
    .PARAMETER RunBy
    Enter Full Name of person running Checks

#>

[CmdletBinding()]
param (
    [Parameter()]
    [string]$vdi,
    [Parameter()]
    [string]$RunBy,
    [Parameter()]
    [switch]$skipFix
)

If($global:DefaultVIServer -or $global:DefaultVIServers) {
    Disconnect-VIServer * -Confirm:$false
}

Function Write-ToConsole ($Details){
	    $LogDate = Get-Date -Format T
	    Write-Host "$($LogDate) $Details"
}

function GetCreds {
    param (
        [string]$RunBy
    )

    $vcsaCredTable  = [ordered]@{}
    $vcsaCredTable  = [System.Collections.Hashtable]::Synchronized($vcsaCredTable)
    
    Write-Host "`t=========================================="    
    Write-Host "`tGathering Credentials for $($vCenter_FQDN)..."
    cls;Write-Host `n`n
    Write-Host "`t=========================================="
    Write-Host "`t     $($vCenter_FQDN)"
    Write-Host "`t=========================================="
    Write-Host "`t    Enter administrator@vsphere Creds     "
    Write-Host "`t=========================================="
    if(!$vcsaAdmnCred){ $vcsaAdmnCred = Get-Credential -message "Enter administrator@vsphere Creds" -UserName "administrator@vsphere.local" }
    cls;Write-Host `n`n
    Write-Host "`t=========================================="
    Write-Host "`t     $($vCenter_FQDN)"
    Write-Host "`t=========================================="
    Write-Host "`t      Enter VCSA root password           "
    Write-Host "`t=========================================="
    if(!$vcsaRootCred){ $vcsaRootCred = Get-Credential -message "Enter VCSA root password" -UserName "root" }
    cls;Write-Host `n`n
    Write-Host "`t=========================================="
    Write-Host "`t     $($vCenter_FQDN)"
    Write-Host "`t=========================================="
    Write-Host "`t        Enter ESXi root password          "
    Write-Host "`t=========================================="
    if(!$esxiRootCred){ $esxiRootCred = Get-Credential -Message "Enter ESXi root password" -UserName "root" }
        
    $credObj = [PSCustomObject]@{
        vcsaAdmnCred = [PSCredential]$vcsaAdmnCred
        vcsaRootCred = [PSCredential]$vcsaRootCred
        esxiRootCred = [PSCredential]$esxiRootCred
    }

    do {
        cls;Write-Host `n`n
        Write-Host "`t=========================================="
        Write-Host "`t      Enter vCenter FQDN and Creds        "
        Write-Host "`t             Enter when done              "
        Write-Host "`t=========================================="
        $vCenter_FQDN  = Read-Host "Enter vCenter FQDN"
        if ($vCenter_FQDN -eq $null -or $vCenter_FQDN -eq ""){continue}
        else{
			$splitName     = $vCenter_FQDN.split(".")
            $connection    = Test-Connection -ComputerName $vCenter_FQDN -Count 1 -Quiet
			#Verify vCenter version
			Write-ToConsole "...Verifying vCenter $vcenter is version 8.0.x"
			Connect-VIServer -Server $vCenter_FQDN -Credential $vcsaAdmnCred -ErrorAction SilentlyContinue | Out-Null
			If(($global:DefaultVIServers | Select-Object -ExpandProperty Version).contains("8.0")){
				If($global:DefaultVIServer -or $global:DefaultVIServers) { Disconnect-VIServer * -Confirm:$false }
				$vCenterVer = "8"
			} Else {
				Write-ToConsole "...vCenter is not version 8.0.x..."
				$vCenterVer = ""
			}
            if($splitName.count -lt 2 -or $connection -ne "True" -or $vCenterVer -ne "8"){
                do {
                    write-host "Could not connect..."
                    $vCenter_FQDN  = Read-Host "Enter valid vCenter FQDN"
                    $splitName     = $vCenter_FQDN.split(".")
                    $connection    = Test-Connection -ComputerName $vCenter_FQDN -Count 1 -Quiet
					#Verify vCenter version
					Write-ToConsole "...Verifying vCenter $vcenter is version 8.0.x"
					Connect-VIServer -Server $vCenter_FQDN -Credential $vcsaAdmnCred -ErrorAction SilentlyContinue | Out-Null
					If(($global:DefaultVIServers | Select-Object -ExpandProperty Version).contains("8.0")){
						If($global:DefaultVIServer -or $global:DefaultVIServers) { Disconnect-VIServer * -Confirm:$false }
						$vCenterVer = "8"
					} Else {
						Write-ToConsole "...vCenter is not version 8.0.x..."
						$vCenterVer = "0"
					}
                }
                until ($splitName.count -gt 2 -and $connection -eq "True" -and $vCenterVer -eq "8")
            }
        }
        $vcsaCredTable.add($vCenter_FQDN,$credObj)
    }
    until ($vCenter_FQDN -eq '')

    if(!$RunBy){ $RunBy = Read-Host -Prompt "Enter your full name" }

    return $vcsaCredTable,$RunBy
}

function VCSAInspecParallel {
    param (
        [hashtable]$vcsaCredTable,
        [string]$RunBy
    )
    # Running vSphere_VCSA_STIG.ps1
    # =============================================================================================
    Write-ToConsole "*********************************************"
    Write-ToConsole "      vSphere_VCSA_STIG_Parallel.ps1         "
    Write-ToConsole "*********************************************"

    $vcsaCredTable.keys | Foreach-Object -ThrottleLimit 5 -Parallel {
        $vcsaCredTable = $using:vcsaCredTable
        $vCenter_FQDN = $_
        $credObj = $vcsaCredTable[$vCenter_FQDN]
        Start-Sleep -MilliSeconds (Get-Random -Minimum 2000 -Maximum 7000)
        & '/opt/stigtools/vsphere8/scripts/vSphere8_VCSA_STIG_Parallel.ps1' -vcenter $vCenter_FQDN -credObj $credObj -RunBy $using:RunBy -skipfix
    }
  
    Write-ToConsole " "
    start-sleep -seconds 10
}

function ESXiInspecParallel {
    param (
        [hashtable]$vcsaCredTable,
        [string]$RunBy
    )

    # Running vSphere8_ESXi_STIG.ps1
    # =============================================================================================
    Write-ToConsole "*********************************************"
    Write-ToConsole "      vSphere8_ESXi_STIG_Parallel.ps1         "
    Write-ToConsole "*********************************************"

    $vcsaCredTable.keys | Foreach-Object -ThrottleLimit 5 -Parallel {
        $vcsaCredTable = $using:vcsaCredTable
        $vCenter_FQDN = $_
        $credObj = $vcsaCredTable[$vCenter_FQDN]
        Start-Sleep -MilliSeconds (Get-Random -Minimum 2000 -Maximum 7000)
        & '/opt/stigtools/vsphere8/scripts/vSphere8_ESXi_STIG_Parallel.ps1' -vcenter $vCenter_FQDN -credObj $credObj -RunBy $using:RunBy -skipfix
    }

    Write-ToConsole " "
    start-sleep -seconds 10
}

function VMSInspecParallel {
    param (
        [hashtable]$vcsaCredTable,
        [string]$RunBy
    )

    # Running vSphere8_VM_STIG.ps1
    # =============================================================================================
    Write-ToConsole "*********************************************"
    Write-ToConsole "      vSphere8_VM_STIG_Parallel.ps1           "
    Write-ToConsole "*********************************************"

    $vcsaCredTable.keys | Foreach-Object -ThrottleLimit 5 -Parallel {
        $vcsaCredTable = $using:vcsaCredTable
        $vCenter_FQDN = $_
        $credObj = $vcsaCredTable[$vCenter_FQDN]
        Start-Sleep -MilliSeconds (Get-Random -Minimum 2000 -Maximum 7000)
        & '/opt/stigtools/vsphere8/scripts/vSphere8_VM_STIG_Parallel.ps1' -vcenter $vCenter_FQDN -credObj $credObj -RunBy $using:RunBy -skipfix
    }
    Write-ToConsole " "
    start-sleep -seconds 10
}

function VCSAInspecRemediate {
    param (
        [hashtable]$vcsaCredTable,
        [string]$RunBy
    )
    # Running vSphere_VCSA_STIG.ps1
    # =============================================================================================
    Write-ToConsole "*********************************************"
    Write-ToConsole "      vSphere_VCSA_STIG_Parallel.ps1         "
    Write-ToConsole "*********************************************"

    $vcsaCredTable.keys | Foreach-Object {
        $vCenter_FQDN = $_
        $credObj = $vcsaCredTable[$vCenter_FQDN]
        & '/opt/stigtools/vsphere8/scripts/vSphere8_VCSA_STIG_Parallel.ps1' -vcenter $vCenter_FQDN -credObj $credObj -RunBy $RunBy
    }

    Write-ToConsole " "
    start-sleep -seconds 10
}

function ESXiInspecRemediate {
    param (
        [hashtable]$vcsaCredTable,
        [string]$RunBy
    )
    # Running vSphere_ESXi_STIG.ps1
    # =============================================================================================
    Write-ToConsole "*********************************************"
    Write-ToConsole "      vSphere_ESXi_STIG_Parallel.ps1         "
    Write-ToConsole "*********************************************"

    $vcsaCredTable.keys | Foreach-Object {
        $vCenter_FQDN = $_
        $credObj = $vcsaCredTable[$vCenter_FQDN]
        & '/opt/stigtools/vsphere8/scripts/vSphere8_ESXi_STIG_Parallel.ps1' -vcenter $vCenter_FQDN -credObj $credObj -RunBy $RunBy
    }
  
    Write-ToConsole " "
    start-sleep -seconds 10
}

function VMSInspecRemediate {
    param (
        [hashtable]$vcsaCredTable,
        [string]$RunBy
    )

    # Running vSphere_VM_STIG.ps1
    # =============================================================================================
    Write-ToConsole "*********************************************"
    Write-ToConsole "      vSphere_VM_STIG_Parallel.ps1           "
    Write-ToConsole "*********************************************"

    $vcsaCredTable.keys | Foreach-Object {
        $vCenter_FQDN = $_
        $credObj = $vcsaCredTable[$vCenter_FQDN]
        & '/opt/stigtools/vsphere8/scripts/vSphere8_VM_STIG_Parallel.ps1' -vcenter $vCenter_FQDN -credObj $credObj -RunBy $RunBy
    }

    Write-ToConsole " "
    start-sleep -seconds 10
}

function ESXiResetPasswords {
    param (
        [hashtable]$vcsaCredTable
    )
    # =============================================================================================
    Write-ToConsole "*********************************************"
    Write-ToConsole "         Resetting ESXi Passwords            "
    Write-ToConsole "*********************************************"

    $vcsaCredTable.keys | Foreach-Object {
        $vCenter_FQDN = $_
        $credObj = $vcsaCredTable[$vCenter_FQDN]
    	$vcsaAdmnCred = $credObj.vcsaAdmnCred
    	$esxiRootCred = $credObj.esxiRootCred

	Connect-VIServer -Server $vCenter_FQDN -Credential $vcsaAdmnCred -ErrorAction SilentlyContinue | Out-Null
	$vmhosts = get-vmhost
	Foreach ($vmhost in $vmhosts) {
    		$vmhost | get-advancedsetting Security.PasswordHistory | Set-AdvancedSetting -value "0" -Confirm:$false
   		$esxcli = get-esxcli -vmhost $vmhost -v2 
    		$esxcli.system.account.set.Invoke(@{id="root";password=$esxiRootCred.GetNetworkCredential().Password;passwordconfirmation=$esxiRootCred.GetNetworkCredential().Password})
    		$esxcli.system.account.set.Invoke(@{id="esxadmin";password=$esxiRootCred.GetNetworkCredential().Password;passwordconfirmation=$esxiRootCred.GetNetworkCredential().Password})
    		$vmhost | get-advancedsetting Security.PasswordHistory | Set-AdvancedSetting -value "5" -Confirm:$false
	}
        If($global:DefaultVIServer -or $global:DefaultVIServers) {
            Disconnect-VIServer * -Confirm:$false
        }
    }
  
    Write-ToConsole " "
    start-sleep -seconds 10
}


function DisplayMenu {
Clear-Host
Write-Host @"
  +=========================================================================+
  | NAME: vSphere STIG Automation                                           |
  | DESCRIPTION: Runs Inspec and Ansible to STIG All assests in a vCenter   |
  | PROFILE: VMware_vSphere_8.0_VCSA_STIG_V2R2 (Services)                   |
  | PROFILE: VMware_vSphere_8.0_vCenter_STIG_V2R2                           |
  | PROFILE: VMware_vSphere_8.0_ESXi_STIG_V2R2                              |
  | PROFILE: VMware_vSphere_8.0_VM_STIG_V2R1                                |    
  |                                                                         |
  +=========================================================================+
  |                        VSPHERE 8.0 STIG MENU                            |
  +=========================================================================+
  |                                                                         |
  |     1) Get Credentials                                                  |
  |        Run first or when switching stacks                               |
  |                                                                         |
  |     RUN PARALLEL SITES // NO REMEDIAITON OPTIONS                        |
  |     ============================================                        |
  |                                                                         |
  |     2) INSPEC ALL PROFILES                                              |
  |        Includes VCSA Services, vCenter, ESXi, and VMs                   |
  |                                                                         |
  |     3) INSPEC vCenter                                                   |
  |        Includes VCSA Services, vCenter                                  |
  |                                                                         |
  |     4) INSPEC ESXi                                                      |
  |        ESXi Profile Only                                                |
  |                                                                         |
  |     5) INSPEC VM                                                        |
  |        VMs Profile Only                                                 |
  |                                                                         |
  |     RUN REMEDIAITON OPTIONS // Processes each site linearly             |
  |     ========================================================            |
  |                                                                         |
  |     6) REMEDIATE ALL PROFILES                                           |
  |        Includes VCSA Services, vCenter, ESXi, and VMs                   |
  |                                                                         |
  |     7) REMEDIATE vCenter                                                |
  |        Includes VCSA Services, vCenter                                  |
  |                                                                         |
  |     8) REMEDIATE ESXi                                                   |
  |        ESXi Profile Only                                                |
  |                                                                         |
  |     9) REMEDIATE VM                                                     |
  |        VMs Profile Only                                                 |
  |                                                                         |
  |     10) Reset Change ESXi Passwords                                     |
  |     11) EXIT                                                            |
  |                                                                         |
  +=========================================================================+​
"@
  $MENU = Read-Host "OPTION"

  Switch ($MENU)
  {
    1 {
        #OPTION1 - Get Credentials
        $vcsaCredTable,$RunBy = GetCreds -RunBy $RunBy
        if ($vcsaCredTable.count -lt 1) {write-host "No vCenters choosen";start-sleep -seconds 3;DisplayMenu}
        Write-ToConsole ""
        Write-ToConsole "Creds collected for: $($vcsaCredTable.keys)"
        pause
        
        DisplayMenu
    }

    2 {
        #OPTION2 - INSPEC VSPHERE ALL PROFILES / PARALLEL / NO REMEDIATION
        Write-ToConsole "Running against: $($vcsaCredTable.keys)"
        $startTime = Get-Date
        if ($vcsaCredTable.count -lt 1) {write-host "No vCenters choosen";start-sleep -seconds 3;DisplayMenu}

        cls
        VCSAInspecParallel -vcsaCredTable $vcsaCredTable -RunBy $RunBy
        ESXiInspecParallel -vcsaCredTable $vcsaCredTable -RunBy $RunBy
        VMSInspecParallel -vcsaCredTable $vcsaCredTable -RunBy $RunBy

        If($global:DefaultVIServer -or $global:DefaultVIServers) {
            Disconnect-VIServer * -Confirm:$false
        }

        # Calculate elapsed time in minutes and seconds
        $elapsedTime = (Get-Date) - $startTime
        $elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
        $elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

        Write-ToConsole ""
        Write-ToConsole "END SCRIPT"
        Write-ToConsole "Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"
        pause
        
        DisplayMenu
    }

    3 {
        #OPTION3 - INSPEC vCenter PROFILES / PARALLEL / NO REMEDIATION 
        Write-ToConsole "Running against: $($vcsaCredTable.keys)"
        $startTime = Get-Date
        if ($vcsaCredTable.count -lt 1) {write-host "No vCenters choosen";start-sleep -seconds 3;DisplayMenu}

        cls
        VCSAInspecParallel -vcsaCredTable $vcsaCredTable -RunBy $RunBy

        If($global:DefaultVIServer -or $global:DefaultVIServers) {
            Disconnect-VIServer * -Confirm:$false
        }

        # Calculate elapsed time in minutes and seconds
        $elapsedTime = (Get-Date) - $startTime
        $elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
        $elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

        Write-ToConsole ""
        Write-ToConsole "END SCRIPT"
        Write-ToConsole "Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"
        pause
        
        DisplayMenu
    }
      
    4 {
        #OPTION4 - INSPEC ESXi PROFILE / PARALLEL / NO REMEDIATION 
        Write-ToConsole "Running against: $($vcsaCredTable.keys)"
        $startTime = Get-Date
        if ($vcsaCredTable.count -lt 1) {write-host "No vCenters choosen";start-sleep -seconds 3;DisplayMenu}

        cls
        ESXiInspecParallel -vcsaCredTable $vcsaCredTable -RunBy $RunBy

        If($global:DefaultVIServer -or $global:DefaultVIServers) {
            Disconnect-VIServer * -Confirm:$false
        }

        # Calculate elapsed time in minutes and seconds
        $elapsedTime = (Get-Date) - $startTime
        $elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
        $elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

        Write-ToConsole ""
        Write-ToConsole "END SCRIPT"
        Write-ToConsole "Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"
        pause
        
        DisplayMenu
    }

    5 {
        #OPTION5 - INSPEC VM PROFILES / PARALLEL / NO REMEDIATION
        Write-ToConsole "Running against: $($vcsaCredTable.keys)"
        $startTime = Get-Date
        if ($vcsaCredTable.count -lt 1) {write-host "No vCenters choosen";start-sleep -seconds 3;DisplayMenu}

        cls
        VMSInspecParallel -vcsaCredTable $vcsaCredTable -RunBy $RunBy

        If($global:DefaultVIServer -or $global:DefaultVIServers) {
            Disconnect-VIServer * -Confirm:$false
        }

        # Calculate elapsed time in minutes and seconds
        $elapsedTime = (Get-Date) - $startTime
        $elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
        $elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

        Write-ToConsole ""
        Write-ToConsole "END SCRIPT"
        Write-ToConsole "Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"
        pause
        
        DisplayMenu
    }

    6 {
        #OPTION6 - INSPEC and REMEDIATE VSPHERE ALL PROFILES
        Write-ToConsole "Running against: $($vcsaCredTable.keys)"
        $startTime = Get-Date
        if ($vcsaCredTable.count -lt 1) {write-host "No vCenters choosen";start-sleep -seconds 3;DisplayMenu}

        cls
        VCSAInspecRemediate -vcsaCredTable $vcsaCredTable -RunBy $RunBy
        ESXiInspecRemediate -vcsaCredTable $vcsaCredTable -RunBy $RunBy
        VMSInspecRemediate -vcsaCredTable $vcsaCredTable -RunBy $RunBy

        If($global:DefaultVIServer -or $global:DefaultVIServers) {
            Disconnect-VIServer * -Confirm:$false
        }

        # Calculate elapsed time in minutes and seconds
        $elapsedTime = (Get-Date) - $startTime
        $elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
        $elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

        Write-ToConsole ""
        Write-ToConsole "END SCRIPT"
        Write-ToConsole "Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"
        pause
        
        DisplayMenu
    }

    7 {
        #OPTION7 - INSPEC and REMEDIATE vCenter and VCSA Services
        Write-ToConsole "Running against: $($vcsaCredTable.keys)"
        $startTime = Get-Date
        if ($vcsaCredTable.count -lt 1) {write-host "No vCenters choosen";start-sleep -seconds 3;DisplayMenu}

        cls
        VCSAInspecRemediate -vcsaCredTable $vcsaCredTable -RunBy $RunBy

        If($global:DefaultVIServer -or $global:DefaultVIServers) {
            Disconnect-VIServer * -Confirm:$false
        }

        # Calculate elapsed time in minutes and seconds
        $elapsedTime = (Get-Date) - $startTime
        $elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
        $elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

        Write-ToConsole ""
        Write-ToConsole "END SCRIPT"
        Write-ToConsole "Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"
        pause
        
        DisplayMenu
    }
      
    8 {
        #OPTION8 - INSPEC ESXi PROFILE and REMEDIATE
        Write-ToConsole "Running against: $($vcsaCredTable.keys)"
        $startTime = Get-Date
        if ($vcsaCredTable.count -lt 1) {write-host "No vCenters choosen";start-sleep -seconds 3;DisplayMenu}

        cls
        ESXiInspecRemediate -vcsaCredTable $vcsaCredTable -RunBy $RunBy

        If($global:DefaultVIServer -or $global:DefaultVIServers) {
            Disconnect-VIServer * -Confirm:$false
        }

        # Calculate elapsed time in minutes and seconds
        $elapsedTime = (Get-Date) - $startTime
        $elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
        $elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

        Write-ToConsole ""
        Write-ToConsole "END SCRIPT"
        Write-ToConsole "Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"
        pause
        
        DisplayMenu
    }

    9 {
        #OPTION9 - INSPEC VM PROFILES and REMEDIATE
        Write-ToConsole "Running against: $($vcsaCredTable.keys)"
        $startTime = Get-Date
        if ($vcsaCredTable.count -lt 1) {write-host "No vCenters choosen";start-sleep -seconds 3;DisplayMenu}

        cls
        VMSInspecRemediate -vcsaCredTable $vcsaCredTable -RunBy $RunBy

        If($global:DefaultVIServer -or $global:DefaultVIServers) {
            Disconnect-VIServer * -Confirm:$false
        }

        # Calculate elapsed time in minutes and seconds
        $elapsedTime = (Get-Date) - $startTime
        $elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
        $elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

        Write-ToConsole ""
        Write-ToConsole "END SCRIPT"
        Write-ToConsole "Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"
        pause
        
        DisplayMenu
    }
 
   10 {
        #OPTION10 - Reset ESXi Passwords
        Write-ToConsole "Running against: $($vcsaCredTable.keys)"
        $startTime = Get-Date
        if ($vcsaCredTable.count -lt 1) {write-host "No vCenters choosen";start-sleep -seconds 3;DisplayMenu}

        cls
        ESXiResetPasswords -vcsaCredTable $vcsaCredTable
        If($global:DefaultVIServer -or $global:DefaultVIServers) {
            Disconnect-VIServer * -Confirm:$false
        }

        # Calculate elapsed time in minutes and seconds
        $elapsedTime = (Get-Date) - $startTime
        $elapsedMinutes = [math]::Floor($elapsedTime.TotalMinutes)
        $elapsedSeconds = $elapsedTime.TotalSeconds - ($elapsedMinutes * 60)

        Write-ToConsole ""
        Write-ToConsole "END SCRIPT"
        Write-ToConsole "Elapsed time: $elapsedMinutes minutes $elapsedSeconds seconds"
        pause
        
        DisplayMenu
    }

   11 {
        #OPTION11 - EXIT
        Break
     }

    default {
        #DEFAULT OPTION
        Write-Host "Option not available"
        Start-Sleep -Seconds 2
        DisplayMenu
      }
  }
}

DisplayMenu
