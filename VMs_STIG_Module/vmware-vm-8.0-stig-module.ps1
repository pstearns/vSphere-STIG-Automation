#==========================================================================
# NAME: VM_STIG_Module.ps1, v2.0.0
# AUTHOR: Peter Stearns
# UPDATED: 10/16/2024
# DESCRIPTION:
#    -Contains VM STIG functions 
#    -Functions use Advanced Settings, Powercli scripts
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

Function AdvancedSettingSTIG ($vm,$name,$value){
    If($asetting = Get-AdvancedSetting -Entity $vm -Name $name){
        If([string]$asetting.value -eq $($value)){
            Write-ToConsoleGreen "...Setting $($name) is already configured correctly to $($value) on $($vm.name)"
        }Else{
            Write-ToConsoleYellow "...Setting $($name) was incorrectly set to $($asetting.value) on $($vm.name)...setting to $($value)"
            $asetting | Set-AdvancedSetting -Value $($value) -Confirm:$false
        }
    }Else{
        Write-ToConsoleYellow "...Setting $($name) does not exist on $($vm.name)...creating setting..."
        New-AdvancedSetting -Entity $vm -Name $name -Value $($value) -Confirm:$false
    }
}

#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++
#//////////////////////////// STIG FUNCTIONS ////////////////////////////
#+++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++++

#===============================================================================================
# PowerCLI Advanced Settings Remediations
#===============================================================================================

# isolation.tools.copy.disable
Function VMCH-80-000189($vm, $stigsettings){
    $STIGID = "VMCH-80-000189"
    $Title = "Virtual machines (VMs) must have copy operations disabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.copyDisable.Keys
    $value = $stigsettings.copyDisable.Values
    AdvancedSettingSTIG $vm $name $value
}

# isolation.tools.dnd.disable
Function VMCH-80-000191($vm, $stigsettings){
    $STIGID = "VMCH-80-000191"
    $Title = "Virtual machines (VMs) must have drag and drop operations disabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.dndDisable.Keys
    $value = $stigsettings.dndDisable.Values
    AdvancedSettingSTIG $vm $name $value
}

# isolation.tools.paste.disable
Function VMCH-80-000192($vm, $stigsettings){
    $STIGID = "VMCH-80-000192"
    $Title = "Virtual machines (VMs) must have paste operations disabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.pasteDisable.Keys
    $value = $stigsettings.pasteDisable.Values
    AdvancedSettingSTIG $vm $name $value
} 

# isolation.tools.diskShrink.disable
Function VMCH-80-000193($vm, $stigsettings){
    $STIGID = "VMCH-80-000193"
    $Title = "Virtual machines (VMs) must have virtual disk shrinking disabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.diskShrink.Keys
    $value = $stigsettings.diskShrink.Values
    AdvancedSettingSTIG $vm $name $value
} 

# isolation.tools.diskWiper.disable
Function VMCH-80-000194($vm, $stigsettings){
    $STIGID = "VMCH-80-000194"
    $Title = "Virtual machines (VMs) must have virtual disk wiping disabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.diskWiper.Keys
    $value = $stigsettings.diskWiper.Values
    AdvancedSettingSTIG $vm $name $value
} 

# Independent, nonpersistent disks must not be used
Function VMCH-80-000208($vm, $stigsettings){
    $STIGID = "VMCH-80-000208"
    $Title = "Virtual machines (VMs) must not use independent, nonpersistent disks."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    Write-ToConsoleRed "...Independent nonpersistent disks must be addressed manually"
}

# Unauthorized floppy devices must be disconnected
Function VMCH-80-000209($vm, $stigsettings){
    $STIGID = "VMCH-80-000209"
    $Title = "Virtual machines (VMs) must remove unneeded floppy devices."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    If($parallel = $vm | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "parallel"}  -ErrorAction Stop){
        Write-ToConsoleYellow "...Floppy device exists on $vm"
        Write-ToConsoleRed "...Floppy device must be removed manually"
    }
    else{
        Write-ToConsoleGreen "...Floppy device does not exist on $vm."
    }
}

# Unauthorized CD/DVD devices must be disconnected
Function VMCH-80-000210($vm, $stigsettings){
    $STIGID = "VMCH-80-000210"
    $Title = "Virtual machines (VMs) must remove unneeded CD/DVD devices."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    If($cddrive = $vm | Get-CDDrive | Where {$_.extensiondata.connectable.connected -eq $true}  -ErrorAction Stop){
        Write-ToConsoleYellow "...CD drive exists on $vm and is attached...removing CD Drive"
        $vm | Get-CDDrive | Set-CDDrive -NoMedia -ErrorAction Stop
    }
    else{
        Write-ToConsoleGreen "...CD drive does not exist on $vm and is not attached."
    }
} 

# Unauthorized parallel devices must be disconnected
Function VMCH-80-000211($vm, $stigsettings){
    $STIGID = "VMCH-80-000211"
    $Title = "Virtual machines (VMs) must remove unneeded parallel devices."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    If($parallel = $vm | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "parallel"}  -ErrorAction Stop){
        Write-ToConsoleYellow "...Parallel device exists on $vm"
        Write-ToConsoleRed "...Parallel device must be removed manually"
    }
    else{
        Write-ToConsoleGreen "...Parallel device does not exist on $vm."
    }
}

# Unauthorized serial devices must be disconnected
Function VMCH-80-000212($vm, $stigsettings){
    $STIGID = "VMCH-80-000212"
    $Title = "Virtual machines (VMs) must remove unneeded serial devices."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    If($serial = $vm | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "serial"}  -ErrorAction Stop){
        Write-ToConsoleYellow "...serial device exists on $vm"
        Write-ToConsoleRed "...serial device must be removed manually"
    }
    else{
        Write-ToConsoleGreen "...serial device does not exist on $vm."
    }
} 

# USB serial devices must be disconnected
Function VMCH-80-000213($vm, $stigsettings){
    $STIGID = "VMCH-80-000213"
    $Title = "Virtual machines (VMs) must remove unneeded USB devices."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    If($usb = $vm | Where {$_.ExtensionData.Config.Hardware.Device.DeviceInfo.Label -match "usb"}  -ErrorAction Stop){
        Write-ToConsoleYellow "...USB device exists on $vm"
        Write-ToConsoleGreen "...USB smart card readers are used to pass smart cards through the VM console to a VM, is not a finding."
    }
    else{
        Write-ToConsoleGreen "...USB device does not exist on $vm."
    }
} 

# Virtual machines (VMs) must disable DirectPath I/O devices when not required.
Function VMCH-80-000214($vm, $stigsettings){
    $STIGID = "VMCH-80-000214"
    $Title = "Virtual machines (VMs) must disable DirectPath I/O devices when not required."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    If($passthrough = $vm | Get-PassthroughDevice -ErrorAction Stop){
        Write-ToConsoleYellow "...PassthroughDevice device exists on $vm"
        Write-ToConsoleRed "...PassthroughDevice device must be removed manually"
    }
    else{
        Write-ToConsoleGreen "...PassthroughDevice device does not exist on $vm."
    }
} 

# RemoteDisplay.maxConnections
Function VMCH-80-000195($vm, $stigsettings){
    $STIGID = "VMCH-80-000195"
    $Title = "Virtual machines (VMs) must limit console sharing."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.RemoteDisplayMax.Keys
    $value = $stigsettings.RemoteDisplayMax.Values
    AdvancedSettingSTIG $vm $name $value
} 

# tools.setinfo.sizeLimit
Function VMCH-80-000196($vm, $stigsettings){
    $STIGID = "VMCH-80-000196"
    $Title = "Virtual machines (VMs) must limit informational messages from the virtual machine to the VMX file."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.setinfoSizeLimit.Keys
    $value = $stigsettings.setinfoSizeLimit.Values
    AdvancedSettingSTIG $vm $name $value
} 

# isolation.device.connectable.disable
Function VMCH-80-000197($vm, $stigsettings){
    $STIGID = "VMCH-80-000197"
    $Title = "Virtual machines (VMs) must prevent unauthorized removal, connection, and modification of devices."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.deviceConnectable.Keys
    $value = $stigsettings.deviceConnectable.Values
    AdvancedSettingSTIG $vm $name $value
} 

# tools.guestlib.enableHostInfo
Function VMCH-80-000198($vm, $stigsettings){
    $STIGID = "VMCH-80-000198"
    $Title = "Virtual machines (VMs) must not be able to obtain host information from the hypervisor."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.guestlibEnableHostInf.Keys
    $value = $stigsettings.guestlibEnableHostInf.Values
    AdvancedSettingSTIG $vm $name $value
} 

# Shared salt values must be disabled
Function VMCH-80-000199($vm, $stigsettings){
    $STIGID = "VMCH-80-000199"
    $Title = "Virtual machines (VMs) must have shared salt values disabled."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    #Checking to see if current setting exists
    If($asetting = $vm | Get-AdvancedSetting -Name $stigsettings.schedMemPshareSalt -ErrorAction Stop){
        Write-ToConsoleYellow "...Setting $($stigsettings.schedMemPshareSalt) exists on $vm...removing setting"
        $asetting | Remove-AdvancedSetting -Confirm:$false -ErrorAction Stop
    }
    else{
        Write-ToConsoleGreen "...Setting $($stigsettings.schedMemPshareSalt) does not exist on $vm"
    }
}

# Configure only VMs that need this access to use the API
Function VMCH-80-000200($vm, $stigsettings){
    $STIGID = "VMCH-80-000200"
    $Title = 'Virtual machines (VMs) must disable access through the "dvfilter" network Application Programming Interface (API).'
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    Write-ToConsoleRed '..."dvFilter" API must be addressed manually'
}

# tools.guest.desktop.autolock
Function VMCH-80-000201($vm, $stigsettings){
    $STIGID = "VMCH-80-000201"
    $Title = "Virtual machines (VMs) must be configured to lock when the last console connection is closed."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.desktopAutolock.Keys
    $value = $stigsettings.desktopAutolock.Values
    AdvancedSettingSTIG $vm $name $value
} 

# mks.enable3d
Function VMCH-80-000202($vm, $stigsettings){
    $STIGID = "VMCH-80-000202"
    $Title = "Virtual machines (VMs) must disable 3D features when not required."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.mksEnable3d.Keys
    $value = $stigsettings.mksEnable3d.Values
    AdvancedSettingSTIG $vm $name $value
} 

# Encryption must be enabled for vMotion
Function VMCH-80-000203($vm, $stigsettings){
    $STIGID = "VMCH-80-000203"
    $Title = "Virtual machines (VMs) must enable encryption for vMotion."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    If($vm.extensiondata.Config.MigrateEncryption -eq $stigsettings.vmotionEncryption){
        Write-ToConsoleGreen "...vMotion encryption set correctly on $vm to $($stigsettings.vmotionEncryption)"
    }else{
        Write-ToConsoleYellow "...vMotion encryption was incorrectly set to $($vm.extensiondata.Config.MigrateEncryption) on $vm"
        $vmv = $vm | get-view -ErrorAction Stop
        $config = new-object VMware.Vim.VirtualMachineConfigSpec
        $config.MigrateEncryption = New-object VMware.Vim.VirtualMachineConfigSpecEncryptedVMotionModes
        $config.MigrateEncryption = "$($stigsettings.vmotionEncryption)"
        $vmv.ReconfigVM($config)
    }
}

# Set virtual machine logging
Function VMCH-80-000207($vm, $stigsettings){
    $STIGID = "VMCH-80-000207"
    $Title = "Virtual machines (VMs) must enable logging."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    If($vm.ExtensionData.Config.Flags.EnableLogging -eq $stigsettings.vmLogging){
        Write-ToConsoleGreen "...Logging set correctly on $vm to $($stigsettings.vmLogging)"
    }else{
        Write-ToConsoleYellow "...Logging was incorrectly set to $($vm.ExtensionData.Config.Flags.EnableLogging) on $vm"
        $vmv = $vm | get-view -ErrorAction Stop
        $config = new-object VMware.Vim.VirtualMachineConfigSpec
        $config.Flags = New-Object VMware.Vim.VirtualMachineFlagInfo
        $config.Flags.enableLogging = $stigsettings.vmLogging
        $vmv.ReconfigVM($config)
    }
}

# log.rotateSize
Function VMCH-80-000205($vm, $stigsettings){
    $STIGID = "VMCH-80-000205"
    $Title = "Virtual machines (VMs) must configure log size."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.logRotateSize.Keys
    $value = $stigsettings.logRotateSize.Values
    AdvancedSettingSTIG $vm $name $value
} 

# log.keepOld
Function VMCH-80-000206($vm, $stigsettings){
    $STIGID = "VMCH-80-000206"
    $Title = "Virtual machines (VMs) must configure log retention"
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    $name = $stigsettings.logKeepOld.Keys
    $value = $stigsettings.logKeepOld.Values
    AdvancedSettingSTIG $vm $name $value
} 

# Set virtual machine ft Encryption
Function VMCH-80-000204($vm, $stigsettings){
    $STIGID = "VMCH-80-000204"
    $Title = "Virtual machines (VMs) must enable encryption for Fault Tolerance."
    Write-ToConsole "...Remediating STIG ID:$STIGID with Title: $Title"
    If($vm.extensiondata.Config.FtEncryptionMode -eq $stigsettings.ftEncryption){
        Write-ToConsoleGreen "...Fault tolerance encryption set correctly on $vm to $($stigsettings.ftEncryption)"
    }else{
        Write-ToConsoleYellow "...Fault tolerance encryption was incorrectly set to $($vm.extensiondata.Config.FtEncryptionMode) on $vm"
        $vmv = $vm | Get-View -ErrorAction Stop
        $config = New-Object VMware.Vim.VirtualMachineConfigSpec
        $config.FTEncryption = New-Object VMware.Vim.VMware.Vim.VirtualMachineConfigSpecEncryptedFtModes
        $config.FT = "$($stigsettings.FtEncryptionMode)"
        $vmv.ReconfigVM($config)
    }
}