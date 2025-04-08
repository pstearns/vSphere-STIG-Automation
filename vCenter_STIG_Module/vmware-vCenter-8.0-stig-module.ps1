#==========================================================================
# NAME: vCenter_8_STIG_Module.ps1, v1.0.0
# AUTHOR: Peter Stearns
# UPDATED: 10/24/2024
# DESCRIPTION:
#    -Contains vCenter STIG functions
#    -Functions use Powercli scripts
#    -Can import modules or call functions to perform individual checks. 

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


## SSO Login Attempts
Function VCSA-80-000023 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000023"
	  $Title = "The vCenter Server must enforce the limit of three consecutive invalid logon attempts by a user."
	  If($controlsenabled.VCSA8000023){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssolockpolicies = Get-SsoLockoutPolicy
		If($ssolockpolicies.MaxFailedAttempts -ne $vcconfig.ssoLoginAttempts){
		  Write-ToConsoleYellow "...SSO login attempts set incorrectly on $vcenter"
		  $ssolockpolicies | Set-SsoLockoutPolicy -MaxFailedAttempts $vcconfig.ssoLoginAttempts
		}Else{
		  Write-ToConsoleGreen "...SSO login attempts set correctly to $($vcconfig.ssoLoginAttempts) on $vcenter"
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## Login Banner
Function VCSA-80-000024 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000024"
	  $Title = "The vCenter Server must display the Standard Mandatory DoD Notice and Consent Banner before logon."
	  If($controlsenabled.VCSA8000024){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## Log Level
Function VCSA-80-000034 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000034"
	  $Title = "The vCenter Server must produce audit records containing information to establish what type of events occurred."
	  If($controlsenabled.VCSA8000034){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$name = $vcconfig.configLogLevel.Keys
		$value = [string]$vcconfig.configLogLevel.Values
		## Checking to see if current setting exists
		If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
		  If($asetting.value -eq $value){
			Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
		  }Else{
			Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
			$asetting | Set-AdvancedSetting -Value $value -Confirm:$false
		  }
		}Else{
		  Write-ToConsoleYellow "...Setting $name does not exist on $vcenter...creating setting..."
		  New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## Plugins
Function VCSA-80-000057 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000057"
	  $Title = "vCenter Server plugins must be verified."
	  If($controlsenabled.VCSA8000057){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## Identity Provider
Function VCSA-80-000059 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000059"
	  $Title = "The vCenter Server must uniquely identify and authenticate users or processes acting on behalf of users."
	  If($controlsenabled.VCSA8000059){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## MFA
Function VCSA-80-000060 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000060"
	  $Title = "The vCenter Server must require multifactor authentication."
	  If($controlsenabled.VCSA8000060){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssoauthpolicy = Get-SsoAuthenticationPolicy
		If($ssoauthpolicy.SmartCardAuthnEnabled -ne $true){
		  Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		}Else{
		  Write-ToConsoleGreen "...SSO Smartcard login enabled on $vcenter"
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## SSO Password Length
Function VCSA-80-000069 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000069"
	  $Title = "The vCenter Server passwords must be at least 15 characters in length."
	  If($controlsenabled.VCSA8000069){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssopwpolicies = Get-SsoPasswordPolicy
		If($ssopwpolicies.MinLength -ne $vcconfig.ssoPasswordLength){
		  Write-ToConsoleYellow "...SSO password length set incorrectly on $vcenter"
		  $ssopwpolicies | Set-SsoPasswordPolicy -MinLength $vcconfig.ssoPasswordLength
		}Else{
		  Write-ToConsoleGreen "...SSO password length set correctly to $($vcconfig.ssoPasswordLength) on $vcenter"
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## SSO Password Reuse
Function VCSA-80-000070 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000070"
	  $Title = "The vCenter Server must prohibit password reuse for a minimum of five generations."
	  If($controlsenabled.VCSA8000070){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssopwpolicies = Get-SsoPasswordPolicy
		If($ssopwpolicies.ProhibitedPreviousPasswordsCount -ne $vcconfig.ssoPasswordReuse){
		  Write-ToConsoleYellow "...SSO password reuse set incorrectly on $vcenter"
		  $ssopwpolicies | Set-SsoPasswordPolicy -ProhibitedPreviousPasswordsCount $vcconfig.ssoPasswordReuse
		}Else{
		  Write-ToConsoleGreen "...SSO password reuse set correctly to $($vcconfig.ssoPasswordReuse) on $vcenter"
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## SSO Password Upper
Function VCSA-80-000071 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000071"
	  $Title = "The vCenter Server passwords must contain at least one uppercase character."
	  If($controlsenabled.VCSA8000071){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssopwpolicies = Get-SsoPasswordPolicy
		If($ssopwpolicies.MinUppercaseCount -ne $vcconfig.ssoPasswordUpper){
		  Write-ToConsoleYellow "...SSO password min upper characters set incorrectly on $vcenter"
		  $ssopwpolicies | Set-SsoPasswordPolicy -MinUppercaseCount $vcconfig.ssoPasswordUpper
		}Else{
		  Write-ToConsoleGreen "...SSO password min upper characters set correctly to $($vcconfig.ssoPasswordUpper) on $vcenter"
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## SSO Password Lower
Function VCSA-80-000072 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000072"
	  $Title = "The vCenter Server passwords must contain at least one lowercase character."
	  If($controlsenabled.VCSA8000072){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssopwpolicies = Get-SsoPasswordPolicy
		If($ssopwpolicies.MinLowercaseCount -ne $vcconfig.ssoPasswordLower){
		  Write-ToConsoleYellow "...SSO password min lower characters set incorrectly on $vcenter"
		  $ssopwpolicies | Set-SsoPasswordPolicy -MinLowercaseCount $vcconfig.ssoPasswordLower
		}Else{
		  Write-ToConsoleGreen "...SSO password min lower characters set correctly to $($vcconfig.ssoPasswordLower) on $vcenter"
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## SSO Password Numbers
Function VCSA-80-000073 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000073"
	  $Title = "The vCenter Server passwords must contain at least one numeric character."
	  If($controlsenabled.VCSA8000073){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssopwpolicies = Get-SsoPasswordPolicy
		If($ssopwpolicies.MinNumericCount -ne $vcconfig.ssoPasswordNum){
		  Write-ToConsoleYellow "...SSO password min numeric characters set incorrectly on $vcenter"
		  $ssopwpolicies | Set-SsoPasswordPolicy -MinNumericCount $vcconfig.ssoPasswordNum
		}Else{
		  Write-ToConsoleGreen "...SSO password min numeric characters set correctly to $($vcconfig.ssoPasswordNum) on $vcenter"
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## SSO Password Special
Function VCSA-80-000074 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000074"
	  $Title = "The vCenter Server passwords must contain at least one special character."
	  If($controlsenabled.VCSA8000074){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssopwpolicies = Get-SsoPasswordPolicy
		If($ssopwpolicies.MinSpecialCharCount -ne $vcconfig.ssoPasswordSpecial){
		  Write-ToConsoleYellow "...SSO password min special characters set incorrectly on $vcenter"
		  $ssopwpolicies | Set-SsoPasswordPolicy -MinSpecialCharCount $vcconfig.ssoPasswordSpecial
		}Else{
		  Write-ToConsoleGreen "...SSO password min special characters set correctly to $($vcconfig.ssoPasswordSpecial) on $vcenter"
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## FIPs
Function VCSA-80-000077 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000077"
	  $Title = "The vCenter Server must enable FIPS validated cryptography."
	  If($controlsenabled.VCSA8000077){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## SSO Password Lifetime
Function VCSA-80-000079 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000079"
	  $Title = " The vCenter Server must enforce a 60-day maximum password lifetime restriction."
	  If($controlsenabled.VCSA8000079){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssopwpolicies = Get-SsoPasswordPolicy
		If($ssopwpolicies.PasswordLifetimeDays -ne $vcconfig.ssoPasswordLifetime){
		  Write-ToConsoleYellow "...SSO password lifetime set incorrectly on $vcenter"
		  $ssopwpolicies | Set-SsoPasswordPolicy -PasswordLifetimeDays $vcconfig.ssoPasswordLifetime
		}Else{
		  Write-ToConsoleGreen "...SSO password lifetime set correctly to $($vcconfig.ssoPasswordLifetime) on $vcenter"
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## Revocation checking
Function VCSA-80-000080 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000080"
	  $Title = "The vCenter Server must enable revocation checking for certificate based authentication."
	  If($controlsenabled.VCSA8000080){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## Session timeout
Function VCSA-80-000089 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000089"
	  $Title = "The vCenter Server must terminate vSphere Client sessions after 10 minutes of inactivity."
	  If($controlsenabled.VCSA8000089){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## User roles
Function VCSA-80-000095 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000095"
	  $Title = "The vCenter Server users must have the correct roles assigned."
	  If($controlsenabled.VCSA8000095){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## NIOC
Function VCSA-80-000110 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000110"
	  $Title = "The vCenter Server must manage excess capacity, bandwidth, or other redundancy to limit the effects of information flooding types of denial-of-service (DoS) attacks by enabling Network I/O Control (NIOC)."
	  If($controlsenabled.VCSA8000110){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter...skipping..."
		}Else{
		  ForEach($switch in $dvs){
			If($switch.ExtensionData.Config.NetworkResourceManagementEnabled -eq $false){
			  Write-ToConsoleYellow "...Network IO Control not enabled on $($switch.name) on $vcenter"
			  ($switch | Get-View).EnableNetworkResourceManagement($true)
			}Else{
			  Write-ToConsoleGreen "...Network IO Control enabled on $($switch.name) on $vcenter"
			}
		  }
		}
	  }
	  Else{
		Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## SSO Alarm
Function VCSA-80-000123 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000123"
	  $Title = "The vCenter Server must provide an immediate real-time alert to the SA and ISSO, at a minimum, on every SSO account action."
	  If($controlsenabled.VCSA8000123){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssoalarm = Get-AlarmDefinition | Where-Object {$_.ExtensionData.Info.Expression.Expression.EventTypeId -eq "com.vmware.sso.PrincipalManagement"}
		If($ssoalarm.Enabled -eq $false){
		  Write-ToConsoleYellow "...Alarm for com.vmware.sso.PrincipalManagement exists on $vcenter but is not enabled...enabling..."
		  $ssoalarm | Set-AlarmDefinition -Enabled $true
		  
		}ElseIf($ssoalarm.Enabled -eq $true){
		  Write-ToConsoleGreen "...Alarm for com.vmware.sso.PrincipalManagement exists on $vcenter and is enabled..."
		  
		}Else{
		  Write-ToConsoleYellow "...Alarm for com.vmware.sso.PrincipalManagement does not exist on $vcenter...creating..."
		  $entity = New-Object VMware.Vim.ManagedObjectReference
		  $entity.Type = 'Folder'
		  $entity.Value = 'group-d1'
		  $spec = New-Object VMware.Vim.AlarmSpec
		  $spec.Expression = New-Object VMware.Vim.OrAlarmExpression
		  $spec.Expression.Expression = New-Object VMware.Vim.AlarmExpression[] (1)
		  $spec.Expression.Expression[0] = New-Object VMware.Vim.EventAlarmExpression
		  $spec.Expression.Expression[0].EventTypeId = 'com.vmware.sso.PrincipalManagement'
		  $spec.Expression.Expression[0].EventType = "Event"
		  $spec.Expression.Expression[0].ObjectType = "Folder"
		  $spec.Expression.Expression[0].Status = 'yellow'
		  $spec.Name = 'SSO account actions - com.vmware.sso.PrincipalManagement'
		  $spec.Description = ''
		  $spec.Enabled = $true
		  $spec.Setting = New-Object VMware.Vim.AlarmSetting
		  $spec.Setting.ToleranceRange = 0
		  $spec.Setting.ReportingFrequency = 300
		  $amview = Get-View -Id 'AlarmManager-AlarmManager'
		  $amview.CreateAlarm($entity, $spec)
		  
		}
	  }
	  Else{
		Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## SSO fail interval
Function VCSA-80-000145 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000145"
	  $Title = "The vCenter Server must set the interval for counting failed login attempts to at least 15 minutes."
	  If($controlsenabled.VCSA8000145){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssolockpolicies = Get-SsoLockoutPolicy
		If($ssolockpolicies.FailedAttemptIntervalSec -ne $vcconfig.ssoFailureInterval){
		  Write-ToConsoleYellow "...SSO failed login interval set incorrectly on $vcenter"
		  $ssolockpolicies | Set-SsoLockoutPolicy -FailedAttemptIntervalSec $vcconfig.ssoFailureInterval
		  
		}Else{
		  Write-ToConsoleGreen "...SSO failed login interval set correctly to $($vcconfig.ssoFailureInterval) on $vcenter"
		  
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Syslog
Function VCSA-80-000148 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000148"
	  $Title = "The vCenter Server must be configured to send logs to a central log server."
	  If($controlsenabled.VCSA8000148){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## NTP
Function VCSA-80-000158 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000158"
	  $Title = "The vCenter Server must compare internal information system clocks at least every 24 hours with an authoritative time server."
	  If($controlsenabled.VCSA8000158){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## DoD Cert
Function VCSA-80-000195 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000195"
	  $Title = "The vCenter Server Machine SSL certificate must be issued by a DoD certificate authority."
	  If($controlsenabled.VCSA8000195){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## vSAN DAR
Function VCSA-80-000196 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000196"
	  $Title = "The vCenter Server must enable data at rest encryption for vSAN."
	  If($controlsenabled.VCSA8000196){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## CEIP
Function VCSA-80-000248 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000248"
	  $Title = "The vCenter Server must disable the Customer Experience Improvement Program (CEIP)."
	  If($controlsenabled.VCSA8000248){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## SNMP v3
Function VCSA-80-000253 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000253"
	  $Title = "The vCenter server must enforce SNMPv3 security features where SNMP is required."
	  If($controlsenabled.VCSA8000253){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## SNMP v1/2
Function VCSA-80-000265 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000265"
	  $Title = "The vCenter server must disable SNMPv1/2 receivers."
	  If($controlsenabled.VCSA8000265){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$snmpview = Get-View -Id 'OptionManager-VpxSettings'
		$snmprecs = $snmpview.setting | Where-Object {$_.key -match 'snmp.receiver.*.enabled'}
		ForEach($snmprec in $snmprecs){
		  If($snmprec.value -ne $false){
			Write-ToConsoleYellow "...$($snmprec.key) is not disabled on $vcenter"
			$updateValue = New-Object VMware.Vim.OptionValue[] (1)
			$updateValue[0] = New-Object VMware.Vim.OptionValue
			$updateValue[0].Value = $false
			$updateValue[0].Key = $snmprec.key
			$updatesnmp = Get-View -Id 'OptionManager-VpxSettings'
			$updatesnmp.UpdateOptions($updateValue)
			
		  }Else{
			Write-ToConsoleGreen "...$($snmprec.key) is disabled on $vcenter"
			
		  }
		}
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## SSO unlock time
Function VCSA-80-000266 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000266"
	  $Title = "The vCenter Server must require an administrator to unlock an account locked due to excessive login failures."
	  If($controlsenabled.VCSA8000266){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$ssolockpolicies = Get-SsoLockoutPolicy
		If($ssolockpolicies.AutoUnlockIntervalSec -ne $vcconfig.ssoUnlockTime){
		  Write-ToConsoleYellow "...SSO auto unlock time set incorrectly on $vcenter"
		  $ssolockpolicies | Set-SsoLockoutPolicy -AutoUnlockIntervalSec $vcconfig.ssoUnlockTime
		  
		}Else{
		  Write-ToConsoleGreen "...SSO auto unlock time set correctly to $($vcconfig.ssoUnlockTime) on $vcenter"
		  
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## DVS Health Check
Function VCSA-80-000267 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000267"
	  $Title = "The vCenter Server must disable the distributed virtual switch health check."
	  If($controlsenabled.VCSA8000267){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
		  
		}Else{
		  ForEach($switch in $dvs){
			If($switch.ExtensionData.Config.HealthCheckConfig.Enable[0] -eq $true -or $switch.ExtensionData.Config.HealthCheckConfig.Enable[1] -eq $true){
			  Write-ToConsoleYellow "...Health check enabled on $($switch.name) on $vcenter"
			  ($switch | Get-View).UpdateDVSHealthCheckConfig(@((New-Object Vmware.Vim.VMwareDVSVlanMtuHealthCheckConfig -property @{enable=0}),(New-Object Vmware.Vim.VMwareDVSTeamingHealthCheckConfig -property @{enable=0})))
			  
			}Else{
			  Write-ToConsoleGreen "...Health check disabled on $($switch.name) on $vcenter"
			  
			}
		  }
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Reject forged transmits
Function VCSA-80-000268 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000268"
	  $Title = "The vCenter Server must set the distributed port group Forged Transmits policy to reject."
	  If($controlsenabled.VCSA8000268){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
		  
		}Else{
		  ForEach($switch in $dvs){
			$policy = $switch | Get-VDSecurityPolicy
			If($policy.ForgedTransmits -eq $true){
			  Write-ToConsoleYellow "...Forged Transmits enabled on $($switch.name) on $vcenter"
			  $policy | Set-VDSecurityPolicy -ForgedTransmits $false
			  
			}Else{
			  Write-ToConsoleGreen "...Forged Transmits disabled on $($switch.name) on $vcenter"
			  
			}
		  }
		  ForEach($pg in $dvpg){
			$policy = $pg | Get-VDSecurityPolicy
			If($policy.ForgedTransmits -eq $true){
			  Write-ToConsoleYellow "...Forged Transmits enabled on $($pg.name) on $vcenter"
			  $policy | Set-VDSecurityPolicy -ForgedTransmits $false
			  
			}Else{
			  Write-ToConsoleGreen "...Forged Transmits disabled on $($pg.name) on $vcenter"
			  
			}
		  }
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## MacChanges
Function VCSA-80-000269 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000269"
	  $Title = "The vCenter Server must set the distributed port group MAC Address Change policy to reject."
	  If($controlsenabled.VCSA8000269){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
		  
		}Else{
		  ForEach($switch in $dvs){
			$policy = $switch | Get-VDSecurityPolicy
			If($policy.MacChanges -eq $true){
			  Write-ToConsoleYellow "...MAC Changes enabled on $($switch.name) on $vcenter"
			  $policy | Set-VDSecurityPolicy -MacChanges $false
			  
			}Else{
			  Write-ToConsoleGreen "...MAC Changes disabled on $($switch.name) on $vcenter"
			  
			}
		  }
		  ForEach($pg in $dvpg){
			$policy = $pg | Get-VDSecurityPolicy
			If($policy.MacChanges -eq $true){
			  Write-ToConsoleYellow "...MAC Changes enabled on $($pg.name) on $vcenter"
			  $policy | Set-VDSecurityPolicy -MacChanges $false
			  
			}Else{
			  Write-ToConsoleGreen "...MAC Changes disabled on $($pg.name) on $vcenter"
			  
			}
		  }
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## promiscious mode
Function VCSA-80-000270 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000270"
	  $Title = "The vCenter Server must set the distributed port group Promiscuous Mode policy to reject."
	  If($controlsenabled.VCSA8000270){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
		  
		}Else{
		  ForEach($switch in $dvs){
			$policy = $switch | Get-VDSecurityPolicy
			If($policy.AllowPromiscuous -eq $true){
			  Write-ToConsoleYellow "...Promiscious Mode enabled on $($switch.name) on $vcenter"
			  $policy | Set-VDSecurityPolicy -AllowPromiscuous $false
			  
			}Else{
			  Write-ToConsoleGreen "...Promiscious Mode disabled on $($switch.name) on $vcenter"
			  
			}
		  }
		  ForEach($pg in $dvpg){
			$policy = $pg | Get-VDSecurityPolicy
			If($policy.AllowPromiscuous -eq $true){
			  Write-ToConsoleYellow "...Promiscious Mode enabled on $($pg.name) on $vcenter"
			  $policy | Set-VDSecurityPolicy -AllowPromiscuous $false
			  
			}Else{
			  Write-ToConsoleGreen "...Promiscious Mode disabled on $($pg.name) on $vcenter"
			  
			}
		  }
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Net Flow
Function VCSA-80-000271 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000271"
	  $Title = "The vCenter Server must only send NetFlow traffic to authorized collectors."
	  If($controlsenabled.VCSA8000271){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
		  
		}Else{
		  ForEach($switch in $dvs){
			If($switch.ExtensionData.Config.IpfixConfig.CollectorIpAddress -ne $vcconfig.vcNetflowCollectorIp){
			  Write-ToConsoleYellow "...Unknown NetFlow collector on $($switch.name) on $vcenter"
			  $switchview = $switch | Get-View
			  $spec = New-Object VMware.Vim.VMwareDVSConfigSpec
			  $spec.configversion = $switchview.Config.ConfigVersion
			  $spec.IpfixConfig = New-Object VMware.Vim.VMwareIpfixConfig
			  $spec.IpfixConfig.CollectorIpAddress = $vcconfig.vcNetflowCollectorIp
			  $spec.IpfixConfig.CollectorPort = "0"
			  $spec.IpfixConfig.ObservationDomainId = "0"
			  $spec.IpfixConfig.ActiveFlowTimeout = "60"
			  $spec.IpfixConfig.IdleFlowTimeout = "15"
			  $spec.IpfixConfig.SamplingRate = "4096"
			  $spec.IpfixConfig.InternalFlowsOnly = $False
			  $switchview.ReconfigureDvs_Task($spec)
			  
			}Else{
			  Write-ToConsoleGreen "...No unknown NetFlow collectors configured on $($switch.name) on $vcenter"
			  
			}
		  }
		  If($vcNetflowDisableonallPortGroups){
			ForEach($pg in $dvpg){
			  If($pg.ExtensionData.Config.DefaultPortConfig.IpfixEnabled.value -eq $true){
				Write-ToConsoleRed "...NetFlow collection enabled on $($pg.name) on $vcenter"
				$pgview = $pg | Get-View
				$spec = New-Object VMware.Vim.DVPortgroupConfigSpec
				$spec.configversion = $pgview.Config.ConfigVersion
				$spec.defaultPortConfig = New-Object VMware.Vim.VMwareDVSPortSetting
				$spec.defaultPortConfig.ipfixEnabled = New-Object VMware.Vim.BoolPolicy
				$spec.defaultPortConfig.ipfixEnabled.inherited = $true
				$spec.defaultPortConfig.ipfixEnabled.value = $false
				$pgview.ReconfigureDVPortgroup_Task($spec)
				
			  }Else{
				Write-ToConsoleGreen "...NetFlow collection disabled on $($pg.name) on $vcenter"
				
			  }
			}   
		  }
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Native VLAN
Function VCSA-80-000272 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000272"
	  $Title = "The vCenter Server must configure all port groups to a value other than that of the native VLAN."
	  If($controlsenabled.VCSA8000272){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
		  
		}Else{
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## VLAN Trunking
Function VCSA-80-000273 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000273"
	  $Title = "The vCenter Server must not configure VLAN Trunking unless Virtual Guest Tagging (VGT) is required and authorized."
	  If($controlsenabled.VCSA8000273){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
		  
		}Else{
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Reserved VLANs
Function VCSA-80-000274 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000274"
	  $Title = "The vCenter Server must not configure all port groups to VLAN values reserved by upstream physical switches."
	  If($controlsenabled.VCSA8000274){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
		  
		}Else{
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## VPXD PW
Function VCSA-80-000275 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000275"
	  $Title = "The vCenter Server must configure the vpxuser auto-password to be changed every 30 days."
	  If($controlsenabled.VCSA8000275){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$name = $vcconfig.vpxdExpiration.Keys
		$value = [string]$vcconfig.vpxdExpiration.Values
		## Checking to see if current setting exists
		If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
		  If($asetting.value -eq $value){
			Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
			
		  }Else{
			Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
			$asetting | Set-AdvancedSetting -Value $value -Confirm:$false
			
		  }
		}Else{
		  Write-ToConsoleYellow "...Setting $name does not exist on $vcenter...creating setting..."
		  New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
		  
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## VPXD PW Length
Function VCSA-80-000276 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000276"
	  $Title = "The vCenter Server must configure the vpxuser password meets length policy."
	  If($controlsenabled.VCSA8000276){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$name = $vcconfig.vpxdPwLength.Keys
		$value = [string]$vcconfig.vpxdPwLength.Values
		## Checking to see if current setting exists
		If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
		  If($asetting.value -eq $value){
			Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
			
		  }Else{
			Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
			$asetting | Set-AdvancedSetting -Value $value -Confirm:$false
			
		  }
		}Else{
		  Write-ToConsoleGreen "...Setting $name does not exist on $vcenter and is not a finding..."
		  
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## vLCM
Function VCSA-80-000277 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000277"
	  $Title = "The vCenter Server must be isolated from the public Internet but must still allow for patch notification and delivery."
	  If($controlsenabled.VCSA8000277){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Service accounts
Function VCSA-80-000278 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000278"
	  $Title = "The vCenter Server must use unique service accounts when applications connect to vCenter."
	  If($controlsenabled.VCSA8000278){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Isolate IP based storage
Function VCSA-80-000279 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000279"
	  $Title = "The vCenter Server must protect the confidentiality and integrity of transmitted information by isolating IP-based storage traffic."
	  If($controlsenabled.VCSA8000279){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Send events to syslog
Function VCSA-80-000280 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000280"
	  $Title = "The vCenter server must be configured to send events to a central log server."
	  If($controlsenabled.VCSA8000280){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$name = $vcconfig.vpxdEventSyslog.Keys
		$value = [string]$vcconfig.vpxdEventSyslog.Values
		## Checking to see if current setting exists
		If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
		  If($asetting.value -eq $value){
			Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
			
		  }Else{
			Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
			$asetting | Set-AdvancedSetting -Value $value -Confirm:$false
			
		  }
		}Else{
		  Write-ToConsoleYellow "...Setting $name does not exist on $vcenter...creating setting..."
		  New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
		  
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## VSAN HCL
Function VCSA-80-000281 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000281"
	  $Title = "The vCenter Server must disable or restrict the connectivity between vSAN Health Check and public Hardware Compatibility List by use of an external proxy server."
	  If($controlsenabled.VCSA8000281){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## VSAN Datastore names
Function VCSA-80-000282 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000282"
	  $Title = "The vCenter Server must configure the vSAN Datastore name to a unique name."
	  If($controlsenabled.VCSA8000282){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$vsandatastores = Get-Datastore | Where-Object {$_.type -match "vsan"}
		If($vsandatastores.count -eq 0){
		  Write-ToConsoleBlue "...No VSAN datastores detected on $vcenter"
		  
		}Else{
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
		}
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Disable UN/PW and IWA
Function VCSA-80-000283 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000283"
	  $Title = "The vCenter Server must disable Username/Password and Windows Integrated Authentication."
	  If($controlsenabled.VCSA8000283){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Crypto role
Function VCSA-80-000284 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000284"
	  $Title = "The vCenter Server must restrict access to the cryptographic role."
	  If($controlsenabled.VCSA8000284){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Crypto permissions
Function VCSA-80-000285 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000285"
	  $Title = "The vCenter Server must restrict access to cryptographic permissions."
	  If($controlsenabled.VCSA8000285){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## iSCSI CHAP
Function VCSA-80-000286 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000286"
	  $Title = "The vCenter Server must have Mutual CHAP configured for vSAN iSCSI targets."
	  If($controlsenabled.VCSA8000286){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## VSAN KEKs
Function VCSA-80-000287 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000287"
	  $Title = "The vCenter Server must have new Key Encryption Keys (KEKs) re-issued at regular intervals for vSAN encrypted datastore(s)."
	  If($controlsenabled.VCSA8000287){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## LDAPS
Function VCSA-80-000288 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000288"
	  $Title = "The vCenter Server must use LDAPS when adding an LDAP identity source."
	  If($controlsenabled.VCSA8000288){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## LDAP Account
Function VCSA-80-000289 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000289"
	  $Title = "The vCenter Server must use a limited privilege account when adding an LDAP identity source."
	  If($controlsenabled.VCSA8000289){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Bash Admin Group
Function VCSA-80-000290 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000290"
	  $Title = "The vCenter Server must limit membership to the SystemConfiguration.BashShellAdministrators SSO group."
	  If($controlsenabled.VCSA8000290){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$groupname = "SystemConfiguration.BashShellAdministrators"
		$users = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoPersonUser
		$groups = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoGroup
		# Add appliance management user to list of approved users so it doesn't get removed
		$vcconfig.bashAdminUsers += Get-SsoGroup -Domain vsphere.local -Name applmgmtSvcUsers | Get-SsoPersonUser | Select-Object -ExpandProperty Name
		ForEach($user in $users){
		  If($vcconfig.bashAdminUsers.Contains($user.name)){
			Write-ToConsoleGreen "...User: $($user.name) in list of approved users."
			
		  }Else{
			Write-ToConsoleYellow "...User: $($user.name) in not approved...removing..."
			Remove-UserFromSsoGroup -User $user -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
			
		  }
		}
		ForEach($group in $groups){
		  If($vcconfig.bashAdminGroups.Contains($group.name)){
			Write-ToConsoleGreen "...Group: $($group.name) in list of approved groups."
			
		  }Else{
			Write-ToConsoleYellow "...Group: $($group.name) in not approved...removing..."
			Remove-GroupFromSsoGroup -Group $group -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
			
		  }
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Trusted Admin Group
Function VCSA-80-000291 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000291"
	  $Title = "The vCenter Server must limit membership to the TrustedAdmins SSO group."
	  If($controlsenabled.VCSA8000291){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$groupname = "TrustedAdmins"
		$users = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoPersonUser
		$groups = Get-SsoGroup -Domain vsphere.local -Name $groupname | Get-SsoGroup
		ForEach($user in $users){
		  If($vcconfig.trustedAdminUsers.Contains($user.name)){
			Write-ToConsoleGreen "...User: $($user.name) in list of approved users."
			
		  }Else{
			Write-ToConsoleYellow "...User: $($user.name) in not approved...removing..."
			Remove-UserFromSsoGroup -User $user -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
			
		  }
		}
		ForEach($group in $groups){
		  If($vcconfig.trustedAdminGroups.Contains($group.name)){
			Write-ToConsoleGreen "...Group: $($group.name) in list of approved groups."
			
		  }Else{
			Write-ToConsoleYellow "...Group: $($group.name) in not approved...removing..."
			Remove-GroupFromSsoGroup -Group $group -TargetGroup (Get-SsoGroup -Domain vsphere.local -Name $groupname)
			
		  }
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Backups
Function VCSA-80-000292 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000292"
	  $Title = "The vCenter server configuration must be backed up on a regular basis."
	  If($controlsenabled.VCSA8000292){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Task Retention
Function VCSA-80-000293 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000293"
	  $Title = "vCenter task and event retention must be set to at least 30 days."
	  If($controlsenabled.VCSA8000293){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$name = $vcconfig.dbEventAge.Keys
		$value = [string]$vcconfig.dbEventAge.Values
		## Checking to see if current setting exists
		If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
		  If($asetting.value -eq $value){
			Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
			
		  }Else{
			Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
			$asetting | Set-AdvancedSetting -Value $value -Confirm:$false
			
		  }
		}Else{
		  Write-ToConsoleYellow "...Setting $name does not exist on $vcenter...creating setting..."
		  New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
		  
		}
		$name = $vcconfig.dbTaskAge.Keys
		$value = [string]$vcconfig.dbTaskAge.Values
		## Checking to see if current setting exists
		If($asetting = Get-AdvancedSetting -Name $name -Entity $global:DefaultVIServers){
		  If($asetting.value -eq $value){
			Write-ToConsoleGreen "...Setting $name is already configured correctly to $value on $vcenter"
			
		  }Else{
			Write-ToConsoleYellow "...Setting $name was incorrectly set to $($asetting.value) on $vcenter...setting to $value"
			$asetting | Set-AdvancedSetting -Value $value -Confirm:$false
			
		  }
		}Else{
		  Write-ToConsoleYellow "...Setting $name does not exist on $vcenter...creating setting..."
		  New-AdvancedSetting -Name $name -Value $value -Entity $global:DefaultVIServers -Confirm:$false
		  
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## NKP
Function VCSA-80-000294 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000294"
	  $Title = "vCenter Native Key Providers must be backed up with a strong password."
	  If($controlsenabled.VCSA8000294){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Content Library Password
Function VCSA-80-000295 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000295"
	  $Title = "The vCenter server must require authentication for published content libraries."
	  If($controlsenabled.VCSA8000295){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Content Library Security Policy
Function VCSA-80-000296 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000296"
	  $Title = "The vCenter server must enable the OVF security policy for content libraries."
	  If($controlsenabled.VCSA8000296){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## SSO Groups for Authorization
Function VCSA-80-000298 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000298"
	  $Title = "The vCenter Server must separate authentication and authorization for administrators."
	  If($controlsenabled.VCSA8000298){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Disable CDP/LLDP
Function VCSA-80-000299 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000299"
	  $Title = "The vCenter Server must disable CDP/LLDP on distributed switches."
	  If($controlsenabled.VCSA8000299){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter...skipping..."
		  
		}Else{
		  ForEach($switch in $dvs){
			If($switch.LinkDiscoveryProtocolOperation -ne "Disabled"){
			  Write-ToConsoleYellow "...CDP/LLDP enabled on $($switch.name) on $vcenter"
			  $switch | Set-VDSwitch -LinkDiscoveryProtocolOperation "Disabled"
			  
			}Else{
			  Write-ToConsoleGreen "...CDP/LLDP disabled on $($switch.name) on $vcenter"
			  
			}
		  }
		}
	  }
	  Else{
		Write-ToConsoleRed "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Port Mirroring
Function VCSA-80-000300 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000300"
	  $Title = "The vCenter Server must remove unauthorized port mirroring sessions on distributed switches."
	  If($controlsenabled.VCSA8000300){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
		
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## DPG override policies
Function VCSA-80-000301 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000301"
	  $Title = "The vCenter Server must not override port group settings at the port level on distributed switches."
	  If($controlsenabled.VCSA8000301){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
		  
		}Else{
		  ForEach($pg in $dvpg){
			If(($pg.ExtensionData.Config.Policy.VlanOverrideAllowed -eq $true) -or ($pg.ExtensionData.Config.Policy.UplinkTeamingOverrideAllowed -eq $true ) -or ($pg.ExtensionData.Config.Policy.SecurityPolicyOverrideAllowed -eq $true) -or ($pg.ExtensionData.Config.Policy.IpfixOverrideAllowed -eq $true) -or ($pg.ExtensionData.Config.Policy.ShapingOverrideAllowed -eq $true) -or ($pg.ExtensionData.Config.Policy.VendorConfigOverrideAllowed -eq $true) -or ($pg.ExtensionData.Config.Policy.TrafficFilterOverrideAllowed -eq $true)){
			  Write-ToConsoleYellow "...Port group override settings incorrect on $($pg.name) on $vcenter"
			  $pgview = $pg | Get-View
			  $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
			  $spec.configversion = $pgview.Config.ConfigVersion
			  $spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
			  $spec.Policy.VlanOverrideAllowed = $False
			  $spec.Policy.UplinkTeamingOverrideAllowed = $False
			  $spec.Policy.SecurityPolicyOverrideAllowed = $False
			  $spec.Policy.IpfixOverrideAllowed = $False
			  $spec.Policy.BlockOverrideAllowed = $True
			  $spec.Policy.ShapingOverrideAllowed = $False
			  $spec.Policy.VendorConfigOverrideAllowed = $False
			  $spec.Policy.TrafficFilterOverrideAllowed = $False
			  $pgview.ReconfigureDVPortgroup_Task($spec)
			  
			}Else{
			  Write-ToConsoleGreen "...Port group override settings correct on $($pg.name) on $vcenter"
			  
			}
		  }
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## DPG reset as disconnect
Function VCSA-80-000302 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000302"
	  $Title = "The vCenter Server must reset port configuration when virtual machines are disconnected."
	  If($controlsenabled.VCSA8000302){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If($dvs.count -eq 0){
		  Write-ToConsoleBlue "...No distributed switches detected on $vcenter"
		  
		}Else{
		  ForEach($pg in $dvpg){
			If($pg.ExtensionData.Config.Policy.PortConfigResetAtDisconnect -eq $false){
			  Write-ToConsoleYellow "...Port group reset at disconnect settings incorrect on $($pg.name) on $vcenter"
			  $pgview = $pg | Get-View
			  $spec = New-Object VMware.Vim.DVPortgroupConfigSpec
			  $spec.configversion = $pgview.Config.ConfigVersion
			  $spec.Policy = New-Object VMware.Vim.VMwareDVSPortgroupPolicy
			  $spec.Policy.PortConfigResetAtDisconnect = $True
			  $pgview.ReconfigureDVPortgroup_Task($spec)
			  
			}Else{
			  Write-ToConsoleGreen "...Port group reset at disconnect correct on $($pg.name) on $vcenter"
			  
			}
		  }
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## SSH Disable
Function VCSA-80-000303 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000303"
	  $Title = "The vCenter Server must disable SSH access."
	  If($controlsenabled.VCSA8000303){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		# Disable vCenter SSH
		$body = Initialize-AccessSshSetRequestBody -Enabled $false
		Invoke-SetAccessSsh -AccessSshSetRequestBody $body
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## vSAN DIT Encryption
Function VCSA-80-000304 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000304"
	  $Title = "The vCenter Server must enable data in transit encryption for vSAN."
	  If($controlsenabled.VCSA8000304){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		Write-ToConsoleBlue "...!!This control must be remediated manually!!"
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	}
}

## Trusted Admin Group
Function VCSA-80-000305 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000305"
	  $Title = "The vCenter Server must disable accounts used for Integrated Windows Authentication (IWA)."
	  If($controlsenabled.VCSA8000305){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		If((Get-SsoPersonUser -Domain vsphere.local -Name "krbtgt/VSPHERE.LOCAL").Disabled -eq $true){
		  Write-ToConsoleGreen "...User: krbtgt/VSPHERE.LOCAL is already disabled."
		  
		}Else{
		  Write-ToConsoleYellow "...User: krbtgt/VSPHERE.LOCAL is enabled...disabling..."
		  Get-SsoPersonUser -Domain vsphere.local -Name "krbtgt/VSPHERE.LOCAL" | Set-SsoPersonUser -Enable $false
		  
		}
		If((Get-SsoPersonUser -Domain vsphere.local -Name "K/M").Disabled -eq $true){
		  Write-ToConsoleGreen "...User: K/M is already disabled."
		  
		}Else{
		  Write-ToConsoleYellow "...User: K/M is enabled...disabling..."
		  Get-SsoPersonUser -Domain vsphere.local -Name "K/M" | Set-SsoPersonUser -Enable $false
		  
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}

## Update TLS Profile. Running this last since it can interrupt the PowerCLI connection
Function VCSA-80-000009 ($controlsenabled, $vcconfig, $vcenter) {
	Try{
	  $STIGID = "VCSA-80-000009"
	  $Title = "The vCenter Server must use DOD-approved encryption to protect the confidentiality of network sessions."
	  If($controlsenabled.VCSA8000009){
		Write-ToConsole "...Remediating STIG ID: $STIGID with Title: $Title"
		$currentTlsProfile = Invoke-GetTlsProfilesGlobal
		If($currentTlsProfile.profile -ne $vcconfig.tlsProfile){
		  Write-ToConsoleYellow "...TLS Profile incorrectly set to $($currentTlsProfile.profile) on $vcenter"
		  Invoke-SetProfilesGlobalAsync -TlsProfilesGlobalSetSpec (Initialize-TlsProfilesGlobalSetSpec -VarProfile $vcconfig.tlsProfile)
		  Write-ToConsoleYellow "...TLS Profile updated to $($vcconfig.tlsProfile) on $vcenter...note that this will take several minutes to complete."
		  
		}Else{
		  Write-ToConsoleGreen "...TLS Profile set correctly to $($vcconfig.tlsProfile) on $vcenter"
		  
		}
	  }
	  Else{
		Write-ToConsoleBlue "...Skipping disabled control STIG ID:$STIGID with Title: $Title"
		
	  }
	}
	Catch{
	  Write-Error "Failed to remediate STIG ID:$STIGID with Title: $Title on $vcenter"
	  Write-Error $_.Exception
	  
	}
}
