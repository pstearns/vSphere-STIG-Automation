## 8.0 Version 1 Release 1] (2024-10-23)

# Included 2 items that require SSH - 2024-10-23
ESXI-80-000236 - The ESXi host must not be configured to override virtual machine (VM) configurations.
	# stat -c "%s" /etc/vmware/settings 
	Expected result: 0

ESXI-80-000237 - The ESXi host must not be configured to override virtual machine (VM) logger settings.
	# grep "^vmx\.log" /etc/vmware/config
	If the command produces any output, this is a finding.


