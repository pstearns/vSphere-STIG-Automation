# vSphere-STIG-Automation
Custom solution to automating STIG verification and remediation, leveraging vmware/dod-compliance-and-automation

## Overview
This solution is built to run on a RHEL 8 system with Ansible, Inspec, PowerCLI installed.
Building on the https://github.com/vmware/dod-compliance-and-automation repo to fully automate verifying, remediating, and outputing a CKL for vSphere DoD SRG.

## Tested against
* ansible core 2.13.2
* inspec 5.18.14
* PowerCLI 12.6
* Powershell 5/Core 7.2.6
* vCenter/ESXi 7.0 U3

## vSphere VCSA
* Poweshell script vcsa_stig_automation.ps1
* DESCRIPTION:
  * Script runs the Inspec Profile against the VCSA
  * Then calls Ansible to fix open findings
  * Outputs a STIG Viewer Checklist file
* Modify vcsa_stig_automation.ps1 to set varibles under the DECLARE VARIBLES section.
* Run vcsa_stig_automation.ps1 
  * Will prompt for all input. 

## vSphere ESXi
* Poweshell script esxi_stig_automation.ps1
* DESCRIPTION:
  * This script runs the Inspec Profile against all ESXi in a VCSA
  * Then calls Ansible and Powershell to fix open findings
  * Outputs a STIG Viewer Checklist file per ESXi host
* Modify esxi_stig_automation.ps1 to set varibles under the DECLARE VARIBLES section.
* Run esxi_stig_automation.ps1 
  * Parameters: 
    * vcenter - FQDN or IP of the vCenter Server to connect
    * hostname - hostname of a single ESXi host to remediate - all hosts if not defined
    * cluster - name of a vSphere cluster to remediate all hosts in a targeted cluster - all clusters if not defined
    * vdi - Enter yes, y, Yes if running against a VDI cluster. This will allow for MemPage Sharing on VDI cluster
    * EXAMPLE: .\esxi_stig_automation.ps1 -vcenter vcentername.test.local -hostname myhost.test.local

## Other Modifications
Each Powershell script includes a Comments and Markups section to allow modifying specific VULN COMMENTs and STATUS. These will modify the final CKL output file with site specific changes or exlusions.

Other modifications to provide more flexibility for site specific findings. For example creating an array of MGMT VLANs for enviorments that use multiple MGMT VLANs in different clusters. 

CREDIT: https://github.com/vmware/dod-compliance-and-automation
