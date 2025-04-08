# vSphere-STIG-Automation  
A custom solution for automating STIG (Security Technical Implementation Guide) verification and remediation, leveraging VMware's [DoD Compliance and Automation](https://vmware.github.io/dod-compliance-and-automation) tools.

[![VMware](https://img.shields.io/badge/VMware-DoD%20Compliance-blue)](https://www.vmware.com/) [![Automation](https://img.shields.io/badge/Automation-Scripts-brightgreen)](https://shields.io) [![PowerShell](https://img.shields.io/badge/PowerShell-7.4-blue)](https://shields.io) [![Ruby](https://img.shields.io/badge/Ruby-3.x-red)](https://www.ruby-lang.org/en/) [![Ansible](https://img.shields.io/badge/Ansible-2.13-green)](https://www.ansible.com/)

## Table of Contents
- [Purpose](#purpose)
- [Overview](#overview)
- [Features](#features)
- [Prerequisites](#prerequisites)
- [Usage](#usage)
  - [vSphere STIG Automation (PowerShell Wrappers)](#vsphere-stig-automation-powershell-wrappers)
  - [Automation Framework Scripts](#automation-framework-scripts)
- [Steps to Run Automation](#steps-to-run-automation)
- [Customizations](#customizations)
  - [Defining Variables](#defining-variables)
  - [Comments and Markups](#comments-and-markups)
  - [Other Modifications](#other-modifications)
    - [ESXi OS Detection via SSH](#esxi-os-detection-via-ssh)
    - [Fixed JSON Encoding Errors](#fixed-json-encoding-errors)
    - [Enhanced Password Handling](#enhanced-password-handling)
- [Future Enhancements](#future-enhancements)
- [Credit](#credit)

---

## Purpose
This project simplifies and automates the intricate process of verifying and remediating vSphere STIG compliance. It drastically reduces manual effort while ensuring accuracy. Key functionalities include:
- Seamless compliance validation
- Remediation
- Generation of STIG Viewer Checklists (CKLs) for vSphere environments

---

## Overview
This project is designed to run on a RHEL 8 system equipped with **Ansible**, **Cinc-Auditor**, **PowerCLI**, and **PowerShell**. It enhances VMware's [DoD Compliance and Automation](https://vmware.github.io/dod-compliance-and-automation) repository tools to fully automate:
1. **Compliance Verification**: Ensures adherence to vSphere STIG guidelines.
2. **Remediation**: Utilizes Ansible playbooks to address findings.
3. **Checklist Generation**: Produces STIG Viewer Checklists (CKLs) for vSphere environments, including vCenter, ESXi hosts, and VMs.

---

## Features
- **Automated Verification**: Leverages Cinc-Auditor to verify over 90% of vSphere STIGs, supporting specific profiles or individual controls.
- **Automated Remediation**: Utilizes Ansible playbooks to resolve findings, targeting specific controls or profiles as needed.
- **PowerShell Wrappers**: Streamlines and automates processes across the vSphere stack, such as checklist conversion and asset information updates.
- **Flexible Integration**: Adapts to site-specific variables and configurations for tailored environments.
- **Efficient Workflow**: Employs optimized scripts to enhance processing efficiency via parallelization.

---

## Prerequisites
Ensure the following tools and versions are installed before executing the scripts:
- **Ansible**: 2.13.2
- **Cinc-Auditor**: 6.8.24 (with `train-vmware-0.2.0.gem`)
- **Inspec_Tools**: 3.1.0 *(Future Update: Convert to SAF Tools)*
- **PowerCLI**: 13.3.0 (with `VMware.vSphere.SsoAdmin 1.3.8`)
- **PowerShell**: 7.4.5
- **vCenter/ESXi**: 8.0 U3

---

## Usage

### vSphere STIG Automation (PowerShell Wrappers)
PowerShell script wrappers streamline and automate **Cinc-Auditor** and **Ansible** processes across the vSphere stack. These scripts manage variables, credentials, and systematic traversal of services, hosts, and VMs. Key functionalities:
- Converts Cinc-Auditor JSON files into Checklists.
- Updates asset information and applies specific check markups.
- Enhances processing efficiency through parallelization.

### Automation Framework Scripts:
- **`vSphere_Stig_Menu.ps1`**: Orchestrates credential collection and invokes the following:
  - **`vSphere_VCSA_STIG_Parallel.ps1`**: Automates VCSA services and vCenter tasks.
  - **`vSphere_ESXi_STIG_Parallel.ps1`**: Automates all ESXi Hosts per vCenter.
  - **`vSphere_VM_STIG_Parallel.ps1`**: Automates all VMs per vCenter.

---

## Steps to Run Automation
1. **Run vSphere STIG Menu**:
   - Command: `./vSphere_Stig_Menu.ps1 -RunBy "Your Name"`
   - The `-RunBy` parameter tags the execution with your name and the date.

2. **Gather Credentials**:
   - From the menu, select **Option 1**.
   - Provide the following:
     - vCenter FQDN
     - **Administrator** credentials (e.g., `username@<site>.local`)
     - vCenter **Root Password**
     - ESXi **Root Password**

3. **Choose Options**:
   - **Verification Options (2–5)**: Runs Cinc-Auditor profiles against assets in parallel, generating compliance checklists.
   - **Remediation Options (6–9)**: Uses Cinc-Auditor for verification, Ansible for remediation, and re-runs Cinc-Auditor for confirmation. Produces final compliance checklists.

---

## Customizations

### Defining Variables
Update site-specific variables in the "Declare Variable" section at the beginning of each script. Add new variables to existing arrays for enhanced adaptability.

### Comments and Markups
- Modify designated known checks (e.g., marking Distributed Switch checks as "NA").
- Incorporate changes into the **Known Item** segment, as needed.

### Other Modifications

#### ESXi OS Detection via SSH
To enhance the SSH-based detection of the ESXi OS, modifications have been introduced in several Cinc-Auditor and Inspec resource files. These changes improve the recognition logic when interacting with ESXi systems. If you need to verify or apply these customizations manually, review the modifications below:
- **File:** `/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems/inspec-core-6.8.24/lib/inspec/resources/command.rb`  
  **Change:**  
  ```ruby
  elseif inspec.os.vmkernel?
  ```
- **File:** `/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems/inspec-core-6.8.24/lib/inspec/resources/mount.rb`  
  **Change:**  
  ```ruby
  if os.linux? || os.vmkernel?
  ```
- **File:** `/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems/inspec-core-6.8.24/lib/inspec/resources/file.rb`  
  **Changes:**  
  ```ruby
  # For conditional checks:
  elsif os.vmkernel?
  # And for composite OS checks:
  if inspec.os.linux? || inspec.os.vmkernel?
  ```
- **File:** `/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems/inspec-core-6.8.24/lib/inspec/resources/filesystem.rb`  
  **Change:**  
  ```ruby
  if os.unix? || os.vmkernel?
  ```
- **File:** `/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems/inspec-core-6.8.24/lib/inspec/resources/groups.rb`  
  **Change:**  
  ```ruby
  elsif os.unix? || os.vmkernel?
  ```
- **File:** `/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems/inspec-core-6.8.24/lib/inspec/resources/users.rb`  
  **Change:**  
  ```ruby
  if os.linux? || os.vmkernel?
  ```
- **File:** `/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems/train-core-3.12.7/lib/train/platforms/detect/specifications/os.rb`  
  **Changes:**  
  ```ruby
  # Pattern matching for VMkernel-based systems:
  unix_uname_s =~ /vmkernel/i
  # And assigning the platform correctly:
  plat.name("vmkernel").in_family("esx")
  ```
These changes ensure that when connecting via SSH, the system accurately recognizes an ESXi host.

#### Fixed JSON Encoding Errors
- Adjusted output of `RunBook` to include: `(command).stdout.encode('UTF-8')`.

#### Enhanced Password Handling
- Updated password handling in `VMware.rb` by wrapping passwords in single quotes.
  - File: `/opt/cinc-auditor/embedded/lib/ruby/gems/3.1.0/gems/train-3.12.7/lib/train/transport/vmware.rb`  
  - Original code snippet:  
    ```ruby
    def connect 
      login_command = "Connect-VIServer #{options[:viserver]} -User #{options[:username]} -Password '#{options[:password]}' | Out-Null"
      result = run_command_via_connection(login_command)
    ```
	
---

## Future Enhancements

In future releases, we plan to streamline the scripts to improve portability, ease of sharing, and customization. Our key enhancements include:

- **Custom Configuration Folder:**  
  Create a dedicated folder for environment-specific changes for InSpec and Ansible. This will allow the scripts to reference local custom configurations instead of the default DoD Automation Framework settings, making upgrades simpler and sharing easier.

- **Script Simplification and Portability:**  
  Refactor and simplify the existing scripts to reduce dependencies and improve readability. The goal is to make the scripts more modular, so users can easily customize or extend individual functions as needed.

- **Automated, Non-Interactive Execution:**  
  Reorganize script functions so that they can operate as scheduled tasks by referencing input configuration files. This enhancement will eliminate the need for manual user input during execution, allowing for fully automated compliance checks and remediation processes.

- **Integration with StigWatcher for Checklist Uploads:**  
  Develop automation that leverages StigWatcher to upload checklists directly to StigManager. This will streamline checklist submission, facilitate centralized compliance monitoring, and enhance the overall reporting capabilities.

---

## Credit
This project builds upon VMware's [DoD Compliance and Automation Repository](https://github.com/vmware/dod-compliance-and-automation). Their tools and documentation are the foundation of this automated solution.

Learn more at VMware's [Compliance Automation Documentation](https://vmware.github.io/dod-compliance-and-automation).

---
