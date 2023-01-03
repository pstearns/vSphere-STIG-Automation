control 'ESXI-70-000038' do
  title 'ESXi hosts using Host Profiles and/or Auto Deploy must use the vSphere Authentication Proxy to protect passwords when adding themselves to Active Directory.'
  desc  'If a host is configured to join an Active Directory domain using Host Profiles and/or Auto Deploy, the Active Directory credentials are saved in the profile and are transmitted over the network. To avoid having to save Active Directory credentials in the Host Profile and to avoid transmitting Active Directory credentials over the network, use the vSphere Authentication Proxy.'
  desc  'rationale', ''
  desc  'check', "
    If you are not using Host Profiles to join Active Directory, this is Not Applicable.

    From the vSphere Client go to Home >> Policies and Profiles >> Host Profiles >> Click a Host Profile to details edit mode >> Configure >> Security and Services >> Security Settings >> Authentication Configuration >> Active Directory Configuration >> Join Domain Method.

    If the method used to join hosts to a domain is not set to \"Use vSphere Authentication Proxy to add the host to domain\", this is a finding.

    or

    From a PowerCLI command prompt while connected to vCenter, run the following command:

    Get-VMHost | Select Name, ` @{N=\"HostProfile\";E={$_ | Get-VMHostProfile}}, ` @{N=\"JoinADEnabled\";E={($_ | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled}}, ` @{N=\"JoinDomainMethod\";E={(($_ | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq \"JoinDomainMethodPolicy\"}).Policyoption.Id}}

    If \"JoinADEnabled\" is \"True\" and \"JoinDomainMethod\" is not \"FixedCAMConfigOption\", this is a finding.
  "
  desc 'fix', "
    From the vSphere Client go to Home >> Policies and Profiles >> Host Profiles >> Click a Host Profile to enter details mode >> Configure >> Security and Services >> Security Settings >> Authentication Configuration >> Active Directory Configuration.

    Click \"Edit Host Profile...\". Set the \"Join Domain Method\" to \"Use vSphere Authentication Proxy to add the host to domain\" and provide the IP address of the vSphere Authentication Proxy server. Click \"Save\".
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-OS-000104-VMM-000500'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'ESXI-70-000038'
  tag cci: ['CCI-000764']
  tag nist: ['IA-2']

  vmhostName = input('vmhostName')
  cluster = input('cluster')
  allhosts = input('allesxi')
  vmhosts = []

  unless vmhostName.empty?
    vmhosts = powercli_command("Get-VMHost -Name #{vmhostName} | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless cluster.empty?
    vmhosts = powercli_command("Get-Cluster -Name '#{cluster}' | Get-VMHost | Sort-Object Name | Select -ExpandProperty Name").stdout.split
  end
  unless allhosts == false
    vmhosts = powercli_command('Get-VMHost | Sort-Object Name | Select -ExpandProperty Name').stdout.split
  end

  if !vmhosts.empty?
    vmhosts.each do |vmhost|
      # Check for Host Profiles
      HostProfile = powercli_command("vmhost | Get-VmHostProfile").stdout
      describe 'Checking if Host Profiles are used' do
        subject { HostProfile }
        it { should be_empty }
      end

      unless HostProfile.empty?
        HostProfileAD = powercli_command("(vmhost | Get-VmHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory.Enabled").stdout
        describe 'Checking if AD enabled in HostProfile' do
          subject { HostProfileAD }
          it { should be_empty }
        end

	HostProfileADMethod = powercli_command('(($vmhost | Get-VMHostProfile).ExtensionData.Config.ApplyProfile.Authentication.ActiveDirectory | Select -ExpandProperty Policy | Where {$_.Id -eq "JoinDomainMethodPolicy"}).Policyoption.Id')
        describe 'Checking if JoinDomainMethodPolicy is in HostProfile' do
          subject { HostProfileADMethod }
          it { should be_empty }
        end
      end
    end
  else
    describe 'No hosts found!' do
      skip 'No hosts found...skipping tests'
    end
  end
end
