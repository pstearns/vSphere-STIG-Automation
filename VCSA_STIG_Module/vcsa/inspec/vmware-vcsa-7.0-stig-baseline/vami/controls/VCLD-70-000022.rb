control 'VCLD-70-000022' do
  title 'VAMI must have debug logging disabled.'
  desc  "
    Information needed by an attacker to begin looking for possible vulnerabilities in a web server includes any information about the web server and plug-ins or modules being used. When debugging or trace information is enabled in a production web server, information about the web server, such as web server type, version, patches installed, plug-ins and modules installed, type of code being used by the hosted application, and any backends being used for data storage may be displayed.

    Since this information may be placed in logs and general messages during normal operation of the web server, an attacker does not need to cause an error condition to gain this information.
  "
  desc  'rationale', ''
  desc  'check', "
    At the command prompt, execute the following command:

    # /opt/vmware/sbin/vami-lighttpd -p -f /opt/vmware/etc/lighttpd/lighttpd.conf 2>/dev/null|grep \"debug.log-request-handling\"|sed 's: ::g'

    Expected result:

    debug.log-request-handling=\"disable\"

    If the output does not match the expected result, this is a finding.

    Note: The command must be run from a bash shell and not from a shell generated by the \"appliance shell\". Use the \"chsh\" command to change the shell for your account to \"/bin/bash\". See KB Article 2100508 for more details.
  "
  desc 'fix', "
    Navigate to and open:

    /opt/vmware/etc/lighttpd/lighttpd.conf

    Add or reconfigure the following value:

    debug.log-request-handling = \"disable\"

    Restart the service with the following command:

    # vmon-cli --restart applmgmt
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'SRG-APP-000266-WSR-000160'
  tag gid: nil
  tag rid: nil
  tag stig_id: 'VCLD-70-000022'
  tag cci: ['CCI-001312']
  tag nist: ['SI-11 a']

  runtime = command("#{input('lighttpdBin')} -p -f #{input('lighttpdConf')}").stdout

  describe parse_config(runtime).params['debug.log-request-handling'] do
    it { should cmp "#{input('debugLogRequestHandling')}" }
  end
end