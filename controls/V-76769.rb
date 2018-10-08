control 'V-76769' do
  title "Unspecified file extensions on a production IIS 8.5 web server must be
removed."
  desc  "By allowing unspecified file extensions to execute, the web servers
attack surface is significantly increased. This increased risk can be reduced
by only allowing specific ISAPI extensions or CGI extensions to run on the web
server."
  impact 0.7
  tag "gtitle": 'SRG-APP-000516-WSR-000174'
  tag "gid": 'V-76769'
  tag "rid": 'SV-91465r1_rule'
  tag "stig_id": 'IISW-SV-000158'
  tag "fix_id": 'F-83465r1_fix'
  tag "cci": ['CCI-000366']
  tag "nist": ['CM-6 b', 'Rev_4']
  tag "false_negatives": nil
  tag "false_positives": nil
  tag "documentable": false
  tag "mitigations": nil
  tag "severity_override_guidance": false
  tag "potential_impacts": nil
  tag "third_party_tools": nil
  tag "mitigation_controls": nil
  tag "responsibility": nil
  tag "ia_controls": nil
  tag "check": "Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the \"ISAPI and CGI restrictions\" icon.

Click “Edit Feature Settings\".

Verify the \"Allow unspecified CGI modules\" and the \"Allow unspecified ISAPI
modules\" check boxes are NOT checked.

If either or both of the \"Allow unspecified CGI modules\" and the \"Allow
unspecified ISAPI modules\" check boxes are checked, this is a finding."
  tag "fix": "Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the \"ISAPI and CGI restrictions\" icon.

Click \"Edit Feature Settings\".

Remove the check from the \"Allow unspecified CGI modules\" and the \"Allow
unspecified ISAPI modules\" check boxes.

Click OK."

  describe windows_feature('Web-ISAPI-Ext') do
    it { should be_installed }
  end

  # FIXME: should these be 'true/false' strings? Boolans. The control previous to
  # this one uses upper-case True / False. Which is the correct? lower or upper?
  # what does this command return?

  describe command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/isapiCgiRestriction" -Name notListedCgisAllowed | select -expandProperty value').stdout.strip do
    it { should cmp 'False' }
  end

  describe command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/isapiCgiRestriction" -Name notListedIsapisAllowed | select -expandProperty value').stdout.strip do
    it { should cmp 'False' }
  end
end
