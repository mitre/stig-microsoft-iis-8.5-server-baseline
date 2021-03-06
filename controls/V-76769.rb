control 'V-76769' do
  title "Unspecified file extensions on a production IIS 8.5 web server must be
  removed."
  desc "By allowing unspecified file extensions to execute, the web servers
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

  isInstalledIsapiCGI = !command('Get-WindowsFeature Web-ISAPI-Ext | Where Installed').stdout.strip.nil?
  notListedCgisAllowed = command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/isapiCgiRestriction" -Name notListedCgisAllowed | select -expandProperty value').stdout.strip == 'False'
  notListedIsapisAllowed = command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/isapiCgiRestriction" -Name notListedIsapisAllowed | select -expandProperty value').stdout.strip == 'False'

  describe 'The ISAPI and CGI restrictions feature must be installed. (currently: ' + (isInstalledIsapiCGI ? 'installed' : 'uninstalled') + " )\n" do
    subject { windows_feature('Web-ISAPI-Ext') }
    it 'The ISAPI and CGI restrictions should be installed' do
      expect(subject).to be_installed
    end
  end
  describe 'The ISAPI and CGI restrictions for notListedCgisAllowed must not be enabled. (currently: ' + (notListedCgisAllowed ? 'disabled' : 'enabled') + " )\n" do
    subject { command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/isapiCgiRestriction" -Name notListedCgisAllowed | select -expandProperty value').stdout.strip }
    it 'The ISAPI and CGI restrictions attribute notListedCgisAllowed should not be checked' do
      expect(subject).to cmp('False')
    end
  end
  describe 'The ISAPI and CGI restrictions for notListedIsapisAllowed must not be enabled. (currently: ' + (notListedIsapisAllowed ? 'disabled' : 'enabled') + " )\n" do
    subject { command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/isapiCgiRestriction" -Name notListedIsapisAllowed | select -expandProperty value').stdout.strip }
    it 'The ISAPI and CGI restrictions attribute notListedIsapisAllowed should not be checked' do
      expect(subject).to cmp('False')
    end
  end
end
