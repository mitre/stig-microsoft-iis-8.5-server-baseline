control 'V-76771' do
  title "The IIS 8.5 web server must have a global authorization rule
configured to restrict access."
  desc  "Authorization rules can be configured at the server, website, folder
(including Virtual Directories), or file level. It is recommended that URL
Authorization be configured to only grant access to the necessary security
principals. Configuring a global Authorization rule that restricts access
ensures inheritance of the settings down through the hierarchy of web
directories. This will ensure access to current and future content is only
granted to the appropriate principals, mitigating risk of unauthorized access."
  impact 0.7
  tag "gtitle": 'SRG-APP-000516-WSR-000174'
  tag "gid": 'V-76771'
  tag "rid": 'SV-91467r2_rule'
  tag "stig_id": 'IISW-SV-000159'
  tag "fix_id": 'F-83467r2_fix'
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

Double-click the “Authorization Rules” icon.

If any user other than “Administrator” is listed, this is a finding.
"
  tag "fix": "Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Double-click the “Authorization Rules” icon.

Remove all users other than “Administrator”."

  # FIXME: should these be 'true/false' strings? Boolans. The control previous to
  # this one uses upper-case True / False. Which is the correct? lower or upper?
  # what does this command return?

  describe command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/authentication/anonymousAuthentication" -Name enabled | select -expandProperty value').stdout.strip do
    it { should cmp 'false' }
  end
  describe command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/authentication/basicAuthentication" -Name enabled | select -expandProperty value').stdout.strip do
    it { should cmp 'true' }
  end
  describe command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/security/authentication/basicAuthentication" -Name defaultLogonDomain | select -expandProperty value').stdout.strip do
    it { should cmp 'Administrator' }
  end
end
