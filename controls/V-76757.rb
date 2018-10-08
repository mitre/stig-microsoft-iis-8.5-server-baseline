control 'V-76757' do
  title 'IIS 8.5 web server session IDs must be sent to the client using TLS.'
  desc  "The HTTP protocol is a stateless protocol. To maintain a session, a
session identifier is used. The session identifier is a piece of data that is
used to identify a session and a user. If the session identifier is compromised
by an attacker, the session can be hijacked. By encrypting the session
identifier, the identifier becomes more difficult for an attacker to hijack,
decrypt, and use before the session has expired."
  impact 0.7
  tag "gtitle": 'SRG-APP-000439-WSR-000152'
  tag "gid": 'V-76757'
  tag "rid": 'SV-91453r1_rule'
  tag "stig_id": 'IISW-SV-000152'
  tag "fix_id": 'F-83453r1_fix'
  tag "cci": ['CCI-002418']
  tag "nist": ['SC-8', 'Rev_4']
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

Under \"Management\" section, double-click the \"Configuration Editor\" icon.

From the \"Section:\" drop-down list, select “system.webServer/asp\".

Expand the \"session\" section.

Verify the \"keepSessionIdSecure\" is set to \"True\".

If the \"keepSessionIdSecure\" is not set to \"True\", this is a finding."
  tag "fix": "Open the IIS 8.5 Manager.

Click the IIS 8.5 web server name.

Under \"Management\" section, double-click the \"Configuration Editor\" icon.

From the \"Section:\" drop-down list, select 'system.webServer/asp\".

Expand the \"session\" section.

Select \"True\" for the \"keepSessionIdSecure\" setting.

Select \"Apply\" from the \"Actions\" pane."

  describe command('Get-WebConfigurationProperty -pspath "MACHINE/WEBROOT/APPHOST" -filter "system.webServer/asp/session" -Name keepSessionIdSecure | select -expandProperty value').stdout.strip do
    it { should cmp 'true' }
  end
end
