control 'V-76765' do
  title "All accounts installed with the IIS 8.5 web server software and tools
must have passwords assigned and default passwords changed."
  desc  "During installation of the web server software, accounts are created
for the web server to operate properly. The accounts installed can have either
no password installed or a default password, which will be known and documented
by the vendor and the user community.

    The first things an attacker will try when presented with a logon screen
are the default user identifiers with default passwords. Installed applications
may also install accounts with no password, making the logon even easier. Once
the web server is installed, the passwords for any created accounts should be
changed and documented. The new passwords must meet the requirements for all
passwords, i.e., upper/lower characters, numbers, special characters, time
until change, reuse policy, etc.

    Service accounts or system accounts that have no logon capability do not
need to have passwords set or changed.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000516-WSR-000079'
  tag "gid": 'V-76765'
  tag "rid": 'SV-91461r1_rule'
  tag "stig_id": 'IISW-SV-000156'
  tag "fix_id": 'F-83461r1_fix'
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
  tag "check": "Access the IIS 8.5 web server.

Access Apps menu. Under Administrative Tools, select Computer Management.

In left pane, expand \"Local Users and Groups\" and click on \"Users\".

Review the local users listed in the middle pane.

If any local accounts are present and are used by IIS 8.5 verify with System
Administrator that default passwords have been changed.

If passwords have not been changed from the default, this is a finding."
  tag "fix": "Access the IIS 8.5 web server.

Access Apps menu. Under Administrative Tools, select Computer Management.

In left pane, expand \"Local Users and Groups\" and click on \"Users\".

Change passwords for any local accounts are present and are used by IIS 8.5
verify with System Administrator that default passwords have been changed.

Develop an internal process for changing passwords on a regular basis."
end
