control 'V-76763' do
  title "The IIS 8.5 web server must install security-relevant software updates
within the configured time period directed by an authoritative source (e.g.,
IAVM, CTOs, DTMs, and STIGs)."
  desc  "Several vulnerabilities are associated with older versions of web
server software. As hot fixes and patches are issued, these solutions are
included in the next version of the server software. Maintaining the web server
at a current version makes the efforts of a malicious user more difficult."
  impact 0.7
  tag "gtitle": 'SRG-APP-000456-WSR-000187'
  tag "gid": 'V-76763'
  tag "rid": 'SV-91459r2_rule'
  tag "stig_id": 'IISW-SV-000155'
  tag "fix_id": 'F-83459r1_fix'
  tag "cci": ['CCI-002605']
  tag "nist": ['SI-2 c', 'Rev_4']
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
  tag "check": "Determine the most recent patch level of the IIS 8.5 software,
as posted on the Microsoft website.

Open the IIS 8.5 Manager.

Click \"Help\", and select \"About Internet Information Services\".

If the version is more than one version behind the most recent patch level,
this is a finding.
"
  tag "fix": "Install the current version of the web server software and
maintain appropriate service packs and patches."
end
