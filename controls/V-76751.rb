control 'V-76751' do
  title "The IIS 8.5 web server must not be running on a system providing any
other role."
  desc  "Web servers provide numerous processes, features, and functionalities
that utilize TCP/IP ports. Some of these processes may be deemed unnecessary or
too unsecure to run on a production system.

    The web server must provide the capability to disable or deactivate
network-related services that are deemed to be non-essential to the server
mission, are too unsecure, or are prohibited by the PPSM CAL and vulnerability
assessments.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000383-WSR-000175'
  tag "gid": 'V-76751'
  tag "rid": 'SV-91447r1_rule'
  tag "stig_id": 'IISW-SV-000148'
  tag "fix_id": 'F-83447r1_fix'
  tag "cci": ['CCI-001762']
  tag "nist": ['CM-7 (1) (b)', 'Rev_4']
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
  tag "check": "Review programs installed on the OS.

Open Control Panel.

Open Programs and Features.

The following programs may be installed without any additional documentation:

Administration Pack for IIS
IIS Search Engine Optimization Toolkit
Microsoft .NET Framework version 3.5 SP1 or greater
Microsoft Web Platform Installer version 3.x or greater
Virtual Machine Additions

Review the installed programs, if any programs are installed other than those
listed above, this is a finding.

Note: If additional software is needed and has supporting documentation signed
by the ISSO, this is not a finding."
  tag "fix": "Remove all unapproved programs and roles from the production web
server."
end
