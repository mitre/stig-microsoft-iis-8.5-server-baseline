control 'V-76759' do
  title "An IIS 8.5 web server must maintain the confidentiality of controlled
information during transmission through the use of an approved TLS version."
  desc  "Transport Layer Security (TLS) encryption is a required security
setting for a private web server. Encryption of private information is
essential to ensuring data confidentiality. If private information is not
encrypted, it can be intercepted and easily read by an unauthorized party. A
private web server must use a FIPS 140-2-approved TLS version, and all
non-FIPS-approved SSL versions must be disabled.

    FIPS 140-2-approved TLS versions include TLS V1.1 or greater. NIST SP
800-52 specifies the preferred configurations for government systems.
  "
  impact 0.7
  tag "gtitle": 'SRG-APP-000439-WSR-000156'
  tag "gid": 'V-76759'
  tag "rid": 'SV-91455r1_rule'
  tag "stig_id": 'IISW-SV-000153'
  tag "fix_id": 'F-83455r1_fix'
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
  tag "check": "Access the IIS 8.5 Web Server.

Access an administrator command prompt and type \"regedit <enter>\" to access
the server's registry.

Navigate to:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.1\\Server

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.2\\Server

Verify a REG_DWORD value of \"0\" for \"DisabledByDefault\"

Navigate to:
HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.0\\Server

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL
2.0\\Server

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL
3.0\\Server

Verify a REG_DWORD value of \"1\" for \"DisabledByDefault\"

If any of the respective registry paths are not existent or configured with the
wrong value, this is a finding."
  tag "fix": "Access the IIS 8.5 Web Server.

Access an administrator command prompt and type \"regedit <enter>\" to access
the server's registry.

Navigate to the following registry paths and configure the
\"DisabledByDefault\" REG_DWORD with the appropriate values:

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.1\\Server

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.2\\Server

With a REG_DWORD value of \"0\" for \"DisabledByDefault\"

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\TLS
1.0\\Server

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL
2.0\\Server

HKLM\\SYSTEM\\CurrentControlSet\\Control\\SecurityProviders\\SCHANNEL\\Protocols\\SSL
3.0\\Server

With a REG_DWORD value of \"1\" for \"DisabledByDefault\""

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.1\Client') do
    its('DisabledByDefault') { should be 0 }
  end

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.2\Client') do
    its('DisabledByDefault') { should be 0 }
  end

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\TLS 1.0\Client') do
    its('DisabledByDefault') { should be 1 }
  end

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 2.0\Client') do
    its('DisabledByDefault') { should be 1 }
  end

  describe registry_key('HKEY_LOCAL_MACHINE\SYSTEM\CurrentControlSet\Control\SecurityProviders\SCHANNEL\Protocols\SSL 3.0\Client') do
    its('DisabledByDefault') { should be 1 }
  end
end
