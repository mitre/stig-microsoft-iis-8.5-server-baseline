control 'V-76767' do
  title 'The File System Object component must be disabled on the IIS 8.5 web
server.'
  desc  'Some Component Object Model (COM) components are not required for most
applications and should be removed if possible. Most notably, consider
disabling the File System Object component; however, this will also remove the
Dictionary object. Be aware some programs may require this component (e.g.,
Commerce Server), so it is highly recommended this be tested completely before
implementing on the production web server.'
  # FIXEME ensure this is correct logic
  if attribute('file_system_object_component')
    impact 0.7
  else
    impact 0.0
  end
  tag "gtitle": 'SRG-APP-000516-WSR-000174'
  tag "gid": 'V-76767'
  tag "rid": 'SV-91463r1_rule'
  tag "stig_id": 'IISW-SV-000157'
  tag "fix_id": 'F-83463r1_fix'
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
  tag "check": 'Locate the HKEY_CLASSES_ROOT\\CLSID\\{0D43FE01-F093-11CF-8940-00A0C9054228} registry key.

  If the key exist, the File System Object component is enabled.

  If the File System Object component is enabled and is not required for
  operations, this is a finding.


  # FIXME this means there should be an impact 0 in this control.
  # so given the below - is it impact 0 when file_system_object_component is
  # true or when it is false?

  Note: If the File System Object component is required for operations and has
  supporting documentation signed by the ISSO, this is not a finding.'

  tag "fix": 'Run the following command, with administrator privileges, to
unregister the File System Object: regsvr32 scrrun.dll /u.'

  # is the below registry key a universal standard?
  # this should really be using a subject and more descriptive describe statment.
  # and a turnary operation based of the boolan attribute
  # someting like:

  # is this the non impact 0 case?
  # using a ruby turnary statement to ensure we communicate clearly what is being tested and
  # what is expected

  describe "The File System Object Component #{attribute('file_system_object_component') ? 'is' : 'is not'} required for operations" do
    subject { registry_key('HKEY_CLASSES_ROOT\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}') }
    if attribute('file_system_object_component')
      it { should exist }
    else
      it { should_not exist }
    end
  end

  describe 'The File System Object Compent is required and has supported docuemtaion from the ISSO' do
    only_if { attribute('file_system_object_component') }
    # if this triggers this is what would be testing in the impact 0 case
    subject { registry_key('HKEY_CLASSES_ROOT\CLSID\{0D43FE01-F093-11CF-8940-00A0C9054228}') }
    it { should exist }
    subject { attribute('file_system_object_component') }
    it { should be true }
  end
end
