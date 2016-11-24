# This script was automatically generated from the 235-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20780);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "235-2");
script_summary(english:"sudo vulnerability");
script_name(english:"USN235-2 : sudo vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "sudo" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-235-1 fixed a vulnerability in sudo\'s handling of environment
variables. Tavis Ormandy noticed that sudo did not filter out the
PYTHONINSPECT environment variable, so that users with the limited
privilege of calling a python script with sudo could still escalate
their privileges.

For reference, this is the original advisory:

  Charles Morris discovered a privilege escalation vulnerability in
  sudo.  On executing Perl scripts with sudo, various environment
  variables that affect Perl\'s library search path were not cleaned
  properly. If sudo is set up to grant limited sudo execution of Perl
  scripts to normal users, this could be exploited to run arbitrary
  commands as the target user.

  This security update also filters out environment variables that can
  be exploited similarly with Python, Ruby, and zsh scripts.

  Please note that this does not affect the default Ubuntu
  installation,
  or any setup that just grants full root privileges to certain users.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- sudo-1.6.8p9-2ubuntu2.3 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-4158");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "sudo", pkgver: "1.6.8p9-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sudo-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to sudo-1.6.8p9-2ubuntu2.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
