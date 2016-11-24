# This script was automatically generated from the 142-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20535);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "142-1");
script_summary(english:"sudo vulnerability");
script_name(english:"USN142-1 : sudo vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "sudo" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Charles Morris discovered a race condition in sudo which could lead to
privilege escalation. If /etc/sudoers allowed a user the execution of
selected programs, and this was followed by another line containing
the pseudo-command "ALL", that user could execute arbitrary commands
with sudo by creating symbolic links at a certain time.

Please note that this does not affect a standard Ubuntu installation.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- sudo-1.6.8p5-1ubuntu2.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-1993");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "sudo", pkgver: "1.6.8p5-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sudo-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to sudo-1.6.8p5-1ubuntu2.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
