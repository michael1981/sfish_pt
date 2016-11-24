# This script was automatically generated from the 407-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27995);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "407-1");
script_summary(english:"libgtop2 vulnerability");
script_name(english:"USN407-1 : libgtop2 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libgtop2-5 
- libgtop2-7 
- libgtop2-common 
- libgtop2-dev 
');
script_set_attribute(attribute:'description', value: 'Liu Qishuai discovered a buffer overflow in the /proc parsing routines
in libgtop. By creating and running a process in a specially crafted
long path and tricking an user into running gnome-system-monitor, an
attacker could exploit this to execute arbitrary code with the user\'s
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libgtop2-5-2.12.0-0ubuntu1.1 (Ubuntu 5.10)
- libgtop2-7-2.14.4-0ubuntu1.1 (Ubuntu 6.10)
- libgtop2-common-2.14.4-0ubuntu1.1 (Ubuntu 6.10)
- libgtop2-dev-2.14.4-0ubuntu1.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libgtop2-5", pkgver: "2.12.0-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtop2-5-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgtop2-5-2.12.0-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgtop2-7", pkgver: "2.14.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtop2-7-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgtop2-7-2.14.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgtop2-common", pkgver: "2.14.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtop2-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgtop2-common-2.14.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgtop2-dev", pkgver: "2.14.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtop2-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgtop2-dev-2.14.4-0ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
