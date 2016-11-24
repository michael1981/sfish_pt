# This script was automatically generated from the 315-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27891);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "315-1");
script_summary(english:"libmms, xine-lib vulnerabilities");
script_name(english:"USN315-1 : libmms, xine-lib vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmms-dev 
- libmms0 
- libxine-dev 
- libxine-main1 
- libxine1 
- libxine1c2 
');
script_set_attribute(attribute:'description', value: 'Matthias Hopf discovered several buffer overflows in libmms. By
tricking a user into opening a specially crafted remote multimedia
stream with an application using libmms, a remote attacker could
exploit this to execute arbitrary code with the user\'s privileges.

The Xine library contains an embedded copy of libmms, and thus needs
the same security update.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmms-dev-0.1-0ubuntu1.2 (Ubuntu 5.10)
- libmms0-0.1-0ubuntu1.2 (Ubuntu 5.10)
- libxine-dev-1.1.1+ubuntu2-7.2 (Ubuntu 6.06)
- libxine-main1-1.1.1+ubuntu2-7.2 (Ubuntu 6.06)
- libxine1-1.0-1ubuntu3.8 (Ubuntu 5.04)
- libxine1c2-1.0.1-1ubuntu10.4 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libmms-dev", pkgver: "0.1-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmms-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmms-dev-0.1-0ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmms0", pkgver: "0.1-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmms0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmms0-0.1-0ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libxine-dev", pkgver: "1.1.1+ubuntu2-7.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libxine-dev-1.1.1+ubuntu2-7.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libxine-main1", pkgver: "1.1.1+ubuntu2-7.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-main1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libxine-main1-1.1.1+ubuntu2-7.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libxine1", pkgver: "1.0-1ubuntu3.8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libxine1-1.0-1ubuntu3.8
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libxine1c2", pkgver: "1.0.1-1ubuntu10.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libxine1c2-1.0.1-1ubuntu10.4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
