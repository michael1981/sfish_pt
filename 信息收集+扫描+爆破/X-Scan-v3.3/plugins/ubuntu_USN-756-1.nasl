# This script was automatically generated from the 756-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37389);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "756-1");
script_summary(english:"clamav vulnerability");
script_name(english:"USN756-1 : clamav vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- clamav 
- clamav-base 
- clamav-daemon 
- clamav-dbg 
- clamav-docs 
- clamav-freshclam 
- clamav-milter 
- clamav-testfiles 
- libclamav-dev 
- libclamav5 
');
script_set_attribute(attribute:'description', value: 'It was discovered that ClamAV did not properly verify buffers when
processing Upack files. A remote attacker could send a crafted file and
cause a denial of service via application crash.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- clamav-0.94.dfsg.2-1ubuntu0.3 (Ubuntu 8.10)
- clamav-base-0.94.dfsg.2-1ubuntu0.3 (Ubuntu 8.10)
- clamav-daemon-0.94.dfsg.2-1ubuntu0.3 (Ubuntu 8.10)
- clamav-dbg-0.94.dfsg.2-1ubuntu0.3 (Ubuntu 8.10)
- clamav-docs-0.94.dfsg.2-1ubuntu0.3 (Ubuntu 8.10)
- clamav-freshclam-0.94.dfsg.2-1ubuntu0.3 (Ubuntu 8.10)
- clamav-milter-0.94.dfsg.2-1ubuntu0.3 (Ubuntu 8.10)
- clamav-testfiles-0.94.dfsg.2-1ubuntu0.3 (Ubuntu 8.10)
- libclamav-dev-0.94.dfsg.2-1ubuntu0.3 (Ubuntu 8.10)
- libclamav5-0.94.dfsg.2-1ub
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "clamav", pkgver: "0.94.dfsg.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to clamav-0.94.dfsg.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "clamav-base", pkgver: "0.94.dfsg.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-base-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to clamav-base-0.94.dfsg.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "clamav-daemon", pkgver: "0.94.dfsg.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-daemon-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to clamav-daemon-0.94.dfsg.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "clamav-dbg", pkgver: "0.94.dfsg.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to clamav-dbg-0.94.dfsg.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "clamav-docs", pkgver: "0.94.dfsg.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-docs-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to clamav-docs-0.94.dfsg.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "clamav-freshclam", pkgver: "0.94.dfsg.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-freshclam-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to clamav-freshclam-0.94.dfsg.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "clamav-milter", pkgver: "0.94.dfsg.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-milter-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to clamav-milter-0.94.dfsg.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "clamav-testfiles", pkgver: "0.94.dfsg.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-testfiles-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to clamav-testfiles-0.94.dfsg.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libclamav-dev", pkgver: "0.94.dfsg.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libclamav-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libclamav-dev-0.94.dfsg.2-1ubuntu0.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libclamav5", pkgver: "0.94.dfsg.2-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libclamav5-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libclamav5-0.94.dfsg.2-1ubuntu0.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
