# This script was automatically generated from the 780-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39311);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "780-1");
script_summary(english:"cups, cupsys vulnerability");
script_name(english:"USN780-1 : cups, cupsys vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- cups 
- cups-bsd 
- cups-client 
- cups-common 
- cups-dbg 
- cupsys 
- cupsys-bsd 
- cupsys-client 
- cupsys-common 
- cupsys-dbg 
- libcups2 
- libcups2-dev 
- libcupsimage2 
- libcupsimage2-dev 
- libcupsys2 
- libcupsys2-dev 
- libcupsys2-gnutls10 
');
script_set_attribute(attribute:'description', value: 'Anibal Sacco discovered that CUPS did not properly handle certain network
operations. A remote attacker could exploit this flaw and cause the CUPS
server to crash, resulting in a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- cups-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- cups-bsd-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- cups-client-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- cups-common-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- cups-dbg-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- cupsys-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- cupsys-bsd-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- cupsys-client-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- cupsys-common-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- cupsys-dbg-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- libcups2-1.3.9-17ubuntu3.1 (Ubuntu 9.04)
- libcups2
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2009-0949");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "cups", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cups-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cups-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cups-bsd", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cups-bsd-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cups-bsd-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cups-client", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cups-client-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cups-client-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cups-common", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cups-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cups-common-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cups-dbg", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cups-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cups-dbg-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cupsys", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cupsys-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cupsys-bsd", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-bsd-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cupsys-bsd-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cupsys-client", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-client-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cupsys-client-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cupsys-common", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cupsys-common-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "cupsys-dbg", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to cupsys-dbg-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libcups2", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcups2-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libcups2-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libcups2-dev", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcups2-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libcups2-dev-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libcupsimage2", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsimage2-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libcupsimage2-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libcupsimage2-dev", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsimage2-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libcupsimage2-dev-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libcupsys2", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsys2-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libcupsys2-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libcupsys2-dev", pkgver: "1.3.9-17ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsys2-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libcupsys2-dev-1.3.9-17ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libcupsys2-gnutls10", pkgver: "1.2.2-0ubuntu0.6.06.14");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsys2-gnutls10-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libcupsys2-gnutls10-1.2.2-0ubuntu0.6.06.14
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
