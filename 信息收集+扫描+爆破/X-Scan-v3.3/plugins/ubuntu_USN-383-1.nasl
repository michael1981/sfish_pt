# This script was automatically generated from the 383-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27966);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "383-1");
script_summary(english:"libpng vulnerability");
script_name(english:"USN383-1 : libpng vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpng10-0 
- libpng10-dev 
- libpng12-0 
- libpng12-dev 
- libpng2 
- libpng2-dev 
- libpng3 
');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy discovered that libpng did not correctly calculate the 
size of sPLT structures when reading an image.  By tricking a user or an 
automated system into processing a specially crafted PNG file, an 
attacker could exploit this weakness to crash the application using the 
library.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpng10-0-1.0.18-1ubuntu3.1 (Ubuntu 5.10)
- libpng10-dev-1.0.18-1ubuntu3.1 (Ubuntu 5.10)
- libpng12-0-1.2.8rel-5.1ubuntu0.1 (Ubuntu 6.10)
- libpng12-dev-1.2.8rel-5.1ubuntu0.1 (Ubuntu 6.10)
- libpng2-1.0.18-1ubuntu3.1 (Ubuntu 5.10)
- libpng2-dev-1.0.18-1ubuntu3.1 (Ubuntu 5.10)
- libpng3-1.2.8rel-5.1ubuntu0.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-5793");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libpng10-0", pkgver: "1.0.18-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng10-0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpng10-0-1.0.18-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpng10-dev", pkgver: "1.0.18-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng10-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpng10-dev-1.0.18-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpng12-0", pkgver: "1.2.8rel-5.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng12-0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpng12-0-1.2.8rel-5.1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpng12-dev", pkgver: "1.2.8rel-5.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng12-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpng12-dev-1.2.8rel-5.1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpng2", pkgver: "1.0.18-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpng2-1.0.18-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpng2-dev", pkgver: "1.0.18-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng2-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpng2-dev-1.0.18-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpng3", pkgver: "1.2.8rel-5.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng3-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpng3-1.2.8rel-5.1ubuntu0.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
