# This script was automatically generated from the 340-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27919);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "340-1");
script_summary(english:"imagemagick vulnerabilities");
script_name(english:"USN340-1 : imagemagick vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- imagemagick 
- libmagick++6 
- libmagick++6-dev 
- libmagick++6c2 
- libmagick++9-dev 
- libmagick++9c2a 
- libmagick6 
- libmagick6-dev 
- libmagick9 
- libmagick9-dev 
- perlmagick 
');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy discovered several buffer overflows in imagemagick\'s Sun
Raster and XCF (Gimp) image decoders. By tricking a user or automated
system into processing a specially crafted image, this could be
exploited to execute arbitrary code with the users\' privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- imagemagick-6.2.4.5-0.6ubuntu0.2 (Ubuntu 6.06)
- libmagick++6-6.0.6.2-2.1ubuntu1.4 (Ubuntu 5.04)
- libmagick++6-dev-6.2.3.4-1ubuntu1.3 (Ubuntu 5.10)
- libmagick++6c2-6.2.3.4-1ubuntu1.3 (Ubuntu 5.10)
- libmagick++9-dev-6.2.4.5-0.6ubuntu0.2 (Ubuntu 6.06)
- libmagick++9c2a-6.2.4.5-0.6ubuntu0.2 (Ubuntu 6.06)
- libmagick6-6.2.3.4-1ubuntu1.3 (Ubuntu 5.10)
- libmagick6-dev-6.2.3.4-1ubuntu1.3 (Ubuntu 5.10)
- libmagick9-6.2.4.5-0.6ubuntu0.2 (Ubuntu 6.06)
- libmagick9-dev-6.2.4.5-0.6ubuntu0.2 (Ubuntu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-3743","CVE-2006-3744");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "imagemagick", pkgver: "6.2.4.5-0.6ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package imagemagick-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to imagemagick-6.2.4.5-0.6ubuntu0.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libmagick++6", pkgver: "6.0.6.2-2.1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libmagick++6-6.0.6.2-2.1ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick++6-dev", pkgver: "6.2.3.4-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick++6-dev-6.2.3.4-1ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick++6c2", pkgver: "6.2.3.4-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick++6c2-6.2.3.4-1ubuntu1.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmagick++9-dev", pkgver: "6.2.4.5-0.6ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmagick++9-dev-6.2.4.5-0.6ubuntu0.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmagick++9c2a", pkgver: "6.2.4.5-0.6ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9c2a-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmagick++9c2a-6.2.4.5-0.6ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick6", pkgver: "6.2.3.4-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick6-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick6-6.2.3.4-1ubuntu1.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick6-dev", pkgver: "6.2.3.4-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick6-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick6-dev-6.2.3.4-1ubuntu1.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmagick9", pkgver: "6.2.4.5-0.6ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmagick9-6.2.4.5-0.6ubuntu0.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmagick9-dev", pkgver: "6.2.4.5-0.6ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmagick9-dev-6.2.4.5-0.6ubuntu0.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "perlmagick", pkgver: "6.2.4.5-0.6ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perlmagick-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to perlmagick-6.2.4.5-0.6ubuntu0.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
