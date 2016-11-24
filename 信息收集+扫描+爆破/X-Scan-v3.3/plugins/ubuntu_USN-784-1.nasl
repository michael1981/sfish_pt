# This script was automatically generated from the 784-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39337);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "784-1");
script_summary(english:"imagemagick vulnerability");
script_name(english:"USN784-1 : imagemagick vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- imagemagick 
- imagemagick-dbg 
- imagemagick-doc 
- libmagick++-dev 
- libmagick++1 
- libmagick++10 
- libmagick++9-dev 
- libmagick++9c2a 
- libmagick10 
- libmagick9 
- libmagick9-dev 
- libmagickcore-dev 
- libmagickcore1 
- libmagickwand-dev 
- libmagickwand1 
- perlmagick 
');
script_set_attribute(attribute:'description', value: 'It was discovered that ImageMagick did not properly verify the dimensions
of TIFF files. If a user or automated system were tricked into opening a
crafted TIFF file, an attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- imagemagick-6.4.5.4.dfsg1-1ubuntu3.1 (Ubuntu 9.04)
- imagemagick-dbg-6.4.5.4.dfsg1-1ubuntu3.1 (Ubuntu 9.04)
- imagemagick-doc-6.4.5.4.dfsg1-1ubuntu3.1 (Ubuntu 9.04)
- libmagick++-dev-6.4.5.4.dfsg1-1ubuntu3.1 (Ubuntu 9.04)
- libmagick++1-6.4.5.4.dfsg1-1ubuntu3.1 (Ubuntu 9.04)
- libmagick++10-6.3.7.9.dfsg1-2ubuntu3.1 (Ubuntu 8.10)
- libmagick++9-dev-6.3.7.9.dfsg1-2ubuntu3.1 (Ubuntu 8.10)
- libmagick++9c2a-6.2.4.5-0.6ubuntu0.9 (Ubuntu 6.06)
- libmagick10-6.3.7.9.dfsg1-2ubuntu3.1 (Ubuntu 8.10)

[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1882");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "imagemagick", pkgver: "6.4.5.4.dfsg1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package imagemagick-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to imagemagick-6.4.5.4.dfsg1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "imagemagick-dbg", pkgver: "6.4.5.4.dfsg1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package imagemagick-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to imagemagick-dbg-6.4.5.4.dfsg1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "imagemagick-doc", pkgver: "6.4.5.4.dfsg1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package imagemagick-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to imagemagick-doc-6.4.5.4.dfsg1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmagick++-dev", pkgver: "6.4.5.4.dfsg1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmagick++-dev-6.4.5.4.dfsg1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmagick++1", pkgver: "6.4.5.4.dfsg1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++1-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmagick++1-6.4.5.4.dfsg1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libmagick++10", pkgver: "6.3.7.9.dfsg1-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++10-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libmagick++10-6.3.7.9.dfsg1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libmagick++9-dev", pkgver: "6.3.7.9.dfsg1-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libmagick++9-dev-6.3.7.9.dfsg1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmagick++9c2a", pkgver: "6.2.4.5-0.6ubuntu0.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9c2a-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmagick++9c2a-6.2.4.5-0.6ubuntu0.9
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libmagick10", pkgver: "6.3.7.9.dfsg1-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick10-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libmagick10-6.3.7.9.dfsg1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmagick9", pkgver: "6.2.4.5-0.6ubuntu0.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmagick9-6.2.4.5-0.6ubuntu0.9
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libmagick9-dev", pkgver: "6.3.7.9.dfsg1-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libmagick9-dev-6.3.7.9.dfsg1-2ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmagickcore-dev", pkgver: "6.4.5.4.dfsg1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagickcore-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmagickcore-dev-6.4.5.4.dfsg1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmagickcore1", pkgver: "6.4.5.4.dfsg1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagickcore1-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmagickcore1-6.4.5.4.dfsg1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmagickwand-dev", pkgver: "6.4.5.4.dfsg1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagickwand-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmagickwand-dev-6.4.5.4.dfsg1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmagickwand1", pkgver: "6.4.5.4.dfsg1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagickwand1-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmagickwand1-6.4.5.4.dfsg1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "perlmagick", pkgver: "6.4.5.4.dfsg1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perlmagick-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to perlmagick-6.4.5.4.dfsg1-1ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
