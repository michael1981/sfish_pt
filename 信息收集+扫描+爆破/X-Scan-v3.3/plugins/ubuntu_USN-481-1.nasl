# This script was automatically generated from the 481-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28082);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "481-1");
script_summary(english:"ImageMagick vulnerabilities");
script_name(english:"USN481-1 : ImageMagick vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- imagemagick 
- libmagick++9-dev 
- libmagick++9c2a 
- libmagick9 
- libmagick9-dev 
- perlmagick 
');
script_set_attribute(attribute:'description', value: 'Multiple vulnerabilities were found in ImageMagick\'s handling of DCM and
WXD image files.  By tricking a user into processing a specially crafted
image with an application that uses imagemagick, an attacker could
execute arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- imagemagick-6.2.4.5.dfsg1-0.14ubuntu0.1 (Ubuntu 7.04)
- libmagick++9-dev-6.2.4.5.dfsg1-0.14ubuntu0.1 (Ubuntu 7.04)
- libmagick++9c2a-6.2.4.5.dfsg1-0.14ubuntu0.1 (Ubuntu 7.04)
- libmagick9-6.2.4.5.dfsg1-0.14ubuntu0.1 (Ubuntu 7.04)
- libmagick9-dev-6.2.4.5.dfsg1-0.14ubuntu0.1 (Ubuntu 7.04)
- perlmagick-6.2.4.5.dfsg1-0.14ubuntu0.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-1667","CVE-2007-1797");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "imagemagick", pkgver: "6.2.4.5.dfsg1-0.14ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package imagemagick-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to imagemagick-6.2.4.5.dfsg1-0.14ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libmagick++9-dev", pkgver: "6.2.4.5.dfsg1-0.14ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libmagick++9-dev-6.2.4.5.dfsg1-0.14ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libmagick++9c2a", pkgver: "6.2.4.5.dfsg1-0.14ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9c2a-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libmagick++9c2a-6.2.4.5.dfsg1-0.14ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libmagick9", pkgver: "6.2.4.5.dfsg1-0.14ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libmagick9-6.2.4.5.dfsg1-0.14ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libmagick9-dev", pkgver: "6.2.4.5.dfsg1-0.14ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libmagick9-dev-6.2.4.5.dfsg1-0.14ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "perlmagick", pkgver: "6.2.4.5.dfsg1-0.14ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perlmagick-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to perlmagick-6.2.4.5.dfsg1-0.14ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
