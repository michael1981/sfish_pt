# This script was automatically generated from the 422-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28014);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "422-1");
script_summary(english:"ImageMagick vulnerabilities");
script_name(english:"USN422-1 : ImageMagick vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- imagemagick 
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
script_set_attribute(attribute:'description', value: 'Vladimir Nadvornik discovered that the fix for CVE-2006-5456, released 
in USN-372-1, did not correctly solve the original flaw in PALM image 
handling.  By tricking a user into processing a specially crafted image 
with an application that uses imagemagick, an attacker could execute 
arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- imagemagick-6.2.4.5.dfsg1-0.10ubuntu0.2 (Ubuntu 6.10)
- libmagick++6-dev-6.2.3.4-1ubuntu1.6 (Ubuntu 5.10)
- libmagick++6c2-6.2.3.4-1ubuntu1.6 (Ubuntu 5.10)
- libmagick++9-dev-6.2.4.5.dfsg1-0.10ubuntu0.2 (Ubuntu 6.10)
- libmagick++9c2a-6.2.4.5.dfsg1-0.10ubuntu0.2 (Ubuntu 6.10)
- libmagick6-6.2.3.4-1ubuntu1.6 (Ubuntu 5.10)
- libmagick6-dev-6.2.3.4-1ubuntu1.6 (Ubuntu 5.10)
- libmagick9-6.2.4.5.dfsg1-0.10ubuntu0.2 (Ubuntu 6.10)
- libmagick9-dev-6.2.4.5.dfsg1-0.10ubuntu0.2 (Ubuntu 6.10)
- perlma
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-5456","CVE-2007-0770");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "imagemagick", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package imagemagick-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to imagemagick-6.2.4.5.dfsg1-0.10ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick++6-dev", pkgver: "6.2.3.4-1ubuntu1.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick++6-dev-6.2.3.4-1ubuntu1.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick++6c2", pkgver: "6.2.3.4-1ubuntu1.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick++6c2-6.2.3.4-1ubuntu1.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libmagick++9-dev", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmagick++9-dev-6.2.4.5.dfsg1-0.10ubuntu0.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libmagick++9c2a", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9c2a-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmagick++9c2a-6.2.4.5.dfsg1-0.10ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick6", pkgver: "6.2.3.4-1ubuntu1.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick6-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick6-6.2.3.4-1ubuntu1.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick6-dev", pkgver: "6.2.3.4-1ubuntu1.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick6-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick6-dev-6.2.3.4-1ubuntu1.6
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libmagick9", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmagick9-6.2.4.5.dfsg1-0.10ubuntu0.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libmagick9-dev", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmagick9-dev-6.2.4.5.dfsg1-0.10ubuntu0.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "perlmagick", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perlmagick-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to perlmagick-6.2.4.5.dfsg1-0.10ubuntu0.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
