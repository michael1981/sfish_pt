# This script was automatically generated from the 372-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27953);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "372-1");
script_summary(english:"imagemagick vulnerability");
script_name(english:"USN372-1 : imagemagick vulnerability");
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
script_set_attribute(attribute:'description', value: 'M. Joonas Pihlaja discovered that ImageMagick did not sufficiently
verify the validity of PALM and DCM images. When processing a
specially crafted image with an application that uses imagemagick,
this could be exploited to execute arbitrary code with the
application\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- imagemagick-6.2.4.5.dfsg1-0.10ubuntu0.1 (Ubuntu 6.10)
- libmagick++6-6.0.6.2-2.1ubuntu1.5 (Ubuntu 5.04)
- libmagick++6-dev-6.2.3.4-1ubuntu1.4 (Ubuntu 5.10)
- libmagick++6c2-6.2.3.4-1ubuntu1.4 (Ubuntu 5.10)
- libmagick++9-dev-6.2.4.5.dfsg1-0.10ubuntu0.1 (Ubuntu 6.10)
- libmagick++9c2a-6.2.4.5.dfsg1-0.10ubuntu0.1 (Ubuntu 6.10)
- libmagick6-6.2.3.4-1ubuntu1.4 (Ubuntu 5.10)
- libmagick6-dev-6.2.3.4-1ubuntu1.4 (Ubuntu 5.10)
- libmagick9-6.2.4.5.dfsg1-0.10ubuntu0.1 (Ubuntu 6.10)
- libmagick9-dev-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-5456");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "imagemagick", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package imagemagick-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to imagemagick-6.2.4.5.dfsg1-0.10ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libmagick++6", pkgver: "6.0.6.2-2.1ubuntu1.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libmagick++6-6.0.6.2-2.1ubuntu1.5
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick++6-dev", pkgver: "6.2.3.4-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick++6-dev-6.2.3.4-1ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick++6c2", pkgver: "6.2.3.4-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick++6c2-6.2.3.4-1ubuntu1.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libmagick++9-dev", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmagick++9-dev-6.2.4.5.dfsg1-0.10ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libmagick++9c2a", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9c2a-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmagick++9c2a-6.2.4.5.dfsg1-0.10ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick6", pkgver: "6.2.3.4-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick6-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick6-6.2.3.4-1ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmagick6-dev", pkgver: "6.2.3.4-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick6-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmagick6-dev-6.2.3.4-1ubuntu1.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libmagick9", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmagick9-6.2.4.5.dfsg1-0.10ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libmagick9-dev", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmagick9-dev-6.2.4.5.dfsg1-0.10ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "perlmagick", pkgver: "6.2.4.5.dfsg1-0.10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perlmagick-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to perlmagick-6.2.4.5.dfsg1-0.10ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
