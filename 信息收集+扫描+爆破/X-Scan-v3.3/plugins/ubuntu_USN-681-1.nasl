# This script was automatically generated from the 681-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36745);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "681-1");
script_summary(english:"imagemagick vulnerability");
script_name(english:"USN681-1 : imagemagick vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- imagemagick 
- libmagick++9-dev 
- libmagick++9c2a 
- libmagick9 
- libmagick9-dev 
- perlmagick 
');
script_set_attribute(attribute:'description', value: 'It was discovered that ImageMagick did not correctly handle certain
malformed XCF images. If a user were tricked into opening a specially
crafted image with an application that uses ImageMagick, an attacker
could cause a denial of service and possibly execute arbitrary code with
the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- imagemagick-6.2.4.5.dfsg1-2ubuntu1.1 (Ubuntu 7.10)
- libmagick++9-dev-6.2.4.5.dfsg1-2ubuntu1.1 (Ubuntu 7.10)
- libmagick++9c2a-6.2.4.5.dfsg1-2ubuntu1.1 (Ubuntu 7.10)
- libmagick9-6.2.4.5.dfsg1-2ubuntu1.1 (Ubuntu 7.10)
- libmagick9-dev-6.2.4.5.dfsg1-2ubuntu1.1 (Ubuntu 7.10)
- perlmagick-6.2.4.5.dfsg1-2ubuntu1.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-1096");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "imagemagick", pkgver: "6.2.4.5.dfsg1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package imagemagick-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to imagemagick-6.2.4.5.dfsg1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmagick++9-dev", pkgver: "6.2.4.5.dfsg1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmagick++9-dev-6.2.4.5.dfsg1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmagick++9c2a", pkgver: "6.2.4.5.dfsg1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++9c2a-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmagick++9c2a-6.2.4.5.dfsg1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmagick9", pkgver: "6.2.4.5.dfsg1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmagick9-6.2.4.5.dfsg1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmagick9-dev", pkgver: "6.2.4.5.dfsg1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick9-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmagick9-dev-6.2.4.5.dfsg1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "perlmagick", pkgver: "6.2.4.5.dfsg1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perlmagick-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to perlmagick-6.2.4.5.dfsg1-2ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
