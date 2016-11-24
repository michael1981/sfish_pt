# This script was automatically generated from the 854-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42407);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "854-1");
script_summary(english:"libgd2 vulnerabilities");
script_name(english:"USN854-1 : libgd2 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libgd-tools 
- libgd2 
- libgd2-dev 
- libgd2-noxpm 
- libgd2-noxpm-dev 
- libgd2-xpm 
- libgd2-xpm-dev 
');
script_set_attribute(attribute:'description', value: 'Tomas Hoger discovered that the GD library did not properly handle the
number of colors in certain malformed GD images. If a user or automated
system were tricked into processing a specially crafted GD image, an
attacker could cause a denial of service or possibly execute arbitrary
code. (CVE-2009-3546)

It was discovered that the GD library did not properly handle incorrect
color indexes. An attacker could send specially crafted input to
applications linked against libgd2 and cause a denial of service or
possibly execute arbitrary code. This issue only affected Ubuntu 6.06 LTS.
(CVE-2009-3293)

It was discovered that the GD library did not properly handle certain
malformed GIF images. If a user or automated system were tricked into
processing a specially crafted GIF image, an attacker could cause a denial
of service. This issue only affected Ubuntu 6.06 LTS. (CVE-2007-3475,
CVE-2007-3476)

It was discovered that the GD library did not properly handle large angle
degree values. An attacker could send special
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libgd-tools-2.0.35.dfsg-3ubuntu2.1 (Ubuntu 8.04)
- libgd2-2.0.33-2ubuntu5.4 (Ubuntu 6.06)
- libgd2-dev-2.0.33-2ubuntu5.4 (Ubuntu 6.06)
- libgd2-noxpm-2.0.35.dfsg-3ubuntu2.1 (Ubuntu 8.04)
- libgd2-noxpm-dev-2.0.35.dfsg-3ubuntu2.1 (Ubuntu 8.04)
- libgd2-xpm-2.0.35.dfsg-3ubuntu2.1 (Ubuntu 8.04)
- libgd2-xpm-dev-2.0.35.dfsg-3ubuntu2.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-3475","CVE-2007-3476","CVE-2007-3477","CVE-2009-3293","CVE-2009-3546");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "libgd-tools", pkgver: "2.0.35.dfsg-3ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd-tools-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgd-tools-2.0.35.dfsg-3ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgd2", pkgver: "2.0.33-2ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgd2-2.0.33-2ubuntu5.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgd2-dev", pkgver: "2.0.33-2ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgd2-dev-2.0.33-2ubuntu5.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgd2-noxpm", pkgver: "2.0.35.dfsg-3ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-noxpm-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgd2-noxpm-2.0.35.dfsg-3ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgd2-noxpm-dev", pkgver: "2.0.35.dfsg-3ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-noxpm-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgd2-noxpm-dev-2.0.35.dfsg-3ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgd2-xpm", pkgver: "2.0.35.dfsg-3ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-xpm-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgd2-xpm-2.0.35.dfsg-3ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgd2-xpm-dev", pkgver: "2.0.35.dfsg-3ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-xpm-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgd2-xpm-dev-2.0.35.dfsg-3ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
