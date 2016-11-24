# This script was automatically generated from the 639-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(34080);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "639-1");
script_summary(english:"tiff vulnerability");
script_name(english:"USN639-1 : tiff vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libtiff-opengl 
- libtiff-tools 
- libtiff4 
- libtiff4-dev 
- libtiffxx0c2 
');
script_set_attribute(attribute:'description', value: 'Drew Yao discovered that the TIFF library did not correctly validate LZW
compressed TIFF images.  If a user or automated system were tricked into
processing a malicious image, a remote attacker could execute arbitrary
code or cause an application linked against libtiff to crash, leading
to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libtiff-opengl-3.8.2-7ubuntu3.1 (Ubuntu 8.04)
- libtiff-tools-3.8.2-7ubuntu3.1 (Ubuntu 8.04)
- libtiff4-3.8.2-7ubuntu3.1 (Ubuntu 8.04)
- libtiff4-dev-3.8.2-7ubuntu3.1 (Ubuntu 8.04)
- libtiffxx0c2-3.8.2-7ubuntu3.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-2327");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "libtiff-opengl", pkgver: "3.8.2-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff-opengl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libtiff-opengl-3.8.2-7ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libtiff-tools", pkgver: "3.8.2-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff-tools-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libtiff-tools-3.8.2-7ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libtiff4", pkgver: "3.8.2-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff4-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libtiff4-3.8.2-7ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libtiff4-dev", pkgver: "3.8.2-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff4-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libtiff4-dev-3.8.2-7ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libtiffxx0c2", pkgver: "3.8.2-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiffxx0c2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libtiffxx0c2-3.8.2-7ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
