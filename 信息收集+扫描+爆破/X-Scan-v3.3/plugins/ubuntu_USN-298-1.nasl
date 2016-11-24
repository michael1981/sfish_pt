# This script was automatically generated from the 298-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27873);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "298-1");
script_summary(english:"libgd2 vulnerability");
script_name(english:"USN298-1 : libgd2 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libgd-tools 
- libgd2 
- libgd2-dev 
- libgd2-noxpm 
- libgd2-noxpm-dev 
- libgd2-xpm 
- libgd2-xpm-dev 
');
script_set_attribute(attribute:'description', value: 'Xavier Roche discovered that libgd\'s function for reading GIF image
data did not sufficiently verify its validity. Specially crafted GIF
images could cause an infinite loop which used up all available CPU
resources. Since libgd is often used in PHP and Perl web applications,
this could lead to a remote Denial of Service vulnerability.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libgd-tools-2.0.33-2ubuntu5.1 (Ubuntu 6.06)
- libgd2-2.0.33-2ubuntu5.1 (Ubuntu 6.06)
- libgd2-dev-2.0.33-2ubuntu5.1 (Ubuntu 6.06)
- libgd2-noxpm-2.0.33-2ubuntu5.1 (Ubuntu 6.06)
- libgd2-noxpm-dev-2.0.33-2ubuntu5.1 (Ubuntu 6.06)
- libgd2-xpm-2.0.33-2ubuntu5.1 (Ubuntu 6.06)
- libgd2-xpm-dev-2.0.33-2ubuntu5.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2906");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libgd-tools", pkgver: "2.0.33-2ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd-tools-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgd-tools-2.0.33-2ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgd2", pkgver: "2.0.33-2ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgd2-2.0.33-2ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgd2-dev", pkgver: "2.0.33-2ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgd2-dev-2.0.33-2ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgd2-noxpm", pkgver: "2.0.33-2ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-noxpm-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgd2-noxpm-2.0.33-2ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgd2-noxpm-dev", pkgver: "2.0.33-2ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-noxpm-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgd2-noxpm-dev-2.0.33-2ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgd2-xpm", pkgver: "2.0.33-2ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-xpm-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgd2-xpm-2.0.33-2ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgd2-xpm-dev", pkgver: "2.0.33-2ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgd2-xpm-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgd2-xpm-dev-2.0.33-2ubuntu5.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
