# This script was automatically generated from the 769-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38685);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "769-1");
script_summary(english:"libwmf vulnerability");
script_name(english:"USN769-1 : libwmf vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libwmf-bin 
- libwmf-dev 
- libwmf-doc 
- libwmf0.2-7 
- libwmf0.2-7-gtk 
');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy discovered that libwmf incorrectly used memory after it had
been freed when using its embedded GD library. If a user or automated
system were tricked into opening a crafted WMF file, an attacker could
cause a denial of service or execute arbitrary code with privileges of the
user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libwmf-bin-0.2.8.4-6ubuntu1.1 (Ubuntu 9.04)
- libwmf-dev-0.2.8.4-6ubuntu1.1 (Ubuntu 9.04)
- libwmf-doc-0.2.8.4-6ubuntu1.1 (Ubuntu 9.04)
- libwmf0.2-7-0.2.8.4-6ubuntu1.1 (Ubuntu 9.04)
- libwmf0.2-7-gtk-0.2.8.4-6ubuntu1.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-1364");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libwmf-bin", pkgver: "0.2.8.4-6ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwmf-bin-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libwmf-bin-0.2.8.4-6ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libwmf-dev", pkgver: "0.2.8.4-6ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwmf-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libwmf-dev-0.2.8.4-6ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libwmf-doc", pkgver: "0.2.8.4-6ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwmf-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libwmf-doc-0.2.8.4-6ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libwmf0.2-7", pkgver: "0.2.8.4-6ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwmf0.2-7-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libwmf0.2-7-0.2.8.4-6ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libwmf0.2-7-gtk", pkgver: "0.2.8.4-6ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwmf0.2-7-gtk-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libwmf0.2-7-gtk-0.2.8.4-6ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
