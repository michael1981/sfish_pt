# This script was automatically generated from the 391-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27976);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "391-1");
script_summary(english:"libgsf vulnerability");
script_name(english:"USN391-1 : libgsf vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libgsf-1 
- libgsf-1-113 
- libgsf-1-113-dbg 
- libgsf-1-114 
- libgsf-1-114-dbg 
- libgsf-1-common 
- libgsf-1-dbg 
- libgsf-1-dev 
- libgsf-bin 
- libgsf-gnome-1 
- libgsf-gnome-1-113 
- libgsf-gnome-1-113-dbg 
- libgsf-gnome-1-114 
- libgsf-gnome-1-114-dbg 
- libgsf-gnome-1-dbg 
- libgsf-gnome-1-dev 
');
script_set_attribute(attribute:'description', value: 'A heap overflow was discovered in the OLE processing code in libgsf.  If 
a user were tricked into opening a specially crafted OLE document, an 
attacker could execute arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libgsf-1-1.12.3-3ubuntu3.1 (Ubuntu 5.10)
- libgsf-1-113-1.13.99-0ubuntu2.1 (Ubuntu 6.06)
- libgsf-1-113-dbg-1.13.99-0ubuntu2.1 (Ubuntu 6.06)
- libgsf-1-114-1.14.1-2ubuntu1.1 (Ubuntu 6.10)
- libgsf-1-114-dbg-1.14.1-2ubuntu1.1 (Ubuntu 6.10)
- libgsf-1-common-1.14.1-2ubuntu1.1 (Ubuntu 6.10)
- libgsf-1-dbg-1.12.3-3ubuntu3.1 (Ubuntu 5.10)
- libgsf-1-dev-1.14.1-2ubuntu1.1 (Ubuntu 6.10)
- libgsf-bin-1.14.1-2ubuntu1.1 (Ubuntu 6.10)
- libgsf-gnome-1-1.12.3-3ubuntu3.1 (Ubuntu 5.10)
- libgsf-gnome-1-1
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4514");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libgsf-1", pkgver: "1.12.3-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgsf-1-1.12.3-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgsf-1-113", pkgver: "1.13.99-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-1-113-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgsf-1-113-1.13.99-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgsf-1-113-dbg", pkgver: "1.13.99-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-1-113-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgsf-1-113-dbg-1.13.99-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgsf-1-114", pkgver: "1.14.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-1-114-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgsf-1-114-1.14.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgsf-1-114-dbg", pkgver: "1.14.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-1-114-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgsf-1-114-dbg-1.14.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgsf-1-common", pkgver: "1.14.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-1-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgsf-1-common-1.14.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgsf-1-dbg", pkgver: "1.12.3-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-1-dbg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgsf-1-dbg-1.12.3-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgsf-1-dev", pkgver: "1.14.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-1-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgsf-1-dev-1.14.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgsf-bin", pkgver: "1.14.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-bin-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgsf-bin-1.14.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgsf-gnome-1", pkgver: "1.12.3-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-gnome-1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgsf-gnome-1-1.12.3-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgsf-gnome-1-113", pkgver: "1.13.99-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-gnome-1-113-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgsf-gnome-1-113-1.13.99-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgsf-gnome-1-113-dbg", pkgver: "1.13.99-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-gnome-1-113-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgsf-gnome-1-113-dbg-1.13.99-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgsf-gnome-1-114", pkgver: "1.14.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-gnome-1-114-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgsf-gnome-1-114-1.14.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgsf-gnome-1-114-dbg", pkgver: "1.14.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-gnome-1-114-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgsf-gnome-1-114-dbg-1.14.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgsf-gnome-1-dbg", pkgver: "1.12.3-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-gnome-1-dbg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgsf-gnome-1-dbg-1.12.3-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgsf-gnome-1-dev", pkgver: "1.14.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgsf-gnome-1-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgsf-gnome-1-dev-1.14.1-2ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
