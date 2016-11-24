# This script was automatically generated from the 694-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37984);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "694-1");
script_summary(english:"libvirt vulnerability");
script_name(english:"USN694-1 : libvirt vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libvirt-bin 
- libvirt-dev 
- libvirt-doc 
- libvirt0 
- libvirt0-dbg 
- python-libvirt 
');
script_set_attribute(attribute:'description', value: 'It was discovered that libvirt did not mark certain operations as read-only. A
local attacker may be able to perform privileged actions such as migrating
virtual machines, adjusting autostart flags, or accessing privileged data in
the virtual machine memory and disks.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libvirt-bin-0.4.4-3ubuntu3.1 (Ubuntu 8.10)
- libvirt-dev-0.4.4-3ubuntu3.1 (Ubuntu 8.10)
- libvirt-doc-0.4.4-3ubuntu3.1 (Ubuntu 8.10)
- libvirt0-0.4.4-3ubuntu3.1 (Ubuntu 8.10)
- libvirt0-dbg-0.4.4-3ubuntu3.1 (Ubuntu 8.10)
- python-libvirt-0.4.4-3ubuntu3.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-5086");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libvirt-bin", pkgver: "0.4.4-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvirt-bin-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libvirt-bin-0.4.4-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libvirt-dev", pkgver: "0.4.4-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvirt-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libvirt-dev-0.4.4-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libvirt-doc", pkgver: "0.4.4-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvirt-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libvirt-doc-0.4.4-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libvirt0", pkgver: "0.4.4-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvirt0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libvirt0-0.4.4-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libvirt0-dbg", pkgver: "0.4.4-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvirt0-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libvirt0-dbg-0.4.4-3ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "python-libvirt", pkgver: "0.4.4-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-libvirt-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-libvirt-0.4.4-3ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
