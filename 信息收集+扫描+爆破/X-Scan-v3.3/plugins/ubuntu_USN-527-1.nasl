# This script was automatically generated from the 527-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28132);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "527-1");
script_summary(english:"xen-3.0 vulnerability");
script_name(english:"USN527-1 : xen-3.0 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libxen3.0 
- libxen3.0-dev 
- python-xen3.0 
- xen-docs-3.0 
- xen-hypervisor-3.0-amd64 
- xen-hypervisor-3.0-i386 
- xen-hypervisor-3.0-i386-pae 
- xen-ioemu-3.0 
- xen-utils-3.0 
');
script_set_attribute(attribute:'description', value: 'Joris van Rantwijk discovered that the Xen host did not correctly validate
the contents of a Xen guests\'s grug.conf file.  Xen guest root users could
exploit this to run arbitrary commands on the host when the guest system
was rebooted.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxen3.0-3.0.3-0ubuntu10.1 (Ubuntu 7.04)
- libxen3.0-dev-3.0.3-0ubuntu10.1 (Ubuntu 7.04)
- python-xen3.0-3.0.3-0ubuntu10.1 (Ubuntu 7.04)
- xen-docs-3.0-3.0.3-0ubuntu10.1 (Ubuntu 7.04)
- xen-hypervisor-3.0-amd64-3.0.3-0ubuntu10.1 (Ubuntu 7.04)
- xen-hypervisor-3.0-i386-3.0.3-0ubuntu10.1 (Ubuntu 7.04)
- xen-hypervisor-3.0-i386-pae-3.0.3-0ubuntu10.1 (Ubuntu 7.04)
- xen-ioemu-3.0-3.0.3-0ubuntu10.1 (Ubuntu 7.04)
- xen-utils-3.0-3.0.3-0ubuntu10.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-4993");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libxen3.0", pkgver: "3.0.3-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxen3.0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libxen3.0-3.0.3-0ubuntu10.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libxen3.0-dev", pkgver: "3.0.3-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxen3.0-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libxen3.0-dev-3.0.3-0ubuntu10.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "python-xen3.0", pkgver: "3.0.3-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-xen3.0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to python-xen3.0-3.0.3-0ubuntu10.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xen-docs-3.0", pkgver: "3.0.3-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xen-docs-3.0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xen-docs-3.0-3.0.3-0ubuntu10.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xen-hypervisor-3.0-amd64", pkgver: "3.0.3-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xen-hypervisor-3.0-amd64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xen-hypervisor-3.0-amd64-3.0.3-0ubuntu10.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xen-hypervisor-3.0-i386", pkgver: "3.0.3-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xen-hypervisor-3.0-i386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xen-hypervisor-3.0-i386-3.0.3-0ubuntu10.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xen-hypervisor-3.0-i386-pae", pkgver: "3.0.3-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xen-hypervisor-3.0-i386-pae-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xen-hypervisor-3.0-i386-pae-3.0.3-0ubuntu10.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xen-ioemu-3.0", pkgver: "3.0.3-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xen-ioemu-3.0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xen-ioemu-3.0-3.0.3-0ubuntu10.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xen-utils-3.0", pkgver: "3.0.3-0ubuntu10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xen-utils-3.0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xen-utils-3.0-3.0.3-0ubuntu10.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
