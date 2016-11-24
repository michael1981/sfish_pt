# This script was automatically generated from the 662-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37161);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "662-2");
script_summary(english:"linux-ubuntu-modules-2.6.22/24 vulnerability");
script_name(english:"USN662-2 : linux-ubuntu-modules-2.6.22/24 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-headers-lum-2.6.24-21-386 
- linux-headers-lum-2.6.24-21-generic 
- linux-headers-lum-2.6.24-21-openvz 
- linux-headers-lum-2.6.24-21-rt 
- linux-headers-lum-2.6.24-21-server 
- linux-headers-lum-2.6.24-21-virtual 
- linux-headers-lum-2.6.24-21-xen 
- linux-ubuntu-modules-2.6.22-15-386 
- linux-ubuntu-modules-2.6.22-15-cell 
- linux-ubuntu-modules-2.6.22-15-generic 
- linux-ubuntu-modules-2.6.22-15-powerpc 
- linux-ubuntu-modules-2.6.22-15-powerp
[...]');
script_set_attribute(attribute:'description', value: 'USN-662-1 fixed vulnerabilities in ndiswrapper in Ubuntu 8.10.
This update provides the corresponding updates for Ubuntu 8.04 and 7.10.

Original advisory details:

 Anders Kaseorg discovered that ndiswrapper did not correctly handle long
 ESSIDs.  For a system using ndiswrapper, a physically near-by attacker
 could generate specially crafted wireless network traffic and execute
 arbitrary code with root privileges. (CVE-2008-4395)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-headers-lum-2.6.24-21-386-2.6.24-21.33 (Ubuntu 8.04)
- linux-headers-lum-2.6.24-21-generic-2.6.24-21.33 (Ubuntu 8.04)
- linux-headers-lum-2.6.24-21-openvz-2.6.24-21.33 (Ubuntu 8.04)
- linux-headers-lum-2.6.24-21-rt-2.6.24-21.33 (Ubuntu 8.04)
- linux-headers-lum-2.6.24-21-server-2.6.24-21.33 (Ubuntu 8.04)
- linux-headers-lum-2.6.24-21-virtual-2.6.24-21.33 (Ubuntu 8.04)
- linux-headers-lum-2.6.24-21-xen-2.6.24-21.33 (Ubuntu 8.04)
- linux-ubuntu-modules-2.6.22-15-386-2.6.22-15.40 (Ubuntu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-4395");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-21-386", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-21-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-21-386-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-21-generic", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-21-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-21-generic-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-21-openvz", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-21-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-21-openvz-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-21-rt", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-21-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-21-rt-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-21-server", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-21-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-21-server-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-21-virtual", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-21-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-21-virtual-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-21-xen", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-21-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-21-xen-2.6.24-21.33
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-386", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-386-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-cell", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-cell-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-generic", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-generic-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-powerpc", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-powerpc-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-powerpc-smp", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-powerpc-smp-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-powerpc64-smp", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-powerpc64-smp-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-rt", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-rt-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-server", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-server-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-sparc64", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-sparc64-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-sparc64-smp", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-sparc64-smp-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-ume", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-ume-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-virtual", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-virtual-2.6.22-15.40
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-xen", pkgver: "2.6.22-15.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-xen-2.6.22-15.40
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-21-386", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-21-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-21-386-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-21-generic", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-21-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-21-generic-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-21-openvz", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-21-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-21-openvz-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-21-rt", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-21-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-21-rt-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-21-server", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-21-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-21-server-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-21-virtual", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-21-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-21-virtual-2.6.24-21.33
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-21-xen", pkgver: "2.6.24-21.33");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-21-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-21-xen-2.6.24-21.33
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
