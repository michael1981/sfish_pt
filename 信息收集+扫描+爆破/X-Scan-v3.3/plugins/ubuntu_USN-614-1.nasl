# This script was automatically generated from the 614-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33093);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "614-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN614-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avm-fritz-firmware-2.6.24-18 
- avm-fritz-kernel-source 
- fglrx-amdcccle 
- fglrx-control 
- fglrx-kernel-source 
- linux-backports-modules-2.6.24-18-386 
- linux-backports-modules-2.6.24-18-generic 
- linux-backports-modules-2.6.24-18-openvz 
- linux-backports-modules-2.6.24-18-rt 
- linux-backports-modules-2.6.24-18-server 
- linux-backports-modules-2.6.24-18-virtual 
- linux-backports-modules-2.6.24-18-xen 
- linux-doc-2.6.24 
- linux-headers-2.6.2
[...]');
script_set_attribute(attribute:'description', value: 'It was discovered that PowerPC kernels did not correctly handle reporting
certain system details.  By requesting a specific set of information,
a local attacker could cause a system crash resulting in a denial
of service. (CVE-2007-6694)

A race condition was discovered between dnotify fcntl() and close() in
the kernel.  If a local attacker performed malicious dnotify requests,
they could cause memory consumption leading to a denial of service,
or possibly send arbitrary signals to any process. (CVE-2008-1375)

On SMP systems, a race condition existed in fcntl().  Local attackers
could perform malicious locks, causing system crashes and leading to
a denial of service. (CVE-2008-1669)

The tehuti network driver did not correctly handle certain IO functions.
A local attacker could perform malicious requests to the driver,
potentially accessing kernel memory, leading to privilege escalation
or access to private system information. (CVE-2008-1675)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avm-fritz-firmware-2.6.24-18-3.11+2.6.24.13-18.41 (Ubuntu 8.04)
- avm-fritz-kernel-source-3.11+2.6.24.13-18.41 (Ubuntu 8.04)
- fglrx-amdcccle-2.6.24.13-18.41 (Ubuntu 8.04)
- fglrx-control-8-3+2.6.24.13-18.41 (Ubuntu 8.04)
- fglrx-kernel-source-8-3+2.6.24.13-18.41 (Ubuntu 8.04)
- linux-backports-modules-2.6.24-18-386-2.6.24-18.16 (Ubuntu 8.04)
- linux-backports-modules-2.6.24-18-generic-2.6.24-18.16 (Ubuntu 8.04)
- linux-backports-modules-2.6.24-18-openvz-2.6.24-18.16 (Ubuntu 8.04)
- linux-b
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2007-6694","CVE-2008-1375","CVE-2008-1669","CVE-2008-1675");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "avm-fritz-firmware-2.6.24-18", pkgver: "3.11+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.24-18-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to avm-fritz-firmware-2.6.24-18-3.11+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "avm-fritz-kernel-source", pkgver: "3.11+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-kernel-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to avm-fritz-kernel-source-3.11+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "fglrx-amdcccle", pkgver: "2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-amdcccle-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to fglrx-amdcccle-2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "fglrx-control", pkgver: "8-3+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-control-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to fglrx-control-8-3+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "fglrx-kernel-source", pkgver: "8-3+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-kernel-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to fglrx-kernel-source-8-3+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-18-386", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-18-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-18-386-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-18-generic", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-18-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-18-generic-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-18-openvz", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-18-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-18-openvz-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-18-rt", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-18-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-18-rt-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-18-server", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-18-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-18-server-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-18-virtual", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-18-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-18-virtual-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-18-xen", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-18-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-18-xen-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-doc-2.6.24", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-doc-2.6.24-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-18", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-18-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-18-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-18-386", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-18-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-18-386-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-18-generic", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-18-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-18-generic-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-18-openvz", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-18-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-18-openvz-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-18-rt", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-18-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-18-rt-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-18-server", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-18-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-18-server-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-18-virtual", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-18-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-18-virtual-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-18-xen", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-18-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-18-xen-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-18-386", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-18-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-18-386-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-18-generic", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-18-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-18-generic-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-18-openvz", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-18-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-18-openvz-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-18-rt", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-18-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-18-rt-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-18-server", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-18-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-18-server-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-18-virtual", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-18-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-18-virtual-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-18-xen", pkgver: "2.6.24-18.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-18-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-18-xen-2.6.24-18.16
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-18-386", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-18-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-18-386-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-18-generic", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-18-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-18-generic-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-18-openvz", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-18-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-18-openvz-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-18-rt", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-18-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-18-rt-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-18-server", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-18-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-18-server-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-18-virtual", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-18-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-18-virtual-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-18-xen", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-18-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-18-xen-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-18-386", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-18-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-18-386-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-18-generic", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-18-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-18-generic-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-18-openvz", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-18-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-18-openvz-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-18-rt", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-18-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-18-rt-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-18-server", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-18-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-18-server-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-18-virtual", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-18-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-18-virtual-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-18-xen", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-18-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-18-xen-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-18-386", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-18-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-18-386-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-18-generic", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-18-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-18-generic-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-18-server", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-18-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-18-server-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-18-virtual", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-18-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-18-virtual-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-kernel-devel", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-kernel-devel-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-libc-dev", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-libc-dev-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-18-386", pkgver: "2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-18-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-18-386-2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-18-generic", pkgver: "2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-18-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-18-generic-2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-18-openvz", pkgver: "2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-18-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-18-openvz-2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-18-rt", pkgver: "2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-18-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-18-rt-2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-18-server", pkgver: "2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-18-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-18-server-2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-18-xen", pkgver: "2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-18-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-18-xen-2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-common", pkgver: "2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-common-2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-source-2.6.24", pkgver: "2.6.24-18.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-source-2.6.24-2.6.24-18.32
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-18-386", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-18-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-18-386-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-18-generic", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-18-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-18-generic-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-18-openvz", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-18-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-18-openvz-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-18-rt", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-18-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-18-rt-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-18-server", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-18-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-18-server-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-18-virtual", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-18-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-18-virtual-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-18-xen", pkgver: "2.6.24-18.26");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-18-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-18-xen-2.6.24-18.26
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx", pkgver: "96.43.05+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-96.43.05+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx-dev", pkgver: "96.43.05+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-dev-96.43.05+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx-legacy", pkgver: "71.86.04+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-legacy-71.86.04+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx-legacy-dev", pkgver: "71.86.04+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-legacy-dev-71.86.04+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx-new", pkgver: "169.12+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-new-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-new-169.12+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx-new-dev", pkgver: "169.12+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-new-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-new-dev-169.12+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-kernel-source", pkgver: "96.43.05+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-kernel-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-kernel-source-96.43.05+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-legacy-kernel-source", pkgver: "71.86.04+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-legacy-kernel-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-legacy-kernel-source-71.86.04+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-new-kernel-source", pkgver: "169.12+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-new-kernel-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-new-kernel-source-169.12+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "xorg-driver-fglrx", pkgver: "7.1.0-8-3+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to xorg-driver-fglrx-7.1.0-8-3+2.6.24.13-18.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "xorg-driver-fglrx-dev", pkgver: "7.1.0-8-3+2.6.24.13-18.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to xorg-driver-fglrx-dev-7.1.0-8-3+2.6.24.13-18.41
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
