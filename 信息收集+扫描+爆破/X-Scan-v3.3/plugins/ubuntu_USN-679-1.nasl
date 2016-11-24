# This script was automatically generated from the 679-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37683);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "679-1");
script_summary(english:"linux, linux-source-2.6.15/22 vulnerabilities");
script_name(english:"USN679-1 : linux, linux-source-2.6.15/22 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avm-fritz-firmware-2.6.15-53 
- avm-fritz-firmware-2.6.22-16 
- avm-fritz-firmware-2.6.24-22 
- avm-fritz-kernel-source 
- fglrx-amdcccle 
- fglrx-control 
- fglrx-kernel-source 
- linux-backports-modules-2.6.15-53-386 
- linux-backports-modules-2.6.15-53-686 
- linux-backports-modules-2.6.15-53-amd64-generic 
- linux-backports-modules-2.6.15-53-amd64-k8 
- linux-backports-modules-2.6.15-53-amd64-server 
- linux-backports-modules-2.6.15-53-amd64-xeon 

[...]');
script_set_attribute(attribute:'description', value: 'It was discovered that the Xen hypervisor block driver did not correctly
validate requests. A user with root privileges in a guest OS could make a
malicious IO request with a large number of blocks that would crash the
host OS, leading to a denial of service. This only affected Ubuntu 7.10.
(CVE-2007-5498)

It was discovered the the i915 video driver did not correctly validate
memory addresses. A local attacker could exploit this to remap memory that
could cause a system crash, leading to a denial of service. This issue did
not affect Ubuntu 6.06 and was previous fixed for Ubuntu 7.10 and 8.04 in
USN-659-1. Ubuntu 8.10 has now been corrected as well. (CVE-2008-3831)

David Watson discovered that the kernel did not correctly strip permissions
when creating files in setgid directories. A local user could exploit this
to gain additional group privileges. This issue only affected Ubuntu 6.06.
(CVE-2008-4210)

Olaf Kirch and Miklos Szeredi discovered that the Linux kernel did
not correctly reject the "append" fla
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avm-fritz-firmware-2.6.15-53-3.11+2.6.15.12-53.4 (Ubuntu 6.06)
- avm-fritz-firmware-2.6.22-16-3.11+2.6.22.4-16.12 (Ubuntu 7.10)
- avm-fritz-firmware-2.6.24-22-3.11+2.6.24.14-22.53 (Ubuntu 8.04)
- avm-fritz-kernel-source-3.11+2.6.24.14-22.53 (Ubuntu 8.04)
- fglrx-amdcccle-2.6.24.14-22.53 (Ubuntu 8.04)
- fglrx-control-8-3+2.6.24.14-22.53 (Ubuntu 8.04)
- fglrx-kernel-source-8-3+2.6.24.14-22.53 (Ubuntu 8.04)
- linux-backports-modules-2.6.15-53-386-2.6.15-53.11 (Ubuntu 6.06)
- linux-backports-mo
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2007-5498","CVE-2008-3831","CVE-2008-4210","CVE-2008-4554","CVE-2008-4576","CVE-2008-4618","CVE-2008-4933","CVE-2008-4934","CVE-2008-5025","CVE-2008-5029","CVE-2008-5033");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "avm-fritz-firmware-2.6.15-53", pkgver: "3.11+2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.15-53-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to avm-fritz-firmware-2.6.15-53-3.11+2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "avm-fritz-firmware-2.6.22-16", pkgver: "3.11+2.6.22.4-16.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.22-16-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to avm-fritz-firmware-2.6.22-16-3.11+2.6.22.4-16.12
');
}
found = ubuntu_check(osver: "8.04", pkgname: "avm-fritz-firmware-2.6.24-22", pkgver: "3.11+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.24-22-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to avm-fritz-firmware-2.6.24-22-3.11+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "avm-fritz-kernel-source", pkgver: "3.11+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-kernel-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to avm-fritz-kernel-source-3.11+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "fglrx-amdcccle", pkgver: "2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-amdcccle-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to fglrx-amdcccle-2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "fglrx-control", pkgver: "8-3+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-control-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to fglrx-control-8-3+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "fglrx-kernel-source", pkgver: "8-3+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-kernel-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to fglrx-kernel-source-8-3+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-386", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-386-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-686", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-686-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-amd64-generic", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-amd64-generic-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-amd64-k8", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-amd64-k8-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-amd64-server", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-amd64-server-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-amd64-xeon", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-amd64-xeon-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-k7", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-k7-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-powerpc", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-powerpc-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-powerpc-smp", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-powerpc-smp-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-powerpc64-smp", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-powerpc64-smp-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-server", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-server-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-server-bigiron", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-server-bigiron-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-sparc64", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-sparc64-2.6.15-53.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-53-sparc64-smp", pkgver: "2.6.15-53.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-53-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-53-sparc64-smp-2.6.15-53.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-386", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-386-2.6.22-16.17
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-generic", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-generic-2.6.22-16.17
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-powerpc", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-powerpc-2.6.22-16.17
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-powerpc-smp", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-powerpc-smp-2.6.22-16.17
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-powerpc64-smp", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-powerpc64-smp-2.6.22-16.17
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-rt", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-rt-2.6.22-16.17
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-server", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-server-2.6.22-16.17
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-sparc64", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-sparc64-2.6.22-16.17
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-sparc64-smp", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-sparc64-smp-2.6.22-16.17
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-ume", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-ume-2.6.22-16.17
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-16-xen", pkgver: "2.6.22-16.17");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-16-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-16-xen-2.6.22-16.17
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-22-386", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-22-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-22-386-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-22-generic", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-22-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-22-generic-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-22-openvz", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-22-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-22-openvz-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-22-rt", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-22-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-22-rt-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-22-server", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-22-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-22-server-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-22-virtual", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-22-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-22-virtual-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-backports-modules-2.6.24-22-xen", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.24-22-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-backports-modules-2.6.24-22-xen-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-backports-modules-2.6.27-9-generic", pkgver: "2.6.27-9.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.27-9-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-backports-modules-2.6.27-9-generic-2.6.27-9.5
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-backports-modules-2.6.27-9-server", pkgver: "2.6.27-9.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.27-9-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-backports-modules-2.6.27-9-server-2.6.27-9.5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-53.74
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-doc-2.6.22", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-doc-2.6.22-2.6.22-16.60
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-doc-2.6.24", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-doc-2.6.24-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-doc-2.6.27", pkgver: "2.6.27-9.19");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-doc-2.6.27-2.6.27-9.19
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-386", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-386-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-686", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-686-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-amd64-generic", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-amd64-generic-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-amd64-k8", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-amd64-k8-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-amd64-server", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-amd64-server-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-amd64-xeon", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-amd64-xeon-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-k7", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-k7-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-powerpc", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-powerpc-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-powerpc-smp", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-powerpc-smp-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-powerpc64-smp", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-powerpc64-smp-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-server", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-server-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-server-bigiron", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-server-bigiron-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-sparc64", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-sparc64-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-sparc64-smp", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-sparc64-smp-2.6.15-53.74
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-386", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-386-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-cell", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-cell-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-generic", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-generic-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-powerpc", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-powerpc-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-powerpc-smp", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-powerpc-smp-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-powerpc64-smp", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-powerpc64-smp-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-rt", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-rt-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-server", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-server-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-sparc64", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-sparc64-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-sparc64-smp", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-sparc64-smp-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-ume", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-ume-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-virtual", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-virtual-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-xen", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-xen-2.6.22-16.60
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-22", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-22-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-22-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-22-386", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-22-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-22-386-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-22-generic", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-22-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-22-generic-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-22-openvz", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-22-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-22-openvz-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-22-rt", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-22-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-22-rt-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-22-server", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-22-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-22-server-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-22-virtual", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-22-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-22-virtual-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-22-xen", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-22-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-22-xen-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-9", pkgver: "2.6.27-9.19");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-9-2.6.27-9.19
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-9-generic", pkgver: "2.6.27-9.19");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-9-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-9-generic-2.6.27-9.19
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-9-server", pkgver: "2.6.27-9.19");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-9-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-9-server-2.6.27-9.19
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-22-386", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-22-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-22-386-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-22-generic", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-22-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-22-generic-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-22-openvz", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-22-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-22-openvz-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-22-rt", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-22-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-22-rt-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-22-server", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-22-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-22-server-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-22-virtual", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-22-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-22-virtual-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lbm-2.6.24-22-xen", pkgver: "2.6.24-22.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.24-22-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lbm-2.6.24-22-xen-2.6.24-22.29
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-lbm-2.6.27-9-generic", pkgver: "2.6.27-9.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.27-9-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-lbm-2.6.27-9-generic-2.6.27-9.5
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-lbm-2.6.27-9-server", pkgver: "2.6.27-9.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lbm-2.6.27-9-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-lbm-2.6.27-9-server-2.6.27-9.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-22-386", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-22-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-22-386-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-22-generic", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-22-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-22-generic-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-22-openvz", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-22-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-22-openvz-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-22-rt", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-22-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-22-rt-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-22-server", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-22-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-22-server-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-22-virtual", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-22-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-22-virtual-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-lum-2.6.24-22-xen", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-lum-2.6.24-22-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-lum-2.6.24-22-xen-2.6.24-22.35
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-386", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-386-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-686", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-686-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-amd64-generic", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-amd64-generic-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-amd64-k8", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-amd64-k8-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-amd64-server", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-amd64-server-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-amd64-xeon", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-amd64-xeon-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-k7", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-k7-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-powerpc", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-powerpc-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-powerpc-smp", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-powerpc-smp-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-powerpc64-smp", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-powerpc64-smp-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-server", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-server-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-server-bigiron", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-server-bigiron-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-sparc64", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-sparc64-2.6.15-53.74
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-sparc64-smp", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-sparc64-smp-2.6.15-53.74
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-386", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-386-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-cell", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-cell-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-generic", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-generic-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-powerpc", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-powerpc-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-powerpc-smp", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-powerpc-smp-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-powerpc64-smp", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-powerpc64-smp-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-rt", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-rt-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-server", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-server-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-sparc64", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-sparc64-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-sparc64-smp", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-sparc64-smp-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-ume", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-ume-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-virtual", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-virtual-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-xen", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-xen-2.6.22-16.60
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-22-386", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-22-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-22-386-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-22-generic", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-22-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-22-generic-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-22-openvz", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-22-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-22-openvz-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-22-rt", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-22-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-22-rt-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-22-server", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-22-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-22-server-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-22-virtual", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-22-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-22-virtual-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-22-xen", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-22-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-22-xen-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-9-generic", pkgver: "2.6.27-9.19");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-9-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-9-generic-2.6.27-9.19
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-9-server", pkgver: "2.6.27-9.19");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-9-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-9-server-2.6.27-9.19
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-9-virtual", pkgver: "2.6.27-9.19");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-9-virtual-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-9-virtual-2.6.27-9.19
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-386", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-386-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-generic", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-generic-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-server", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-server-2.6.22-16.60
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-virtual", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-virtual-2.6.22-16.60
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-22-386", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-22-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-22-386-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-22-generic", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-22-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-22-generic-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-22-server", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-22-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-22-server-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-22-virtual", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-22-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-22-virtual-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-kernel-devel", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-kernel-devel-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-libc-dev", pkgver: "2.6.27-9.19");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-libc-dev-2.6.27-9.19
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-53-386", pkgver: "2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-53-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-53-386-2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-53-686", pkgver: "2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-53-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-53-686-2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-53-amd64-generic", pkgver: "2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-53-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-53-amd64-generic-2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-53-amd64-k8", pkgver: "2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-53-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-53-amd64-k8-2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-53-amd64-xeon", pkgver: "2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-53-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-53-amd64-xeon-2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-53-k7", pkgver: "2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-53-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-53-k7-2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-53-powerpc", pkgver: "2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-53-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-53-powerpc-2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-53-powerpc-smp", pkgver: "2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-53-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-53-powerpc-smp-2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-53-sparc64", pkgver: "2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-53-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-53-sparc64-2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-53-sparc64-smp", pkgver: "2.6.15.12-53.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-53-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-53-sparc64-smp-2.6.15.12-53.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-16-386", pkgver: "2.6.22.4-16.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-16-386-2.6.22.4-16.12
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-16-generic", pkgver: "2.6.22.4-16.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-16-generic-2.6.22.4-16.12
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-16-powerpc", pkgver: "2.6.22.4-16.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-16-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-16-powerpc-2.6.22.4-16.12
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-16-powerpc-smp", pkgver: "2.6.22.4-16.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-16-powerpc-smp-2.6.22.4-16.12
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-16-powerpc64-smp", pkgver: "2.6.22.4-16.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-16-powerpc64-smp-2.6.22.4-16.12
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-16-rt", pkgver: "2.6.22.4-16.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-16-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-16-rt-2.6.22.4-16.12
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-16-sparc64", pkgver: "2.6.22.4-16.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-16-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-16-sparc64-2.6.22.4-16.12
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-16-sparc64-smp", pkgver: "2.6.22.4-16.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-16-sparc64-smp-2.6.22.4-16.12
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-16-xen", pkgver: "2.6.22.4-16.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-16-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-16-xen-2.6.22.4-16.12
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-22-386", pkgver: "2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-22-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-22-386-2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-22-generic", pkgver: "2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-22-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-22-generic-2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-22-openvz", pkgver: "2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-22-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-22-openvz-2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-22-rt", pkgver: "2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-22-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-22-rt-2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-22-server", pkgver: "2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-22-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-22-server-2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-restricted-modules-2.6.24-22-xen", pkgver: "2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.24-22-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-restricted-modules-2.6.24-22-xen-2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-restricted-modules-2.6.27-9-generic", pkgver: "2.6.27-9.13");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.27-9-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-restricted-modules-2.6.27-9-generic-2.6.27-9.13
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-restricted-modules-2.6.27-9-server", pkgver: "2.6.27-9.13");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.27-9-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-restricted-modules-2.6.27-9-server-2.6.27-9.13
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-restricted-modules-common", pkgver: "2.6.27-9.13");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-common-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-restricted-modules-common-2.6.27-9.13
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-53.74");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-53.74
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-source-2.6.22", pkgver: "2.6.22-16.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-source-2.6.22-2.6.22-16.60
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-source-2.6.24", pkgver: "2.6.24-22.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-source-2.6.24-2.6.24-22.45
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-source-2.6.27", pkgver: "2.6.27-9.19");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-source-2.6.27-2.6.27-9.19
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-386", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-386-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-cell", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-cell-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-generic", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-generic-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-powerpc", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-powerpc-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-powerpc-smp", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-powerpc-smp-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-powerpc64-smp", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-powerpc64-smp-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-rt", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-rt-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-server", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-server-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-sparc64", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-sparc64-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-sparc64-smp", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-sparc64-smp-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-ume", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-ume-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-virtual", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-virtual-2.6.22-16.41
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-16-xen", pkgver: "2.6.22-16.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-16-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-16-xen-2.6.22-16.41
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-22-386", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-22-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-22-386-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-22-generic", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-22-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-22-generic-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-22-openvz", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-22-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-22-openvz-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-22-rt", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-22-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-22-rt-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-22-server", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-22-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-22-server-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-22-virtual", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-22-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-22-virtual-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-ubuntu-modules-2.6.24-22-xen", pkgver: "2.6.24-22.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.24-22-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-ubuntu-modules-2.6.24-22-xen-2.6.24-22.35
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx", pkgver: "96.43.05+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-96.43.05+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx-dev", pkgver: "96.43.05+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-dev-96.43.05+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx-legacy", pkgver: "71.86.04+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-legacy-71.86.04+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx-legacy-dev", pkgver: "71.86.04+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-legacy-dev-71.86.04+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx-new", pkgver: "169.12+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-new-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-new-169.12+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-glx-new-dev", pkgver: "169.12+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-new-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-glx-new-dev-169.12+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-kernel-source", pkgver: "96.43.05+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-kernel-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-kernel-source-96.43.05+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-legacy-kernel-source", pkgver: "71.86.04+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-legacy-kernel-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-legacy-kernel-source-71.86.04+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "nvidia-new-kernel-source", pkgver: "169.12+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-new-kernel-source-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to nvidia-new-kernel-source-169.12+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "xorg-driver-fglrx", pkgver: "7.1.0-8-3+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to xorg-driver-fglrx-7.1.0-8-3+2.6.24.14-22.53
');
}
found = ubuntu_check(osver: "8.04", pkgname: "xorg-driver-fglrx-dev", pkgver: "7.1.0-8-3+2.6.24.14-22.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to xorg-driver-fglrx-dev-7.1.0-8-3+2.6.24.14-22.53
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
