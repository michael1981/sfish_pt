# This script was automatically generated from the 618-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33255);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "618-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN618-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avm-fritz-firmware-2.6.15-52 
- avm-fritz-firmware-2.6.20-17 
- avm-fritz-firmware-2.6.22-15 
- avm-fritz-kernel-source 
- fglrx-control 
- fglrx-kernel-source 
- linux-backports-modules-2.6.15-52-386 
- linux-backports-modules-2.6.15-52-686 
- linux-backports-modules-2.6.15-52-amd64-generic 
- linux-backports-modules-2.6.15-52-amd64-k8 
- linux-backports-modules-2.6.15-52-amd64-server 
- linux-backports-modules-2.6.15-52-amd64-xeon 
- linux-backports-
[...]');
script_set_attribute(attribute:'description', value: 'It was discovered that the ALSA /proc interface did not write the
correct number of bytes when reporting memory allocations.  A local
attacker might be able to access sensitive kernel memory, leading to
a loss of privacy. (CVE-2007-4571)

Multiple buffer overflows were discovered in the handling of CIFS
filesystems.  A malicious CIFS server could cause a client system crash
or possibly execute arbitrary code with kernel privileges. (CVE-2007-5904)

It was discovered that PowerPC kernels did not correctly handle reporting
certain system details.  By requesting a specific set of information,
a local attacker could cause a system crash resulting in a denial
of service. (CVE-2007-6694)

It was discovered that some device driver fault handlers did not
correctly verify memory ranges.  A local attacker could exploit this
to access sensitive kernel memory, possibly leading to a loss of privacy.
(CVE-2008-0007)

It was discovered that CPU resource limits could be bypassed.
A malicious local user could exploit this to
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avm-fritz-firmware-2.6.15-52-3.11+2.6.15.12-52.3 (Ubuntu 6.06)
- avm-fritz-firmware-2.6.20-17-3.11+2.6.20.6-17.31 (Ubuntu 7.04)
- avm-fritz-firmware-2.6.22-15-3.11+2.6.22.4-15.11 (Ubuntu 7.10)
- avm-fritz-kernel-source-3.11+2.6.22.4-15.11 (Ubuntu 7.10)
- fglrx-control-8.37.6+2.6.22.4-15.11 (Ubuntu 7.10)
- fglrx-kernel-source-8.37.6+2.6.22.4-15.11 (Ubuntu 7.10)
- linux-backports-modules-2.6.15-52-386-2.6.15-52.10 (Ubuntu 6.06)
- linux-backports-modules-2.6.15-52-686-2.6.15-52.10 (Ubuntu 6.06
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2007-4571","CVE-2007-5904","CVE-2007-6694","CVE-2008-0007","CVE-2008-1294","CVE-2008-1375","CVE-2008-1669");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "avm-fritz-firmware-2.6.15-52", pkgver: "3.11+2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.15-52-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to avm-fritz-firmware-2.6.15-52-3.11+2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "7.04", pkgname: "avm-fritz-firmware-2.6.20-17", pkgver: "3.11+2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.20-17-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to avm-fritz-firmware-2.6.20-17-3.11+2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.10", pkgname: "avm-fritz-firmware-2.6.22-15", pkgver: "3.11+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.22-15-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to avm-fritz-firmware-2.6.22-15-3.11+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "avm-fritz-kernel-source", pkgver: "3.11+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-kernel-source-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to avm-fritz-kernel-source-3.11+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "fglrx-control", pkgver: "8.37.6+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-control-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to fglrx-control-8.37.6+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "fglrx-kernel-source", pkgver: "8.37.6+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-kernel-source-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to fglrx-kernel-source-8.37.6+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-386", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-386-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-686", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-686-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-amd64-generic", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-amd64-generic-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-amd64-k8", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-amd64-k8-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-amd64-server", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-amd64-server-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-amd64-xeon", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-amd64-xeon-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-k7", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-k7-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-powerpc", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-powerpc-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-powerpc-smp", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-powerpc-smp-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-powerpc64-smp", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-powerpc64-smp-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-server", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-server-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-server-bigiron", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-server-bigiron-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-sparc64", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-sparc64-2.6.15-52.10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-backports-modules-2.6.15-52-sparc64-smp", pkgver: "2.6.15-52.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.15-52-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-backports-modules-2.6.15-52-sparc64-smp-2.6.15-52.10
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-backports-modules-2.6.20-17-386", pkgver: "2.6.20-17.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-backports-modules-2.6.20-17-386-2.6.20-17.12
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-backports-modules-2.6.20-17-generic", pkgver: "2.6.20-17.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-backports-modules-2.6.20-17-generic-2.6.20-17.12
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-backports-modules-2.6.20-17-powerpc", pkgver: "2.6.20-17.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-backports-modules-2.6.20-17-powerpc-2.6.20-17.12
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-backports-modules-2.6.20-17-powerpc-smp", pkgver: "2.6.20-17.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-backports-modules-2.6.20-17-powerpc-smp-2.6.20-17.12
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-backports-modules-2.6.20-17-powerpc64-smp", pkgver: "2.6.20-17.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-backports-modules-2.6.20-17-powerpc64-smp-2.6.20-17.12
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-backports-modules-2.6.20-17-server", pkgver: "2.6.20-17.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.20-17-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-backports-modules-2.6.20-17-server-2.6.20-17.12
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-backports-modules-2.6.20-17-server-bigiron", pkgver: "2.6.20-17.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.20-17-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-backports-modules-2.6.20-17-server-bigiron-2.6.20-17.12
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-backports-modules-2.6.20-17-sparc64", pkgver: "2.6.20-17.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-backports-modules-2.6.20-17-sparc64-2.6.20-17.12
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-backports-modules-2.6.20-17-sparc64-smp", pkgver: "2.6.20-17.12");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-backports-modules-2.6.20-17-sparc64-smp-2.6.20-17.12
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-386", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-386-2.6.22-15.16
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-generic", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-generic-2.6.22-15.16
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-powerpc", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-powerpc-2.6.22-15.16
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-powerpc-smp", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-powerpc-smp-2.6.22-15.16
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-powerpc64-smp", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-powerpc64-smp-2.6.22-15.16
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-rt", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-rt-2.6.22-15.16
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-server", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-server-2.6.22-15.16
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-sparc64", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-sparc64-2.6.22-15.16
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-sparc64-smp", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-sparc64-smp-2.6.22-15.16
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-ume", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-ume-2.6.22-15.16
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-backports-modules-2.6.22-15-xen", pkgver: "2.6.22-15.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-backports-modules-2.6.22-15-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-backports-modules-2.6.22-15-xen-2.6.22-15.16
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-52.67
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-doc-2.6.20", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-doc-2.6.20-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-doc-2.6.22", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-doc-2.6.22-2.6.22-15.54
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-386", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-386-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-686", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-686-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-generic", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-generic-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-k8", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-k8-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-server", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-server-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-xeon", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-xeon-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-k7", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-k7-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-powerpc", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-powerpc-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-powerpc-smp", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-powerpc-smp-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-powerpc64-smp", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-powerpc64-smp-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-server", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-server-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-server-bigiron", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-server-bigiron-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-sparc64", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-sparc64-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-sparc64-smp", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-sparc64-smp-2.6.15-52.67
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-386", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-386-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-generic", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-generic-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-lowlatency", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-lowlatency-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-powerpc", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-powerpc-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-powerpc-smp", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-powerpc-smp-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-powerpc64-smp", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-powerpc64-smp-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-server", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-server-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-server-bigiron", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-server-bigiron-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-sparc64", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-sparc64-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-sparc64-smp", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-sparc64-smp-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-386", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-386-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-cell", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-cell-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-generic", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-generic-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-powerpc", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-powerpc-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-powerpc-smp", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-powerpc-smp-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-powerpc64-smp", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-powerpc64-smp-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-rt", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-rt-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-server", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-server-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-sparc64", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-sparc64-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-sparc64-smp", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-sparc64-smp-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-ume", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-ume-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-virtual", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-virtual-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-xen", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-xen-2.6.22-15.54
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-386", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-386-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-686", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-686-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-generic", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-generic-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-k8", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-k8-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-server", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-server-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-xeon", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-xeon-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-k7", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-k7-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-powerpc", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-powerpc-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-powerpc-smp", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-powerpc-smp-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-powerpc64-smp", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-powerpc64-smp-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-server", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-server-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-server-bigiron", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-server-bigiron-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-sparc64", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-sparc64-2.6.15-52.67
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-sparc64-smp", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-sparc64-smp-2.6.15-52.67
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-386", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-386-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-generic", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-generic-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-lowlatency", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-lowlatency-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-powerpc", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-powerpc-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-powerpc-smp", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-powerpc-smp-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-powerpc64-smp", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-powerpc64-smp-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-server", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-server-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-server-bigiron", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-server-bigiron-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-sparc64", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-sparc64-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-sparc64-smp", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-sparc64-smp-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-386", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-386-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-cell", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-cell-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-generic", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-generic-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-powerpc", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-powerpc-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-powerpc-smp", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-powerpc-smp-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-powerpc64-smp", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-powerpc64-smp-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-rt", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-rt-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-server", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-server-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-sparc64", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-sparc64-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-sparc64-smp", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-sparc64-smp-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-ume", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-ume-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-virtual", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-virtual-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-xen", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-xen-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-386", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-386-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-generic", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-generic-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-lowlatency", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-lowlatency-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-powerpc", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-powerpc-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-powerpc-smp", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-powerpc-smp-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-powerpc64-smp", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-powerpc64-smp-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-server", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-server-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-server-bigiron", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-server-bigiron-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-sparc64", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-sparc64-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-sparc64-smp", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-sparc64-smp-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-386", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-386-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-generic", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-generic-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-server", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-server-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-virtual", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-virtual-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-kernel-devel", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-kernel-devel-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-libc-dev", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-libc-dev-2.6.22-15.54
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-52-386", pkgver: "2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-52-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-52-386-2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-52-686", pkgver: "2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-52-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-52-686-2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-52-amd64-generic", pkgver: "2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-52-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-52-amd64-generic-2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-52-amd64-k8", pkgver: "2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-52-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-52-amd64-k8-2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-52-amd64-xeon", pkgver: "2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-52-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-52-amd64-xeon-2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-52-k7", pkgver: "2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-52-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-52-k7-2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-52-powerpc", pkgver: "2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-52-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-52-powerpc-2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-52-powerpc-smp", pkgver: "2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-52-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-52-powerpc-smp-2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-52-sparc64", pkgver: "2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-52-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-52-sparc64-2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-52-sparc64-smp", pkgver: "2.6.15.12-52.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-52-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-52-sparc64-smp-2.6.15.12-52.3
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-17-386", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-17-386-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-17-generic", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-17-generic-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-17-lowlatency", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-17-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-17-lowlatency-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-17-powerpc", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-17-powerpc-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-17-powerpc-smp", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-17-powerpc-smp-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-17-powerpc64-smp", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-17-powerpc64-smp-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-17-sparc64", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-17-sparc64-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-restricted-modules-2.6.20-17-sparc64-smp", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-restricted-modules-2.6.20-17-sparc64-smp-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-15-386", pkgver: "2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-15-386-2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-15-generic", pkgver: "2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-15-generic-2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-15-powerpc", pkgver: "2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-15-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-15-powerpc-2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-15-powerpc-smp", pkgver: "2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-15-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-15-powerpc-smp-2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-15-powerpc64-smp", pkgver: "2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-15-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-15-powerpc64-smp-2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-15-rt", pkgver: "2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-15-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-15-rt-2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-15-sparc64", pkgver: "2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-15-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-15-sparc64-2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-15-sparc64-smp", pkgver: "2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-15-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-15-sparc64-smp-2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-2.6.22-15-xen", pkgver: "2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.22-15-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-2.6.22-15-xen-2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-restricted-modules-common", pkgver: "2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-restricted-modules-common-2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-52.67");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-52.67
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-source-2.6.20", pkgver: "2.6.20-17.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-source-2.6.20-2.6.20-17.36
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-source-2.6.22", pkgver: "2.6.22-15.54");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-source-2.6.22-2.6.22-15.54
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-386", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-386-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-cell", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-cell-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-generic", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-generic-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-powerpc", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-powerpc-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-powerpc-smp", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-powerpc-smp-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-powerpc64-smp", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-powerpc64-smp-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-rt", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-rt-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-server", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-server-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-sparc64", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-sparc64-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-sparc64-smp", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-sparc64-smp-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-ume", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-ume-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-virtual", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-virtual-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-ubuntu-modules-2.6.22-15-xen", pkgver: "2.6.22-15.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-ubuntu-modules-2.6.22-15-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-ubuntu-modules-2.6.22-15-xen-2.6.22-15.39
');
}
found = ubuntu_check(osver: "7.10", pkgname: "nvidia-glx", pkgver: "1.0.9639+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to nvidia-glx-1.0.9639+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "nvidia-glx-dev", pkgver: "1.0.9639+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to nvidia-glx-dev-1.0.9639+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "nvidia-glx-legacy", pkgver: "1.0.7185+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to nvidia-glx-legacy-1.0.7185+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "nvidia-glx-legacy-dev", pkgver: "1.0.7185+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to nvidia-glx-legacy-dev-1.0.7185+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "nvidia-glx-new", pkgver: "100.14.19+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-new-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to nvidia-glx-new-100.14.19+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "nvidia-glx-new-dev", pkgver: "100.14.19+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-new-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to nvidia-glx-new-dev-100.14.19+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "nvidia-kernel-source", pkgver: "1.0.9639+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-kernel-source-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to nvidia-kernel-source-1.0.9639+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "nvidia-legacy-kernel-source", pkgver: "1.0.7185+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-legacy-kernel-source-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to nvidia-legacy-kernel-source-1.0.7185+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "nvidia-new-kernel-source", pkgver: "100.14.19+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-new-kernel-source-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to nvidia-new-kernel-source-100.14.19+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vmware-player-kernel-modules-2.6.20-17", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-2.6.20-17-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vmware-player-kernel-modules-2.6.20-17-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vmware-server-kernel-modules-2.6.20-17", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-server-kernel-modules-2.6.20-17-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vmware-server-kernel-modules-2.6.20-17-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.04", pkgname: "vmware-tools-kernel-modules-2.6.20-17", pkgver: "2.6.20.6-17.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-tools-kernel-modules-2.6.20-17-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to vmware-tools-kernel-modules-2.6.20-17-2.6.20.6-17.31
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xorg-driver-fglrx", pkgver: "7.1.0-8.37.6+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xorg-driver-fglrx-7.1.0-8.37.6+2.6.22.4-15.11
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xorg-driver-fglrx-dev", pkgver: "7.1.0-8.37.6+2.6.22.4-15.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xorg-driver-fglrx-dev-7.1.0-8.37.6+2.6.22.4-15.11
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
