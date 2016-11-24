# This script was automatically generated from the 347-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27927);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "347-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN347-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avm-fritz-firmware 
- avm-fritz-firmware-2.6.15-27 
- avm-fritz-kernel-source 
- fglrx-control 
- fglrx-kernel-source 
- linux 
- linux-386 
- linux-686 
- linux-686-smp 
- linux-amd64-generic 
- linux-amd64-k8 
- linux-amd64-k8-smp 
- linux-amd64-server 
- linux-amd64-xeon 
- linux-doc 
- linux-doc-2.6.10 
- linux-doc-2.6.12 
- linux-headers-2.6.10-6 
- linux-headers-2.6.10-6-386 
- linux-headers-2.6.10-6-686 
- linux-headers-2.6.10-6-686-smp 
- linux
[...]');
script_set_attribute(attribute:'description', value: 'Sridhar Samudrala discovered a local Denial of Service vulnerability
in the handling of SCTP sockets. By opening such a socket with a
special SO_LINGER value, a local attacker could exploit this to crash
the kernel. (CVE-2006-4535)

Kirill Korotaev discovered that the ELF loader on the ia64 and sparc
platforms did not sufficiently verify the memory layout. By attempting
to execute a specially crafted executable, a local user could exploit
this to crash the kernel. (CVE-2006-4538)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avm-fritz-firmware-2.6.15.25 (Ubuntu 6.06)
- avm-fritz-firmware-2.6.15-27-3.11+2.6.15.11-5 (Ubuntu 6.06)
- avm-fritz-kernel-source-3.11+2.6.15.11-5 (Ubuntu 6.06)
- fglrx-control-8.25.18+2.6.15.11-5 (Ubuntu 6.06)
- fglrx-kernel-source-8.25.18+2.6.15.11-5 (Ubuntu 6.06)
- linux-2.6.15.25 (Ubuntu 6.06)
- linux-386-2.6.15.25 (Ubuntu 6.06)
- linux-686-2.6.15.25 (Ubuntu 6.06)
- linux-686-smp-2.6.15.25 (Ubuntu 6.06)
- linux-amd64-generic-2.6.15.25 (Ubuntu 6.06)
- linux-amd64-k8-2.6.15.25 (Ubuntu 6.
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-4535","CVE-2006-4538");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "avm-fritz-firmware", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to avm-fritz-firmware-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "avm-fritz-firmware-2.6.15-27", pkgver: "3.11+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-firmware-2.6.15-27-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to avm-fritz-firmware-2.6.15-27-3.11+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "avm-fritz-kernel-source", pkgver: "3.11+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avm-fritz-kernel-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to avm-fritz-kernel-source-3.11+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "fglrx-control", pkgver: "8.25.18+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-control-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to fglrx-control-8.25.18+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "fglrx-kernel-source", pkgver: "8.25.18+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-kernel-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to fglrx-kernel-source-8.25.18+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-386", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-386-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-686", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-686-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-686-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-686-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-686-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-amd64-generic", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-amd64-generic-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-amd64-k8", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-amd64-k8-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-amd64-k8-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-amd64-k8-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-amd64-k8-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-amd64-server", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-amd64-server-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-amd64-xeon", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-amd64-xeon-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-doc", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15.25
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-doc-2.6.10", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-doc-2.6.10-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-doc-2.6.12", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-doc-2.6.12-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-386", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-386-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-386-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-686", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-686-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-686-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-686-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-686-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-686-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-generic", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-amd64-generic-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-generic-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-k8", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-amd64-k8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-k8-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-k8-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-k8-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-amd64-xeon", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-amd64-xeon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-amd64-xeon-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-k7", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-k7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-k7-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-k7-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-k7-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-k7-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power3", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-power3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power3-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power3-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-power3-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power3-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power4", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-power4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power4-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-power4-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-power4-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-power4-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-powerpc", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-powerpc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-powerpc-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-headers-2.6.10-6-powerpc-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.10-6-powerpc-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-headers-2.6.10-6-powerpc-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-386", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-386-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-generic-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-xeon-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-iseries-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc64-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-386", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-386-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-686", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-686-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-amd64-generic", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-amd64-generic-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-amd64-k8", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-amd64-k8-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-amd64-server", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-amd64-server-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-amd64-xeon", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-amd64-xeon-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-k7", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-k7-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-powerpc", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-powerpc-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-powerpc-smp", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-powerpc-smp-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-powerpc64-smp", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-powerpc64-smp-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-server", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-server-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-server-bigiron", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-server-bigiron-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-sparc64", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-sparc64-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-sparc64-smp", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-sparc64-smp-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-386", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-386-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-686", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-686-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-amd64-generic", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-amd64-generic-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-amd64-k8", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-amd64-k8-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-amd64-server", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-amd64-server-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-amd64-xeon", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-amd64-xeon-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-k7", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-k7-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-power3", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-power3-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-power3-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-power3-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-power3-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-power3-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-power4", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-power4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-power4-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-power4-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-power4-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-power4-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-powerpc", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-powerpc-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-powerpc-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-powerpc-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-powerpc64-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-powerpc64-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-server", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-server-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-server-bigiron", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-server-bigiron-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-sparc64", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-sparc64-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-sparc64-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-sparc64-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-386", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-386-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-386-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-686", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-686-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-686-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-686-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-686-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-686-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-generic", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-amd64-generic-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-generic-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-k8", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-amd64-k8-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-k8-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-k8-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-k8-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-amd64-xeon", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-amd64-xeon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-amd64-xeon-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-k7", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-k7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-k7-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-k7-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-k7-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-k7-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power3", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-power3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power3-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power3-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-power3-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power3-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power4", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-power4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power4-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-power4-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-power4-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-power4-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-powerpc", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-powerpc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-powerpc-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-image-2.6.10-6-powerpc-smp", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.10-6-powerpc-smp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-image-2.6.10-6-powerpc-smp-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-386", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-386-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-generic-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-xeon-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-iseries-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc64-smp-2.6.12-10.40
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-386", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-386-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-686", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-686-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-amd64-generic", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-amd64-generic-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-amd64-k8", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-amd64-k8-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-amd64-server", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-amd64-server-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-amd64-xeon", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-amd64-xeon-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-k7", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-k7-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-powerpc", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-powerpc-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-powerpc-smp", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-powerpc-smp-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-powerpc64-smp", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-powerpc64-smp-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-server", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-server-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-server-bigiron", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-server-bigiron-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-sparc64", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-sparc64-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-sparc64-smp", pkgver: "2.6.15-27.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-sparc64-smp-2.6.15-27.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-386", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-386-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-686", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-686-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-amd64-generic", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-amd64-generic-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-amd64-k8", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-amd64-k8-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-amd64-server", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-amd64-server-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-amd64-xeon", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-amd64-xeon-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-k7", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-k7-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-power3", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-power3-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-power3-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-power3-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-power3-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-power3-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-power4", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-power4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-power4-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-power4-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-power4-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-power4-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-powerpc", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-powerpc-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-powerpc-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-powerpc-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-powerpc64-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-powerpc64-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-server", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-server-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-server-bigiron", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-server-bigiron-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-sparc64", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-sparc64-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-sparc64-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-sparc64-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-k7", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-k7-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-k7-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-k7-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-k7-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-patch-ubuntu-2.6.10", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-patch-ubuntu-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-patch-ubuntu-2.6.10-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-patch-ubuntu-2.6.12", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-patch-ubuntu-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-patch-ubuntu-2.6.12-2.6.12-10.40
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-power3", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-power3-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-power3-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-power3-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-power3-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-power3-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-power4", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-power4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-power4-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-power4-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-power4-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-power4-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-powerpc", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-powerpc-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-powerpc-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-powerpc-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-powerpc64-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-powerpc64-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-386", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-386-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-686", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-686-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-amd64-generic", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-amd64-generic-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-amd64-k8", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-amd64-k8-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-amd64-xeon", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-amd64-xeon-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-k7", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-k7-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-powerpc", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-powerpc-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-powerpc-smp", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-powerpc-smp-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-sparc64", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-sparc64-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-2.6.15-27-sparc64-smp", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-2.6.15-27-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-2.6.15-27-sparc64-smp-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-386", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-386-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-686", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-686-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-amd64-generic", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-amd64-generic-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-amd64-k8", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-amd64-k8-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-amd64-xeon", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-amd64-xeon-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-common", pkgver: "2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-common-2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-k7", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-k7-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-powerpc", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-powerpc-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-powerpc-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-powerpc-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-sparc64", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-sparc64-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-restricted-modules-sparc64-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-restricted-modules-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-restricted-modules-sparc64-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-server", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-server-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-server-bigiron", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-server-bigiron-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15.25
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-source-2.6.10", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-source-2.6.10-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-source-2.6.12", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-source-2.6.12-2.6.12-10.40
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-sparc64", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-sparc64-2.6.15.25
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-sparc64-smp", pkgver: "2.6.15.25");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-sparc64-smp-2.6.15.25
');
}
found = ubuntu_check(osver: "5.04", pkgname: "linux-tree-2.6.10", pkgver: "2.6.10-34.24");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-tree-2.6.10-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to linux-tree-2.6.10-2.6.10-34.24
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-tree-2.6.12", pkgver: "2.6.12-10.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-tree-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-tree-2.6.12-2.6.12-10.40
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-glx", pkgver: "1.0.8762+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-glx-1.0.8762+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-glx-dev", pkgver: "1.0.8762+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-glx-dev-1.0.8762+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-glx-legacy", pkgver: "1.0.7174+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-glx-legacy-1.0.7174+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-glx-legacy-dev", pkgver: "1.0.7174+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-glx-legacy-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-glx-legacy-dev-1.0.7174+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-kernel-source", pkgver: "1.0.8762+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-kernel-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-kernel-source-1.0.8762+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "nvidia-legacy-kernel-source", pkgver: "1.0.7174+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nvidia-legacy-kernel-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to nvidia-legacy-kernel-source-1.0.7174+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "vmware-player-kernel-modules", pkgver: "2.6.15.10-10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to vmware-player-kernel-modules-2.6.15.10-10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "vmware-player-kernel-modules-2.6.15-27", pkgver: "2.6.15.10-10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-modules-2.6.15-27-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to vmware-player-kernel-modules-2.6.15-27-2.6.15.10-10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "vmware-player-kernel-source", pkgver: "2.6.15.10-10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vmware-player-kernel-source-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to vmware-player-kernel-source-2.6.15.10-10
');
}
found = ubuntu_check(osver: "6.06", pkgname: "xorg-driver-fglrx", pkgver: "7.0.0-8.25.18+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xorg-driver-fglrx-7.0.0-8.25.18+2.6.15.11-5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "xorg-driver-fglrx-dev", pkgver: "7.0.0-8.25.18+2.6.15.11-5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xorg-driver-fglrx-dev-7.0.0-8.25.18+2.6.15.11-5
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
