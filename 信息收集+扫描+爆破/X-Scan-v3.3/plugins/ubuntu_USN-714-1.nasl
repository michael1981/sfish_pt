# This script was automatically generated from the 714-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36454);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "714-1");
script_summary(english:"linux-source-2.6.15/22, linux vulnerabilities");
script_name(english:"USN714-1 : linux-source-2.6.15/22, linux vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
- linux-doc-2.6.22 
- linux-doc-2.6.24 
- linux-headers-2.6.15-53 
- linux-headers-2.6.15-53-386 
- linux-headers-2.6.15-53-686 
- linux-headers-2.6.15-53-amd64-generic 
- linux-headers-2.6.15-53-amd64-k8 
- linux-headers-2.6.15-53-amd64-server 
- linux-headers-2.6.15-53-amd64-xeon 
- linux-headers-2.6.15-53-k7 
- linux-headers-2.6.15-53-powerpc 
- linux-headers-2.6.15-53-powerpc-smp 
- linux-headers-2.6.15-53-powerpc64-smp 
- linux-h
[...]');
script_set_attribute(attribute:'description', value: 'Hugo Dias discovered that the ATM subsystem did not correctly manage socket
counts. A local attacker could exploit this to cause a system hang, leading
to a denial of service. (CVE-2008-5079)

It was discovered that the libertas wireless driver did not correctly
handle beacon and probe responses. A physically near-by attacker could
generate specially crafted wireless network traffic and cause a denial of
service. Ubuntu 6.06 was not affected. (CVE-2008-5134)

It was discovered that the inotify subsystem contained watch removal race
conditions. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2008-5182)

Dann Frazier discovered that in certain situations sendmsg did not
correctly release allocated memory. A local attacker could exploit this to
force the system to run out of free memory, leading to a denial of service.
Ubuntu 6.06 was not affected.  (CVE-2008-5300)

It was discovered that the ATA subsystem did not correctly set timeouts. A
local attacker could explo
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-53.75 (Ubuntu 6.06)
- linux-doc-2.6.22-2.6.22-16.61 (Ubuntu 7.10)
- linux-doc-2.6.24-2.6.24-23.48 (Ubuntu 8.04)
- linux-headers-2.6.15-53-2.6.15-53.75 (Ubuntu 6.06)
- linux-headers-2.6.15-53-386-2.6.15-53.75 (Ubuntu 6.06)
- linux-headers-2.6.15-53-686-2.6.15-53.75 (Ubuntu 6.06)
- linux-headers-2.6.15-53-amd64-generic-2.6.15-53.75 (Ubuntu 6.06)
- linux-headers-2.6.15-53-amd64-k8-2.6.15-53.75 (Ubuntu 6.06)
- linux-headers-2.6.15-53-amd64-server-2.6.15-53.75 (Ubuntu 6.0
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-5079","CVE-2008-5134","CVE-2008-5182","CVE-2008-5300","CVE-2008-5700","CVE-2008-5702","CVE-2008-5713");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-53.75
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-doc-2.6.22", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-doc-2.6.22-2.6.22-16.61
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-doc-2.6.24", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-doc-2.6.24-2.6.24-23.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-386", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-386-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-686", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-686-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-amd64-generic", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-amd64-generic-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-amd64-k8", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-amd64-k8-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-amd64-server", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-amd64-server-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-amd64-xeon", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-amd64-xeon-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-k7", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-k7-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-powerpc", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-powerpc-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-powerpc-smp", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-powerpc-smp-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-powerpc64-smp", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-powerpc64-smp-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-server", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-server-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-server-bigiron", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-server-bigiron-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-sparc64", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-sparc64-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-53-sparc64-smp", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-53-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-53-sparc64-smp-2.6.15-53.75
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-386", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-386-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-cell", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-cell-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-generic", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-generic-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-powerpc", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-powerpc-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-powerpc-smp", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-powerpc-smp-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-powerpc64-smp", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-powerpc64-smp-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-rt", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-rt-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-server", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-server-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-sparc64", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-sparc64-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-sparc64-smp", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-sparc64-smp-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-ume", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-ume-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-virtual", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-virtual-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-xen", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-xen-2.6.22-16.61
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-386", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-386-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-generic", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-generic-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-openvz", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-openvz-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-rt", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-rt-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-server", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-server-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-virtual", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-virtual-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-xen", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-xen-2.6.24-23.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-386", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-386-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-686", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-686-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-amd64-generic", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-amd64-generic-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-amd64-k8", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-amd64-k8-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-amd64-server", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-amd64-server-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-amd64-xeon", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-amd64-xeon-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-k7", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-k7-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-powerpc", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-powerpc-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-powerpc-smp", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-powerpc-smp-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-powerpc64-smp", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-powerpc64-smp-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-server", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-server-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-server-bigiron", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-server-bigiron-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-sparc64", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-sparc64-2.6.15-53.75
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-53-sparc64-smp", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-53-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-53-sparc64-smp-2.6.15-53.75
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-386", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-386-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-cell", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-cell-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-generic", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-generic-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-powerpc", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-powerpc-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-powerpc-smp", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-powerpc-smp-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-powerpc64-smp", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-powerpc64-smp-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-rt", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-rt-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-server", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-server-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-sparc64", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-sparc64-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-sparc64-smp", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-sparc64-smp-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-ume", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-ume-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-virtual", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-virtual-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-xen", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-xen-2.6.22-16.61
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-386", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-386-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-generic", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-generic-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-openvz", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-openvz-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-rt", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-rt-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-server", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-server-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-virtual", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-virtual-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-xen", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-xen-2.6.24-23.48
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-386", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-386-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-generic", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-generic-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-server", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-server-2.6.22-16.61
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-virtual", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-virtual-2.6.22-16.61
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-23-386", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-23-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-23-386-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-23-generic", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-23-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-23-generic-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-23-server", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-23-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-23-server-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-23-virtual", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-23-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-23-virtual-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-kernel-devel", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-kernel-devel-2.6.24-23.48
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-libc-dev", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-libc-dev-2.6.24-23.48
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-53.75");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-53.75
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-source-2.6.22", pkgver: "2.6.22-16.61");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-source-2.6.22-2.6.22-16.61
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-source-2.6.24", pkgver: "2.6.24-23.48");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-source-2.6.24-2.6.24-23.48
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
