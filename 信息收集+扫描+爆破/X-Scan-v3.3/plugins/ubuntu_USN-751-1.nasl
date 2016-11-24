# This script was automatically generated from the 751-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37337);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "751-1");
script_summary(english:"linux, linux-source-2.6.22 vulnerabilities");
script_name(english:"USN751-1 : linux, linux-source-2.6.22 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.22 
- linux-doc-2.6.24 
- linux-doc-2.6.27 
- linux-headers-2.6.22-16 
- linux-headers-2.6.22-16-386 
- linux-headers-2.6.22-16-cell 
- linux-headers-2.6.22-16-generic 
- linux-headers-2.6.22-16-powerpc 
- linux-headers-2.6.22-16-powerpc-smp 
- linux-headers-2.6.22-16-powerpc64-smp 
- linux-headers-2.6.22-16-rt 
- linux-headers-2.6.22-16-server 
- linux-headers-2.6.22-16-sparc64 
- linux-headers-2.6.22-16-sparc64-smp 
- linux-headers-2.6.
[...]');
script_set_attribute(attribute:'description', value: 'NFS did not correctly handle races between fcntl and interrupts. A local
attacker on an NFS mount could consume unlimited kernel memory, leading to
a denial of service. Ubuntu 8.10 was not affected. (CVE-2008-4307)

Sparc syscalls did not correctly check mmap regions. A local attacker
could cause a system panic, leading to a denial of service. Ubuntu 8.10
was not affected. (CVE-2008-6107)

In certain situations, cloned processes were able to send signals to parent
processes, crossing privilege boundaries. A local attacker could send
arbitrary signals to parent processes, leading to a denial of service.
(CVE-2009-0028)

The kernel keyring did not free memory correctly. A local attacker could
consume unlimited kernel memory, leading to a denial of service.
(CVE-2009-0031)

The SCTP stack did not correctly validate FORWARD-TSN packets. A remote
attacker could send specially crafted SCTP traffic causing a system crash,
leading to a denial of service. (CVE-2009-0065)

The eCryptfs filesystem did not correctly han
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.22-2.6.22-16.62 (Ubuntu 7.10)
- linux-doc-2.6.24-2.6.24-23.52 (Ubuntu 8.04)
- linux-doc-2.6.27-2.6.27-11.31 (Ubuntu 8.10)
- linux-headers-2.6.22-16-2.6.22-16.62 (Ubuntu 7.10)
- linux-headers-2.6.22-16-386-2.6.22-16.62 (Ubuntu 7.10)
- linux-headers-2.6.22-16-cell-2.6.22-16.62 (Ubuntu 7.10)
- linux-headers-2.6.22-16-generic-2.6.22-16.62 (Ubuntu 7.10)
- linux-headers-2.6.22-16-powerpc-2.6.22-16.62 (Ubuntu 7.10)
- linux-headers-2.6.22-16-powerpc-smp-2.6.22-16.62 (Ubuntu 7.10)
- li
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-4307","CVE-2008-6107","CVE-2009-0028","CVE-2009-0031","CVE-2009-0065","CVE-2009-0269","CVE-2009-0322","CVE-2009-0605","CVE-2009-0675","CVE-2009-0676","CVE-2009-0745","CVE-2009-0746","CVE-2009-0747","CVE-2009-0748","CVE-2009-0834","CVE-2009-0835","CVE-2009-0859","CVE-2009-1046");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "linux-doc-2.6.22", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-doc-2.6.22-2.6.22-16.62
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-doc-2.6.24", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-doc-2.6.24-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-doc-2.6.27", pkgver: "2.6.27-11.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-doc-2.6.27-2.6.27-11.31
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-386", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-386-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-cell", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-cell-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-generic", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-generic-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-powerpc", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-powerpc-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-powerpc-smp", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-powerpc-smp-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-powerpc64-smp", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-powerpc64-smp-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-rt", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-rt-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-server", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-server-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-sparc64", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-sparc64-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-sparc64-smp", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-sparc64-smp-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-ume", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-ume-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-virtual", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-virtual-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-16-xen", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-16-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-16-xen-2.6.22-16.62
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-386", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-386-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-generic", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-generic-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-openvz", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-openvz-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-rt", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-rt-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-server", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-server-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-virtual", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-virtual-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-23-xen", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-23-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-23-xen-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-11", pkgver: "2.6.27-11.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-11-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-11-2.6.27-11.31
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-11-generic", pkgver: "2.6.27-11.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-11-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-11-generic-2.6.27-11.31
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-11-server", pkgver: "2.6.27-11.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-11-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-11-server-2.6.27-11.31
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-386", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-386-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-cell", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-cell-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-generic", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-generic-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-powerpc", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-powerpc-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-powerpc-smp", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-powerpc-smp-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-powerpc64-smp", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-powerpc64-smp-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-rt", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-rt-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-server", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-server-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-sparc64", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-sparc64-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-sparc64-smp", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-sparc64-smp-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-ume", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-ume-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-virtual", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-virtual-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-16-xen", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-16-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-16-xen-2.6.22-16.62
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-386", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-386-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-generic", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-generic-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-openvz", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-openvz-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-rt", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-rt-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-server", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-server-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-virtual", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-virtual-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-23-xen", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-23-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-23-xen-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-11-generic", pkgver: "2.6.27-11.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-11-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-11-generic-2.6.27-11.31
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-11-server", pkgver: "2.6.27-11.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-11-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-11-server-2.6.27-11.31
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-11-virtual", pkgver: "2.6.27-11.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-11-virtual-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-11-virtual-2.6.27-11.31
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-386", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-386-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-generic", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-generic-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-server", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-server-2.6.22-16.62
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-16-virtual", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-16-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-16-virtual-2.6.22-16.62
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-23-386", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-23-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-23-386-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-23-generic", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-23-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-23-generic-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-23-server", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-23-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-23-server-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-23-virtual", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-23-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-23-virtual-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-kernel-devel", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-kernel-devel-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-libc-dev", pkgver: "2.6.27-11.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-libc-dev-2.6.27-11.31
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-source-2.6.22", pkgver: "2.6.22-16.62");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-source-2.6.22-2.6.22-16.62
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-source-2.6.24", pkgver: "2.6.24-23.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-source-2.6.24-2.6.24-23.52
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-source-2.6.27", pkgver: "2.6.27-11.31");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-source-2.6.27-2.6.27-11.31
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
