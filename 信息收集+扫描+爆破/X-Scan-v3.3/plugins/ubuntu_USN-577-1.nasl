# This script was automatically generated from the 577-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31092);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "577-1");
script_summary(english:"Linux kernel vulnerability");
script_name(english:"USN577-1 : Linux kernel vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.17 
- linux-doc-2.6.20 
- linux-doc-2.6.22 
- linux-headers-2.6.17-12 
- linux-headers-2.6.17-12-386 
- linux-headers-2.6.17-12-generic 
- linux-headers-2.6.17-12-powerpc 
- linux-headers-2.6.17-12-powerpc-smp 
- linux-headers-2.6.17-12-powerpc64-smp 
- linux-headers-2.6.17-12-server 
- linux-headers-2.6.17-12-server-bigiron 
- linux-headers-2.6.17-12-sparc64 
- linux-headers-2.6.17-12-sparc64-smp 
- linux-headers-2.6.20-16 
- linux-heade
[...]');
script_set_attribute(attribute:'description', value: 'Wojciech Purczynski discovered that the vmsplice system call did
not properly perform verification of user-memory pointers. A local
attacker could exploit this to overwrite arbitrary kernel memory
and gain root privileges. (CVE-2008-0600)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.17-2.6.17.1-12.44 (Ubuntu 6.10)
- linux-doc-2.6.20-2.6.20-16.35 (Ubuntu 7.04)
- linux-doc-2.6.22-2.6.22-14.52 (Ubuntu 7.10)
- linux-headers-2.6.17-12-2.6.17.1-12.44 (Ubuntu 6.10)
- linux-headers-2.6.17-12-386-2.6.17.1-12.44 (Ubuntu 6.10)
- linux-headers-2.6.17-12-generic-2.6.17.1-12.44 (Ubuntu 6.10)
- linux-headers-2.6.17-12-powerpc-2.6.17.1-12.44 (Ubuntu 6.10)
- linux-headers-2.6.17-12-powerpc-smp-2.6.17.1-12.44 (Ubuntu 6.10)
- linux-headers-2.6.17-12-powerpc64-smp-2.6.17.1-1
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-0600");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "linux-doc-2.6.17", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-doc-2.6.17-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-doc-2.6.20", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-doc-2.6.20-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-doc-2.6.22", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-doc-2.6.22-2.6.22-14.52
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-386", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-386-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-generic", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-generic-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc-smp-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc64-smp-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-server", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-server-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-server-bigiron-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-sparc64-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-sparc64-smp-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-386", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-386-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-generic", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-generic-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-lowlatency", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-lowlatency-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc-smp-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc64-smp-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-server", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-server-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-server-bigiron-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-sparc64", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-sparc64-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-sparc64-smp-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-386", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-386-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-cell", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-cell-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-generic", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-generic-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-powerpc", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-powerpc-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-powerpc-smp", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-powerpc-smp-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-powerpc64-smp", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-powerpc64-smp-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-rt", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-rt-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-server", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-server-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-sparc64", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-sparc64-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-sparc64-smp", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-sparc64-smp-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-ume", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-ume-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-virtual", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-virtual-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-14-xen", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-14-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-14-xen-2.6.22-14.52
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-386", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-386-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-generic", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-generic-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc-smp-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc64-smp-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-server", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-server-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-server-bigiron-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-sparc64-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-sparc64-smp-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-386", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-386-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-generic", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-generic-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-lowlatency", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-lowlatency-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc-smp-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc64-smp-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-server", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-server-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-server-bigiron-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-sparc64", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-sparc64-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-sparc64-smp-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-386", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-386-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-cell", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-cell-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-generic", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-generic-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-powerpc", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-powerpc-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-powerpc-smp", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-powerpc-smp-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-powerpc64-smp", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-powerpc64-smp-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-rt", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-rt-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-server", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-server-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-sparc64", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-sparc64-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-sparc64-smp", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-sparc64-smp-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-ume", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-ume-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-virtual", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-virtual-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-14-xen", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-14-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-14-xen-2.6.22-14.52
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-386", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-386-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-generic", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-generic-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc-smp-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc64-smp-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-server", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-server-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-server-bigiron-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-sparc64-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-sparc64-smp-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-386", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-386-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-generic", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-generic-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-lowlatency", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-lowlatency-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc-smp-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc64-smp-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-server", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-server-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-server-bigiron-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-sparc64", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-sparc64-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-sparc64-smp-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-14-386", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-14-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-14-386-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-14-generic", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-14-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-14-generic-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-14-server", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-14-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-14-server-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-14-virtual", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-14-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-14-virtual-2.6.22-14.52
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-kdump", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-kdump-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-kdump-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-kernel-devel", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-kernel-devel-2.6.22-14.52
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-libc-dev", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-libc-dev-2.6.22-14.52
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-source-2.6.17", pkgver: "2.6.17.1-12.44");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-source-2.6.17-2.6.17.1-12.44
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-source-2.6.20", pkgver: "2.6.20-16.35");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-source-2.6.20-2.6.20-16.35
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-source-2.6.22", pkgver: "2.6.22-14.52");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-source-2.6.22-2.6.22-14.52
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
