# This script was automatically generated from the 518-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28123);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "518-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN518-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
- linux-doc-2.6.17 
- linux-doc-2.6.20 
- linux-headers-2.6.15-29 
- linux-headers-2.6.15-29-386 
- linux-headers-2.6.15-29-686 
- linux-headers-2.6.15-29-amd64-generic 
- linux-headers-2.6.15-29-amd64-k8 
- linux-headers-2.6.15-29-amd64-server 
- linux-headers-2.6.15-29-amd64-xeon 
- linux-headers-2.6.15-29-k7 
- linux-headers-2.6.15-29-powerpc 
- linux-headers-2.6.15-29-powerpc-smp 
- linux-headers-2.6.15-29-powerpc64-smp 
- linux-h
[...]');
script_set_attribute(attribute:'description', value: 'Evan Teran discovered that the Linux kernel ptrace routines did not
correctly handle certain requests robustly.  Local attackers could exploit
this to crash the system, causing a denial of service.  (CVE-2007-3731)

It was discovered that hugetlb kernels on PowerPC systems did not prevent
the stack from colliding with reserved kernel memory.  Local attackers
could exploit this and crash the system, causing a denial of service.
(CVE-2007-3739)

It was discovered that certain CIFS filesystem actions did not honor
the umask of a process.  Local attackers could exploit this to gain
additional privileges. (CVE-2007-3740)

Wojciech Purczynski discovered that the Linux kernel ia32 syscall
emulation in x86_64 kernels did not correctly clear the high bits of
registers.  Local attackers could exploit this to gain root privileges.
(CVE-2007-4573)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-29.60 (Ubuntu 6.06)
- linux-doc-2.6.17-2.6.17.1-12.41 (Ubuntu 6.10)
- linux-doc-2.6.20-2.6.20-16.32 (Ubuntu 7.04)
- linux-headers-2.6.15-29-2.6.15-29.60 (Ubuntu 6.06)
- linux-headers-2.6.15-29-386-2.6.15-29.60 (Ubuntu 6.06)
- linux-headers-2.6.15-29-686-2.6.15-29.60 (Ubuntu 6.06)
- linux-headers-2.6.15-29-amd64-generic-2.6.15-29.60 (Ubuntu 6.06)
- linux-headers-2.6.15-29-amd64-k8-2.6.15-29.60 (Ubuntu 6.06)
- linux-headers-2.6.15-29-amd64-server-2.6.15-29.60 (Ubuntu 6
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-3731","CVE-2007-3739","CVE-2007-3740","CVE-2007-4573");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-doc-2.6.17", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-doc-2.6.17-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-doc-2.6.20", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-doc-2.6.20-2.6.20-16.32
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-386", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-386-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-686", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-686-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-amd64-generic", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-amd64-generic-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-amd64-k8", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-amd64-k8-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-amd64-server", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-amd64-server-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-amd64-xeon", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-amd64-xeon-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-k7", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-k7-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-powerpc", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-powerpc-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-powerpc-smp", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-powerpc-smp-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-powerpc64-smp", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-powerpc64-smp-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-server", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-server-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-server-bigiron", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-server-bigiron-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-sparc64", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-sparc64-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-sparc64-smp", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-sparc64-smp-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-386", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-386-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-generic", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-generic-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc-smp-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc64-smp-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-server", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-server-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-server-bigiron-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-sparc64-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-sparc64-smp-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-386", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-386-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-generic", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-generic-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-lowlatency", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-lowlatency-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc-smp-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc64-smp-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-server", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-server-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-server-bigiron-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-sparc64", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-sparc64-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-sparc64-smp-2.6.20-16.32
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-386", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-386-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-686", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-686-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-amd64-generic", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-amd64-generic-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-amd64-k8", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-amd64-k8-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-amd64-server", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-amd64-server-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-amd64-xeon", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-amd64-xeon-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-k7", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-k7-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-powerpc", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-powerpc-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-powerpc-smp", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-powerpc-smp-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-powerpc64-smp", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-powerpc64-smp-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-server", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-server-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-server-bigiron", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-server-bigiron-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-sparc64", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-sparc64-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-sparc64-smp", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-sparc64-smp-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-386", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-386-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-generic", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-generic-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc-smp-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc64-smp-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-server", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-server-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-server-bigiron-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-sparc64-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-sparc64-smp-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-386", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-386-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-generic", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-generic-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-lowlatency", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-lowlatency-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc-smp-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc64-smp-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-server", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-server-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-server-bigiron-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-sparc64", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-sparc64-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-sparc64-smp-2.6.20-16.32
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-386", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-386-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-generic", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-generic-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc-smp-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc64-smp-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-server", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-server-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-server-bigiron-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-sparc64-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-sparc64-smp-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-386", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-386-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-generic", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-generic-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-lowlatency", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-lowlatency-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc-smp-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc64-smp-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-server", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-server-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-server-bigiron-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-sparc64", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-sparc64-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-sparc64-smp-2.6.20-16.32
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-kdump", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-kdump-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-kdump-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-kernel-devel", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-kernel-devel-2.6.20-16.32
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-libc-dev", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-libc-dev-2.6.20-16.32
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-29.60");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-29.60
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-source-2.6.17", pkgver: "2.6.17.1-12.41");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-source-2.6.17-2.6.17.1-12.41
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-source-2.6.20", pkgver: "2.6.20-16.32");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-source-2.6.20-2.6.20-16.32
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
