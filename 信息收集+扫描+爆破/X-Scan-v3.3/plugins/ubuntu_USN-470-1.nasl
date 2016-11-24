# This script was automatically generated from the 470-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28071);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "470-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN470-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.20 
- linux-headers-2.6.20-16 
- linux-headers-2.6.20-16-386 
- linux-headers-2.6.20-16-generic 
- linux-headers-2.6.20-16-lowlatency 
- linux-headers-2.6.20-16-powerpc 
- linux-headers-2.6.20-16-powerpc-smp 
- linux-headers-2.6.20-16-powerpc64-smp 
- linux-headers-2.6.20-16-server 
- linux-headers-2.6.20-16-server-bigiron 
- linux-headers-2.6.20-16-sparc64 
- linux-headers-2.6.20-16-sparc64-smp 
- linux-image-2.6.20-16-386 
- linux-image
[...]');
script_set_attribute(attribute:'description', value: 'USN-464-1 fixed several vulnerabilities in the Linux kernel.  Some
additional code changes were accidentally included in the Feisty update
which caused trouble for some people who were not using UUID-based
filesystem mounts.  These changes have been reverted.  We apologize for
the inconvenience.  For more information see:
 https://launchpad.net/bugs/117314
 https://wiki.ubuntu.com/UsingUUID

Ilja van Sprundel discovered that Bluetooth setsockopt calls could leak
kernel memory contents via an uninitialized stack buffer.  A local
attacker could exploit this flaw to view sensitive kernel information.
(CVE-2007-1353)

The GEODE-AES driver did not correctly initialize its encryption key.
Any data encrypted using this type of device would be easily compromised.
(CVE-2007-2451)

The random number generator was hashing a subset of the available
entropy, leading to slightly less random numbers.  Additionally, systems
without an entropy source would be seeded with the same inputs at boot
time, leading to a repeatable 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.20-2.6.20-16.29 (Ubuntu 7.04)
- linux-headers-2.6.20-16-2.6.20-16.29 (Ubuntu 7.04)
- linux-headers-2.6.20-16-386-2.6.20-16.29 (Ubuntu 7.04)
- linux-headers-2.6.20-16-generic-2.6.20-16.29 (Ubuntu 7.04)
- linux-headers-2.6.20-16-lowlatency-2.6.20-16.29 (Ubuntu 7.04)
- linux-headers-2.6.20-16-powerpc-2.6.20-16.29 (Ubuntu 7.04)
- linux-headers-2.6.20-16-powerpc-smp-2.6.20-16.29 (Ubuntu 7.04)
- linux-headers-2.6.20-16-powerpc64-smp-2.6.20-16.29 (Ubuntu 7.04)
- linux-headers-2.6.20-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2007-1353","CVE-2007-2451","CVE-2007-2453");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "linux-doc-2.6.20", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-doc-2.6.20-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-386", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-386-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-generic", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-generic-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-lowlatency", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-lowlatency-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc-smp-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc64-smp-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-server", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-server-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-server-bigiron-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-sparc64", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-sparc64-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-sparc64-smp-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-386", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-386-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-generic", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-generic-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-lowlatency", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-lowlatency-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc-smp-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc64-smp-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-server", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-server-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-server-bigiron-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-sparc64", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-sparc64-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-sparc64-smp-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-386", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-386-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-generic", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-generic-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-lowlatency", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-lowlatency-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc-smp-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc64-smp-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-server", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-server-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-server-bigiron-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-sparc64", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-sparc64-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-sparc64-smp-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-kernel-devel", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-kernel-devel-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-libc-dev", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-libc-dev-2.6.20-16.29
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-source-2.6.20", pkgver: "2.6.20-16.29");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-source-2.6.20-2.6.20-16.29
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
