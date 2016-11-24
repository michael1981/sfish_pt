# This script was automatically generated from the 486-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28087);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "486-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN486-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.17 
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
- linux-image-2.6.17-12-386 
- linux-image-2.6.17-12-generic 
- linux-image-2.6.
[...]');
script_set_attribute(attribute:'description', value: 'The compat_sys_mount function allowed local users to cause a denial of
service when mounting a smbfs filesystem in compatibility mode.
(CVE-2006-7203)

The Omnikey CardMan 4040 driver (cm4040_cs) did not limit the size of
buffers passed to read() and write(). A local attacker could exploit
this to execute arbitrary code with kernel privileges. (CVE-2007-0005)

Due to a variable handling flaw in the  ipv6_getsockopt_sticky()
function a local attacker could exploit the getsockopt() calls to
read arbitrary kernel memory. This could disclose sensitive data.
(CVE-2007-1000)

Ilja van Sprundel discovered that Bluetooth setsockopt calls could leak
kernel memory contents via an uninitialized stack buffer.  A local 
attacker could exploit this flaw to view sensitive kernel information.
(CVE-2007-1353)

A flaw was discovered in the handling of netlink messages.  Local
attackers could cause infinite recursion leading to a denial of service.
(CVE-2007-1861)

A flaw was discovered in the IPv6 stack\'s handling of type 0 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.17-2.6.17.1-12.39 (Ubuntu 6.10)
- linux-headers-2.6.17-12-2.6.17.1-12.39 (Ubuntu 6.10)
- linux-headers-2.6.17-12-386-2.6.17.1-12.39 (Ubuntu 6.10)
- linux-headers-2.6.17-12-generic-2.6.17.1-12.39 (Ubuntu 6.10)
- linux-headers-2.6.17-12-powerpc-2.6.17.1-12.39 (Ubuntu 6.10)
- linux-headers-2.6.17-12-powerpc-smp-2.6.17.1-12.39 (Ubuntu 6.10)
- linux-headers-2.6.17-12-powerpc64-smp-2.6.17.1-12.39 (Ubuntu 6.10)
- linux-headers-2.6.17-12-server-2.6.17.1-12.39 (Ubuntu 6.10)
- linux-hea
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-7203","CVE-2007-0005","CVE-2007-1000","CVE-2007-1353","CVE-2007-1861","CVE-2007-2242","CVE-2007-2453","CVE-2007-2525","CVE-2007-2875","CVE-2007-2876","CVE-2007-2878");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "linux-doc-2.6.17", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-doc-2.6.17-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-386", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-386-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-generic", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-generic-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc-smp-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc64-smp-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-server", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-server-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-server-bigiron-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-sparc64-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-sparc64-smp-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-386", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-386-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-generic", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-generic-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc-smp-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc64-smp-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-server", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-server-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-server-bigiron-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-sparc64-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-sparc64-smp-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-386", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-386-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-generic", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-generic-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc-smp-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc64-smp-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-server", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-server-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-server-bigiron-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-sparc64-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-sparc64-smp-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-kdump", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-kdump-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-kdump-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-kernel-devel", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-kernel-devel-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-libc-dev", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-libc-dev-2.6.17.1-12.39
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-source-2.6.17", pkgver: "2.6.17.1-12.39");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-source-2.6.17-2.6.17.1-12.39
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
