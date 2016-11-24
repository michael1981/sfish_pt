# This script was automatically generated from the 509-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28113);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "509-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN509-1 : Linux kernel vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'A flaw in the sysfs_readdir function allowed a local user to cause a
denial of service by dereferencing a NULL pointer. (CVE-2007-3104)

A buffer overflow was discovered in the random number generator.  In
environments with granular assignment of root privileges, a local attacker
could gain additional privileges. (CVE-2007-3105)

A flaw was discovered in the usblcd driver.  A local attacker could cause
large amounts of kernel memory consumption, leading to a denial of service.
(CVE-2007-3513)

It was discovered that certain setuid-root processes did not correctly
reset process death signal handlers.  A local user could manipulate this
to send signals to processes they would not normally have access to.
(CVE-2007-3848)

The Direct Rendering Manager for the i915 driver could be made to write
to arbitrary memory locations.  An attacker with access to a running X11
session could send a specially crafted buffer and gain root privileges.
(CVE-2007-3851)

It was discovered that the aacraid SCSI driver did not corre
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.17-2.6.17.1-12.40 (Ubuntu 6.10)
- linux-headers-2.6.17-12-2.6.17.1-12.40 (Ubuntu 6.10)
- linux-headers-2.6.17-12-386-2.6.17.1-12.40 (Ubuntu 6.10)
- linux-headers-2.6.17-12-generic-2.6.17.1-12.40 (Ubuntu 6.10)
- linux-headers-2.6.17-12-powerpc-2.6.17.1-12.40 (Ubuntu 6.10)
- linux-headers-2.6.17-12-powerpc-smp-2.6.17.1-12.40 (Ubuntu 6.10)
- linux-headers-2.6.17-12-powerpc64-smp-2.6.17.1-12.40 (Ubuntu 6.10)
- linux-headers-2.6.17-12-server-2.6.17.1-12.40 (Ubuntu 6.10)
- linux-hea
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:S/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-3104","CVE-2007-3105","CVE-2007-3513","CVE-2007-3848","CVE-2007-3851","CVE-2007-4308");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "linux-doc-2.6.17", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-doc-2.6.17-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-386", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-386-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-generic", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-generic-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc-smp-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-powerpc64-smp-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-server", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-server-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-server-bigiron-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-sparc64-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-12-sparc64-smp-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-386", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-386-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-generic", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-generic-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc-smp-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-powerpc64-smp-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-server", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-server-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-server-bigiron-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-sparc64-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-12-sparc64-smp-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-386", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-386-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-generic", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-generic-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc-smp", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc-smp-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-powerpc64-smp", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-powerpc64-smp-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-server", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-server-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-server-bigiron", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-server-bigiron-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-sparc64", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-sparc64-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-12-sparc64-smp", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-12-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-12-sparc64-smp-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-kdump", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-kdump-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-kdump-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-kernel-devel", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-kernel-devel-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-libc-dev", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-libc-dev-2.6.17.1-12.40
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-source-2.6.17", pkgver: "2.6.17.1-12.40");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-source-2.6.17-2.6.17.1-12.40
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
