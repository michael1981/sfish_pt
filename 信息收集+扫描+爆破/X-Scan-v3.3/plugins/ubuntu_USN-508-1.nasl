# This script was automatically generated from the 508-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28112);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "508-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN508-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
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
- linux-headers-2.6.15-29-server 
- linux-headers
[...]');
script_set_attribute(attribute:'description', value: 'A buffer overflow was discovered in the Moxa serial driver.  Local
attackers could execute arbitrary code and gain root privileges.
(CVE-2005-0504)

A flaw was discovered in the IPv6 stack\'s handling of type 0 route headers.
By sending a specially crafted IPv6 packet, a remote attacker could cause
a denial of service between two IPv6 hosts. (CVE-2007-2242)

A flaw in the sysfs_readdir function allowed a local user to cause a
denial of service by dereferencing a NULL pointer. (CVE-2007-3104)

A buffer overflow was discovered in the random number generator.  In
environments with granular assignment of root privileges, a local attacker
could gain additional privileges. (CVE-2007-3105)

It was discovered that certain setuid-root processes did not correctly
reset process death signal handlers.  A local user could manipulate this
to send signals to processes they would not normally have access to.
(CVE-2007-3848)

It was discovered that the aacraid SCSI driver did not correctly check
permissions on certain ioctls
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-29.58 (Ubuntu 6.06)
- linux-headers-2.6.15-29-2.6.15-29.58 (Ubuntu 6.06)
- linux-headers-2.6.15-29-386-2.6.15-29.58 (Ubuntu 6.06)
- linux-headers-2.6.15-29-686-2.6.15-29.58 (Ubuntu 6.06)
- linux-headers-2.6.15-29-amd64-generic-2.6.15-29.58 (Ubuntu 6.06)
- linux-headers-2.6.15-29-amd64-k8-2.6.15-29.58 (Ubuntu 6.06)
- linux-headers-2.6.15-29-amd64-server-2.6.15-29.58 (Ubuntu 6.06)
- linux-headers-2.6.15-29-amd64-xeon-2.6.15-29.58 (Ubuntu 6.06)
- linux-headers-2.6.15-29
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2005-0504","CVE-2007-2242","CVE-2007-3104","CVE-2007-3105","CVE-2007-3848","CVE-2007-4308");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-386", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-386-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-686", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-686-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-amd64-generic", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-amd64-generic-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-amd64-k8", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-amd64-k8-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-amd64-server", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-amd64-server-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-amd64-xeon", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-amd64-xeon-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-k7", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-k7-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-powerpc", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-powerpc-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-powerpc-smp", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-powerpc-smp-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-powerpc64-smp", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-powerpc64-smp-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-server", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-server-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-server-bigiron", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-server-bigiron-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-sparc64", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-sparc64-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-29-sparc64-smp", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-29-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-29-sparc64-smp-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-386", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-386-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-686", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-686-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-amd64-generic", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-amd64-generic-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-amd64-k8", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-amd64-k8-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-amd64-server", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-amd64-server-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-amd64-xeon", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-amd64-xeon-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-k7", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-k7-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-powerpc", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-powerpc-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-powerpc-smp", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-powerpc-smp-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-powerpc64-smp", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-powerpc64-smp-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-server", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-server-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-server-bigiron", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-server-bigiron-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-sparc64", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-sparc64-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-29-sparc64-smp", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-29-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-29-sparc64-smp-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-kernel-devel", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-kernel-devel-2.6.15-29.58
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-29.58");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-29.58
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
