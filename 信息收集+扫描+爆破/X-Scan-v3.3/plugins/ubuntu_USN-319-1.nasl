# This script was automatically generated from the 319-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27895);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "319-1");
script_summary(english:"Linux kernel vulnerability");
script_name(english:"USN319-1 : Linux kernel vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
- linux-headers-2.6.15-26 
- linux-headers-2.6.15-26-386 
- linux-headers-2.6.15-26-686 
- linux-headers-2.6.15-26-amd64-generic 
- linux-headers-2.6.15-26-amd64-k8 
- linux-headers-2.6.15-26-amd64-server 
- linux-headers-2.6.15-26-amd64-xeon 
- linux-headers-2.6.15-26-k7 
- linux-headers-2.6.15-26-powerpc 
- linux-headers-2.6.15-26-powerpc-smp 
- linux-headers-2.6.15-26-powerpc64-smp 
- linux-headers-2.6.15-26-server 
- linux-headers
[...]');
script_set_attribute(attribute:'description', value: 'A race condition has been discovered in the file permission handling
of the /proc file system. A local attacker could exploit this to
execute arbitrary code with full root privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-26.45 (Ubuntu 6.06)
- linux-headers-2.6.15-26-2.6.15-26.45 (Ubuntu 6.06)
- linux-headers-2.6.15-26-386-2.6.15-26.45 (Ubuntu 6.06)
- linux-headers-2.6.15-26-686-2.6.15-26.45 (Ubuntu 6.06)
- linux-headers-2.6.15-26-amd64-generic-2.6.15-26.45 (Ubuntu 6.06)
- linux-headers-2.6.15-26-amd64-k8-2.6.15-26.45 (Ubuntu 6.06)
- linux-headers-2.6.15-26-amd64-server-2.6.15-26.45 (Ubuntu 6.06)
- linux-headers-2.6.15-26-amd64-xeon-2.6.15-26.45 (Ubuntu 6.06)
- linux-headers-2.6.15-26
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-3626");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-386", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-386-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-686", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-686-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-amd64-generic", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-amd64-generic-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-amd64-k8", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-amd64-k8-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-amd64-server", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-amd64-server-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-amd64-xeon", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-amd64-xeon-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-k7", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-k7-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-powerpc", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-powerpc-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-powerpc-smp", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-powerpc-smp-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-powerpc64-smp", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-powerpc64-smp-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-server", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-server-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-server-bigiron", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-server-bigiron-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-sparc64", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-sparc64-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-26-sparc64-smp", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-26-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-26-sparc64-smp-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-386", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-386-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-686", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-686-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-amd64-generic", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-amd64-generic-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-amd64-k8", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-amd64-k8-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-amd64-server", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-amd64-server-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-amd64-xeon", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-amd64-xeon-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-k7", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-k7-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-powerpc", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-powerpc-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-powerpc-smp", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-powerpc-smp-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-powerpc64-smp", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-powerpc64-smp-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-server", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-server-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-server-bigiron", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-server-bigiron-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-sparc64", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-sparc64-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-26-sparc64-smp", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-26-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-26-sparc64-smp-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-kernel-devel", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-kernel-devel-2.6.15-26.45
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-26.45");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-26.45
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
