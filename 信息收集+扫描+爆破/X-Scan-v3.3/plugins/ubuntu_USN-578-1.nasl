# This script was automatically generated from the 578-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31093);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "578-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN578-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
- linux-headers-2.6.15-51 
- linux-headers-2.6.15-51-386 
- linux-headers-2.6.15-51-686 
- linux-headers-2.6.15-51-amd64-generic 
- linux-headers-2.6.15-51-amd64-k8 
- linux-headers-2.6.15-51-amd64-server 
- linux-headers-2.6.15-51-amd64-xeon 
- linux-headers-2.6.15-51-k7 
- linux-headers-2.6.15-51-powerpc 
- linux-headers-2.6.15-51-powerpc-smp 
- linux-headers-2.6.15-51-powerpc64-smp 
- linux-headers-2.6.15-51-server 
- linux-headers
[...]');
script_set_attribute(attribute:'description', value: 'The minix filesystem did not properly validate certain filesystem
values. If a local attacker could trick the system into attempting
to mount a corrupted minix filesystem, the kernel could be made to
hang for long periods of time, resulting in a denial of service.
(CVE-2006-6058)

Alexander Schulze discovered that the skge driver does not properly
use the spin_lock and spin_unlock functions. Remote attackers could
exploit this by sending a flood of network traffic and cause a denial
of service (crash). (CVE-2006-7229)

Hugh Dickins discovered that hugetlbfs performed certain prio_tree
calculations using HPAGE_SIZE instead of PAGE_SIZE. A local user
could exploit this and cause a denial of service via kernel panic.
(CVE-2007-4133)

Chris Evans discovered an issue with certain drivers that use the
ieee80211_rx function. Remote attackers could send a crafted 802.11
frame and cause a denial of service via crash. (CVE-2007-4997)

Alex Smith discovered an issue with the pwc driver for certain webcam
devices. A loc
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-51.66 (Ubuntu 6.06)
- linux-headers-2.6.15-51-2.6.15-51.66 (Ubuntu 6.06)
- linux-headers-2.6.15-51-386-2.6.15-51.66 (Ubuntu 6.06)
- linux-headers-2.6.15-51-686-2.6.15-51.66 (Ubuntu 6.06)
- linux-headers-2.6.15-51-amd64-generic-2.6.15-51.66 (Ubuntu 6.06)
- linux-headers-2.6.15-51-amd64-k8-2.6.15-51.66 (Ubuntu 6.06)
- linux-headers-2.6.15-51-amd64-server-2.6.15-51.66 (Ubuntu 6.06)
- linux-headers-2.6.15-51-amd64-xeon-2.6.15-51.66 (Ubuntu 6.06)
- linux-headers-2.6.15-51
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-6058","CVE-2006-7229","CVE-2007-4133","CVE-2007-4997","CVE-2007-5093","CVE-2007-5500","CVE-2007-6063","CVE-2007-6151","CVE-2007-6206","CVE-2007-6417","CVE-2008-0001");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-386", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-386-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-686", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-686-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-amd64-generic", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-amd64-generic-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-amd64-k8", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-amd64-k8-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-amd64-server", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-amd64-server-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-amd64-xeon", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-amd64-xeon-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-k7", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-k7-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-powerpc", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-powerpc-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-powerpc-smp", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-powerpc-smp-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-powerpc64-smp", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-powerpc64-smp-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-server", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-server-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-server-bigiron", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-server-bigiron-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-sparc64", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-sparc64-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-51-sparc64-smp", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-51-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-51-sparc64-smp-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-386", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-386-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-686", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-686-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-amd64-generic", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-amd64-generic-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-amd64-k8", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-amd64-k8-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-amd64-server", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-amd64-server-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-amd64-xeon", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-amd64-xeon-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-k7", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-k7-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-powerpc", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-powerpc-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-powerpc-smp", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-powerpc-smp-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-powerpc64-smp", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-powerpc64-smp-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-server", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-server-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-server-bigiron", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-server-bigiron-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-sparc64", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-sparc64-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-51-sparc64-smp", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-51-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-51-sparc64-smp-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-kernel-devel", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-kernel-devel-2.6.15-51.66
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-51.66");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-51.66
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
