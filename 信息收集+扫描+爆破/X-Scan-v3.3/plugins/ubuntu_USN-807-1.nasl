# This script was automatically generated from the 807-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40416);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "807-1");
script_summary(english:"linux, linux-source-2.6.15 vulnerabilities");
script_name(english:"USN807-1 : linux, linux-source-2.6.15 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
- linux-doc-2.6.24 
- linux-doc-2.6.27 
- linux-doc-2.6.28 
- linux-headers-2.6.15-54 
- linux-headers-2.6.15-54-386 
- linux-headers-2.6.15-54-686 
- linux-headers-2.6.15-54-amd64-generic 
- linux-headers-2.6.15-54-amd64-k8 
- linux-headers-2.6.15-54-amd64-server 
- linux-headers-2.6.15-54-amd64-xeon 
- linux-headers-2.6.15-54-k7 
- linux-headers-2.6.15-54-powerpc 
- linux-headers-2.6.15-54-powerpc-smp 
- linux-headers-2.6.15-54-powe
[...]');
script_set_attribute(attribute:'description', value: 'Michael Tokarev discovered that the RTL8169 network driver did not
correctly validate buffer sizes.  A remote attacker on the local network
could send specially traffic traffic that would crash the system or
potentially grant elevated privileges. (CVE-2009-1389)

Julien Tinnes and Tavis Ormandy discovered that when executing setuid
processes the kernel did not clear certain personality flags.  A local
attacker could exploit this to map the NULL memory page, causing other
vulnerabilities to become exploitable.  Ubuntu 6.06 was not affected.
(CVE-2009-1895)

Matt T. Yourst discovered that KVM did not correctly validate the
page table root.  A local attacker could exploit this to crash the
system, leading to a denial of service.  Ubuntu 6.06 was not affected.
(CVE-2009-2287)

Ramon de Carvalho Valle discovered that eCryptfs did not correctly
validate certain buffer sizes.  A local attacker could create specially
crafted eCryptfs files to crash the system or gain elevated privileges.
Ubuntu 6.06 was not affected
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-54.78 (Ubuntu 6.06)
- linux-doc-2.6.24-2.6.24-24.57 (Ubuntu 8.04)
- linux-doc-2.6.27-2.6.27-14.37 (Ubuntu 8.10)
- linux-doc-2.6.28-2.6.28-14.47 (Ubuntu 9.04)
- linux-headers-2.6.15-54-2.6.15-54.78 (Ubuntu 6.06)
- linux-headers-2.6.15-54-386-2.6.15-54.78 (Ubuntu 6.06)
- linux-headers-2.6.15-54-686-2.6.15-54.78 (Ubuntu 6.06)
- linux-headers-2.6.15-54-amd64-generic-2.6.15-54.78 (Ubuntu 6.06)
- linux-headers-2.6.15-54-amd64-k8-2.6.15-54.78 (Ubuntu 6.06)
- linux-headers-2
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1389","CVE-2009-1895","CVE-2009-2287","CVE-2009-2406","CVE-2009-2407");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-54.78
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-doc-2.6.24", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-doc-2.6.24-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-doc-2.6.27", pkgver: "2.6.27-14.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-doc-2.6.27-2.6.27-14.37
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-doc-2.6.28", pkgver: "2.6.28-14.47");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.28-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-doc-2.6.28-2.6.28-14.47
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-386", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-386-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-686", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-686-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-amd64-generic", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-amd64-generic-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-amd64-k8", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-amd64-k8-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-amd64-server", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-amd64-server-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-amd64-xeon", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-amd64-xeon-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-k7", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-k7-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-powerpc", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-powerpc-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-powerpc-smp", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-powerpc-smp-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-powerpc64-smp", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-powerpc64-smp-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-server", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-server-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-server-bigiron", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-server-bigiron-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-sparc64", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-sparc64-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-54-sparc64-smp", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-54-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-54-sparc64-smp-2.6.15-54.78
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-24", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-24-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-24-386", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-24-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-24-386-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-24-generic", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-24-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-24-generic-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-24-openvz", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-24-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-24-openvz-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-24-rt", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-24-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-24-rt-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-24-server", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-24-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-24-server-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-24-virtual", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-24-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-24-virtual-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-24-xen", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-24-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-24-xen-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-14", pkgver: "2.6.27-14.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-14-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-14-2.6.27-14.37
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-14-generic", pkgver: "2.6.27-14.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-14-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-14-generic-2.6.27-14.37
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-14-server", pkgver: "2.6.27-14.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-14-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-14-server-2.6.27-14.37
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-headers-2.6.28-14", pkgver: "2.6.28-14.47");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.28-14-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-headers-2.6.28-14-2.6.28-14.47
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-headers-2.6.28-14-generic", pkgver: "2.6.28-14.47");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.28-14-generic-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-headers-2.6.28-14-generic-2.6.28-14.47
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-headers-2.6.28-14-server", pkgver: "2.6.28-14.47");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.28-14-server-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-headers-2.6.28-14-server-2.6.28-14.47
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-386", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-386-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-686", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-686-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-amd64-generic", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-amd64-generic-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-amd64-k8", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-amd64-k8-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-amd64-server", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-amd64-server-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-amd64-xeon", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-amd64-xeon-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-k7", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-k7-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-powerpc", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-powerpc-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-powerpc-smp", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-powerpc-smp-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-powerpc64-smp", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-powerpc64-smp-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-server", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-server-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-server-bigiron", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-server-bigiron-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-sparc64", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-sparc64-2.6.15-54.78
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-54-sparc64-smp", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-54-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-54-sparc64-smp-2.6.15-54.78
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-24-386", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-24-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-24-386-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-24-generic", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-24-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-24-generic-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-24-openvz", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-24-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-24-openvz-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-24-rt", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-24-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-24-rt-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-24-server", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-24-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-24-server-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-24-virtual", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-24-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-24-virtual-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-24-xen", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-24-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-24-xen-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-14-generic", pkgver: "2.6.27-14.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-14-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-14-generic-2.6.27-14.37
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-14-server", pkgver: "2.6.27-14.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-14-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-14-server-2.6.27-14.37
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-14-virtual", pkgver: "2.6.27-14.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-14-virtual-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-14-virtual-2.6.27-14.37
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-image-2.6.28-14-generic", pkgver: "2.6.28-14.47");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.28-14-generic-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-image-2.6.28-14-generic-2.6.28-14.47
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-image-2.6.28-14-server", pkgver: "2.6.28-14.47");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.28-14-server-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-image-2.6.28-14-server-2.6.28-14.47
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-image-2.6.28-14-virtual", pkgver: "2.6.28-14.47");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.28-14-virtual-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-image-2.6.28-14-virtual-2.6.28-14.47
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-24-386", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-24-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-24-386-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-24-generic", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-24-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-24-generic-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-24-server", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-24-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-24-server-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-24-virtual", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-24-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-24-virtual-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-kernel-devel", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-kernel-devel-2.6.24-24.57
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-libc-dev", pkgver: "2.6.28-14.47");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-libc-dev-2.6.28-14.47
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-54.78");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-54.78
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-source-2.6.24", pkgver: "2.6.24-24.57");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-source-2.6.24-2.6.24-24.57
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-source-2.6.27", pkgver: "2.6.27-14.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-source-2.6.27-2.6.27-14.37
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-source-2.6.28", pkgver: "2.6.28-14.47");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.28-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-source-2.6.28-2.6.28-14.47
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
