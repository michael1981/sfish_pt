# This script was automatically generated from the 852-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42209);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "852-1");
script_summary(english:"linux, linux-source-2.6.15 vulnerabilities");
script_name(english:"USN852-1 : linux, linux-source-2.6.15 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
- linux-doc-2.6.24 
- linux-doc-2.6.27 
- linux-doc-2.6.28 
- linux-headers-2.6.15-55 
- linux-headers-2.6.15-55-386 
- linux-headers-2.6.15-55-686 
- linux-headers-2.6.15-55-amd64-generic 
- linux-headers-2.6.15-55-amd64-k8 
- linux-headers-2.6.15-55-amd64-server 
- linux-headers-2.6.15-55-amd64-xeon 
- linux-headers-2.6.15-55-k7 
- linux-headers-2.6.15-55-powerpc 
- linux-headers-2.6.15-55-powerpc-smp 
- linux-headers-2.6.15-55-powe
[...]');
script_set_attribute(attribute:'description', value: 'Solar Designer discovered that the z90crypt driver did not correctly
check capabilities.  A local attacker could exploit this to shut down
the device, leading to a denial of service.  Only affected Ubuntu 6.06.
(CVE-2009-1883)

Michael Buesch discovered that the SGI GRU driver did not correctly check
the length when setting options.  A local attacker could exploit this
to write to the kernel stack, leading to root privilege escalation or
a denial of service.  Only affected Ubuntu 8.10 and 9.04. (CVE-2009-2584)

It was discovered that SELinux did not fully implement the mmap_min_addr
restrictions.  A local attacker could exploit this to allocate the
NULL memory page which could lead to further attacks against kernel
NULL-dereference vulnerabilities.  Ubuntu 6.06 was not affected.
(CVE-2009-2695)

Cagri Coltekin discovered that the UDP stack did not correctly handle
certain flags.  A local user could send specially crafted commands and
traffic to gain root privileges or crash the systeam, leading to a denial
o
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-55.80 (Ubuntu 6.06)
- linux-doc-2.6.24-2.6.24-25.63 (Ubuntu 8.04)
- linux-doc-2.6.27-2.6.27-15.43 (Ubuntu 8.10)
- linux-doc-2.6.28-2.6.28-16.55 (Ubuntu 9.04)
- linux-headers-2.6.15-55-2.6.15-55.80 (Ubuntu 6.06)
- linux-headers-2.6.15-55-386-2.6.15-55.80 (Ubuntu 6.06)
- linux-headers-2.6.15-55-686-2.6.15-55.80 (Ubuntu 6.06)
- linux-headers-2.6.15-55-amd64-generic-2.6.15-55.80 (Ubuntu 6.06)
- linux-headers-2.6.15-55-amd64-k8-2.6.15-55.80 (Ubuntu 6.06)
- linux-headers-2
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2009-1883","CVE-2009-2584","CVE-2009-2695","CVE-2009-2698","CVE-2009-2767","CVE-2009-2846","CVE-2009-2847","CVE-2009-2848","CVE-2009-2849","CVE-2009-2903","CVE-2009-2908","CVE-2009-3001","CVE-2009-3002","CVE-2009-3238","CVE-2009-3286","CVE-2009-3288","CVE-2009-3290");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-55.80
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-doc-2.6.24", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-doc-2.6.24-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-doc-2.6.27", pkgver: "2.6.27-15.43");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-doc-2.6.27-2.6.27-15.43
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-doc-2.6.28", pkgver: "2.6.28-16.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.28-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-doc-2.6.28-2.6.28-16.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-386", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-386-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-686", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-686-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-amd64-generic", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-amd64-generic-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-amd64-k8", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-amd64-k8-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-amd64-server", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-amd64-server-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-amd64-xeon", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-amd64-xeon-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-k7", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-k7-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-powerpc", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-powerpc-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-powerpc-smp", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-powerpc-smp-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-powerpc64-smp", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-powerpc64-smp-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-server", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-server-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-server-bigiron", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-server-bigiron-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-sparc64", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-sparc64-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-55-sparc64-smp", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-55-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-55-sparc64-smp-2.6.15-55.80
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-25", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-25-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-25-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-25-386", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-25-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-25-386-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-25-generic", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-25-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-25-generic-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-25-openvz", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-25-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-25-openvz-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-25-rt", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-25-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-25-rt-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-25-server", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-25-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-25-server-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-25-virtual", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-25-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-25-virtual-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-25-xen", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-25-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-25-xen-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-15", pkgver: "2.6.27-15.43");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-15-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-15-2.6.27-15.43
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-15-generic", pkgver: "2.6.27-15.43");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-15-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-15-generic-2.6.27-15.43
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-15-server", pkgver: "2.6.27-15.43");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-15-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-15-server-2.6.27-15.43
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-headers-2.6.28-16", pkgver: "2.6.28-16.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.28-16-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-headers-2.6.28-16-2.6.28-16.55
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-headers-2.6.28-16-generic", pkgver: "2.6.28-16.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.28-16-generic-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-headers-2.6.28-16-generic-2.6.28-16.55
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-headers-2.6.28-16-server", pkgver: "2.6.28-16.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.28-16-server-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-headers-2.6.28-16-server-2.6.28-16.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-386", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-386-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-686", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-686-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-amd64-generic", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-amd64-generic-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-amd64-k8", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-amd64-k8-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-amd64-server", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-amd64-server-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-amd64-xeon", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-amd64-xeon-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-k7", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-k7-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-powerpc", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-powerpc-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-powerpc-smp", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-powerpc-smp-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-powerpc64-smp", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-powerpc64-smp-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-server", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-server-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-server-bigiron", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-server-bigiron-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-sparc64", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-sparc64-2.6.15-55.80
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-55-sparc64-smp", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-55-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-55-sparc64-smp-2.6.15-55.80
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-25-386", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-25-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-25-386-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-25-generic", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-25-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-25-generic-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-25-openvz", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-25-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-25-openvz-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-25-rt", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-25-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-25-rt-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-25-server", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-25-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-25-server-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-25-virtual", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-25-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-25-virtual-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-25-xen", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-25-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-25-xen-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-15-generic", pkgver: "2.6.27-15.43");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-15-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-15-generic-2.6.27-15.43
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-15-server", pkgver: "2.6.27-15.43");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-15-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-15-server-2.6.27-15.43
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-15-virtual", pkgver: "2.6.27-15.43");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-15-virtual-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-15-virtual-2.6.27-15.43
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-image-2.6.28-16-generic", pkgver: "2.6.28-16.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.28-16-generic-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-image-2.6.28-16-generic-2.6.28-16.55
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-image-2.6.28-16-server", pkgver: "2.6.28-16.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.28-16-server-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-image-2.6.28-16-server-2.6.28-16.55
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-image-2.6.28-16-virtual", pkgver: "2.6.28-16.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.28-16-virtual-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-image-2.6.28-16-virtual-2.6.28-16.55
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-25-386", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-25-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-25-386-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-25-generic", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-25-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-25-generic-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-25-server", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-25-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-25-server-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-25-virtual", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-25-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-25-virtual-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-kernel-devel", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-kernel-devel-2.6.24-25.63
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-libc-dev", pkgver: "2.6.28-16.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-libc-dev-2.6.28-16.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-55.80");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-55.80
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-source-2.6.24", pkgver: "2.6.24-25.63");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-source-2.6.24-2.6.24-25.63
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-source-2.6.27", pkgver: "2.6.27-15.43");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-source-2.6.27-2.6.27-15.43
');
}
found = ubuntu_check(osver: "9.04", pkgname: "linux-source-2.6.28", pkgver: "2.6.28-16.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.28-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to linux-source-2.6.28-2.6.28-16.55
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
