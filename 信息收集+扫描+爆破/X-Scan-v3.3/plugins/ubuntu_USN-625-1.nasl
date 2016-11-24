# This script was automatically generated from the 625-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33531);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "625-1");
script_summary(english:"linux, linux-source-2.6.15/20/22 vulnerabilities");
script_name(english:"USN625-1 : linux, linux-source-2.6.15/20/22 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
- linux-doc-2.6.20 
- linux-doc-2.6.22 
- linux-doc-2.6.24 
- linux-headers-2.6.15-52 
- linux-headers-2.6.15-52-386 
- linux-headers-2.6.15-52-686 
- linux-headers-2.6.15-52-amd64-generic 
- linux-headers-2.6.15-52-amd64-k8 
- linux-headers-2.6.15-52-amd64-server 
- linux-headers-2.6.15-52-amd64-xeon 
- linux-headers-2.6.15-52-k7 
- linux-headers-2.6.15-52-powerpc 
- linux-headers-2.6.15-52-powerpc-smp 
- linux-headers-2.6.15-52-powe
[...]');
script_set_attribute(attribute:'description', value: 'Dirk Nehring discovered that the IPsec protocol stack did not correctly
handle fragmented ESP packets. A remote attacker could exploit this to
crash the system, leading to a denial of service. (CVE-2007-6282)

Johannes Bauer discovered that the 64bit kernel did not correctly handle
hrtimer updates. A local attacker could request a large expiration value
and cause the system to hang, leading to a denial of service.
(CVE-2007-6712)

Tavis Ormandy discovered that the ia32 emulation under 64bit kernels did
not fully clear uninitialized data. A local attacker could read private
kernel memory, leading to a loss of privacy. (CVE-2008-0598)

Jan Kratochvil discovered that PTRACE did not correctly handle certain
calls when running under 64bit kernels. A local attacker could exploit this
to crash the system, leading to a denial of service. (CVE-2008-1615)

Wei Wang discovered that the ASN.1 decoding routines in CIFS and SNMP NAT
did not correctly handle certain length values. Remote attackers could
exploit this to exe
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-52.69 (Ubuntu 6.06)
- linux-doc-2.6.20-2.6.20-17.37 (Ubuntu 7.04)
- linux-doc-2.6.22-2.6.22-15.56 (Ubuntu 7.10)
- linux-doc-2.6.24-2.6.24-19.36 (Ubuntu 8.04)
- linux-headers-2.6.15-52-2.6.15-52.69 (Ubuntu 6.06)
- linux-headers-2.6.15-52-386-2.6.15-52.69 (Ubuntu 6.06)
- linux-headers-2.6.15-52-686-2.6.15-52.69 (Ubuntu 6.06)
- linux-headers-2.6.15-52-amd64-generic-2.6.15-52.69 (Ubuntu 6.06)
- linux-headers-2.6.15-52-amd64-k8-2.6.15-52.69 (Ubuntu 6.06)
- linux-headers-2
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-6282","CVE-2007-6712","CVE-2008-0598","CVE-2008-1615","CVE-2008-1673","CVE-2008-2136","CVE-2008-2137","CVE-2008-2148","CVE-2008-2358","CVE-2008-2365","CVE-2008-2729","CVE-2008-2750","CVE-2008-2826");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-52.69
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-doc-2.6.20", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-doc-2.6.20-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-doc-2.6.22", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-doc-2.6.22-2.6.22-15.56
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-doc-2.6.24", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-doc-2.6.24-2.6.24-19.36
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-386", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-386-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-686", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-686-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-generic", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-generic-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-k8", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-k8-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-server", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-server-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-amd64-xeon", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-amd64-xeon-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-k7", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-k7-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-powerpc", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-powerpc-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-powerpc-smp", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-powerpc-smp-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-powerpc64-smp", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-powerpc64-smp-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-server", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-server-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-server-bigiron", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-server-bigiron-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-sparc64", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-sparc64-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-52-sparc64-smp", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-52-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-52-sparc64-smp-2.6.15-52.69
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-386", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-386-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-generic", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-generic-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-lowlatency", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-lowlatency-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-powerpc", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-powerpc-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-powerpc-smp", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-powerpc-smp-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-powerpc64-smp", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-powerpc64-smp-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-server", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-server-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-server-bigiron", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-server-bigiron-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-sparc64", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-sparc64-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-17-sparc64-smp", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-17-sparc64-smp-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-386", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-386-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-cell", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-cell-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-generic", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-generic-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-powerpc", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-powerpc-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-powerpc-smp", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-powerpc-smp-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-powerpc64-smp", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-powerpc64-smp-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-rt", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-rt-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-server", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-server-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-sparc64", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-sparc64-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-sparc64-smp", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-sparc64-smp-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-ume", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-ume-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-virtual", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-virtual-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-headers-2.6.22-15-xen", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.22-15-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-headers-2.6.22-15-xen-2.6.22-15.56
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-386", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-386-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-generic", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-generic-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-openvz", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-openvz-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-rt", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-rt-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-server", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-server-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-virtual", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-virtual-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-headers-2.6.24-19-xen", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.24-19-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-headers-2.6.24-19-xen-2.6.24-19.36
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-386", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-386-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-686", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-686-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-generic", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-generic-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-k8", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-k8-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-server", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-server-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-amd64-xeon", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-amd64-xeon-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-k7", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-k7-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-powerpc", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-powerpc-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-powerpc-smp", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-powerpc-smp-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-powerpc64-smp", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-powerpc64-smp-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-server", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-server-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-server-bigiron", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-server-bigiron-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-sparc64", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-sparc64-2.6.15-52.69
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-52-sparc64-smp", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-52-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-52-sparc64-smp-2.6.15-52.69
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-386", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-386-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-generic", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-generic-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-lowlatency", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-lowlatency-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-powerpc", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-powerpc-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-powerpc-smp", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-powerpc-smp-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-powerpc64-smp", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-powerpc64-smp-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-server", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-server-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-server-bigiron", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-server-bigiron-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-sparc64", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-sparc64-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-17-sparc64-smp", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-17-sparc64-smp-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-386", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-386-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-cell", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-cell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-cell-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-generic", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-generic-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-powerpc", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-powerpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-powerpc-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-powerpc-smp", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-powerpc-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-powerpc-smp-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-powerpc64-smp", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-powerpc64-smp-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-rt", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-rt-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-rt-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-server", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-server-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-sparc64", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-sparc64-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-sparc64-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-sparc64-smp", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-sparc64-smp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-sparc64-smp-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-ume", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-ume-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-ume-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-virtual", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-virtual-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-2.6.22-15-xen", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.22-15-xen-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-2.6.22-15-xen-2.6.22-15.56
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-386", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-386-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-generic", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-generic-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-openvz", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-openvz-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-openvz-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-rt", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-rt-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-rt-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-server", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-server-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-virtual", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-virtual-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-2.6.24-19-xen", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.24-19-xen-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-2.6.24-19-xen-2.6.24-19.36
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-386", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-386-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-generic", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-generic-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-lowlatency", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-lowlatency-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-powerpc", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-powerpc-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-powerpc-smp", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-powerpc-smp-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-powerpc64-smp", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-powerpc64-smp-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-server", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-server-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-server-bigiron", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-server-bigiron-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-sparc64", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-sparc64-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-17-sparc64-smp", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-17-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-17-sparc64-smp-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-386", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-386-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-386-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-generic", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-generic-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-generic-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-server", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-server-2.6.22-15.56
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-image-debug-2.6.22-15-virtual", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.22-15-virtual-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-image-debug-2.6.22-15-virtual-2.6.22-15.56
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-19-386", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-19-386-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-19-386-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-19-generic", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-19-generic-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-19-generic-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-19-server", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-19-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-19-server-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-image-debug-2.6.24-19-virtual", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.24-19-virtual-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-image-debug-2.6.24-19-virtual-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-kernel-devel", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-kernel-devel-2.6.24-19.36
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-libc-dev", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-libc-dev-2.6.24-19.36
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-52.69");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-52.69
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-source-2.6.20", pkgver: "2.6.20-17.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-source-2.6.20-2.6.20-17.37
');
}
found = ubuntu_check(osver: "7.10", pkgname: "linux-source-2.6.22", pkgver: "2.6.22-15.56");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.22-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to linux-source-2.6.22-2.6.22-15.56
');
}
found = ubuntu_check(osver: "8.04", pkgname: "linux-source-2.6.24", pkgver: "2.6.24-19.36");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.24-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to linux-source-2.6.24-2.6.24-19.36
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
