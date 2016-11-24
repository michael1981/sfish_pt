# This script was automatically generated from the 464-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28064);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "464-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN464-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
- linux-doc-2.6.17 
- linux-doc-2.6.20 
- linux-headers-2.6.15-28 
- linux-headers-2.6.15-28-386 
- linux-headers-2.6.15-28-686 
- linux-headers-2.6.15-28-amd64-generic 
- linux-headers-2.6.15-28-amd64-k8 
- linux-headers-2.6.15-28-amd64-server 
- linux-headers-2.6.15-28-amd64-xeon 
- linux-headers-2.6.15-28-k7 
- linux-headers-2.6.15-28-powerpc 
- linux-headers-2.6.15-28-powerpc-smp 
- linux-headers-2.6.15-28-powerpc64-smp 
- linux-h
[...]');
script_set_attribute(attribute:'description', value: 'Philipp Richter discovered that the AppleTalk protocol handler did
not sufficiently verify the length of packets. By sending a crafted
AppleTalk packet, a remote attacker could exploit this to crash the
kernel. (CVE-2007-1357)

Gabriel Campana discovered that the do_ipv6_setsockopt() function did
not sufficiently verifiy option values for IPV6_RTHDR. A local
attacker could exploit this to trigger a kernel crash. (CVE-2007-1388)

A Denial of Service vulnerability was discovered in the
nfnetlink_log() netfilter function. A remote attacker could exploit
this to trigger a kernel crash. (CVE-2007-1496)

The connection tracking module for IPv6 did not properly handle the
status field when reassembling fragmented packets, so that the final
packet always had the \'established\' state. A remote attacker could
exploit this to bypass intended firewall rules. (CVE-2007-1497)

Masayuki Nakagawa discovered an error in the flowlabel handling of
IPv6 network sockets. A local attacker could exploit this to crash
the kernel. 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-28.55 (Ubuntu 6.06)
- linux-doc-2.6.17-2.6.17.1-11.38 (Ubuntu 6.10)
- linux-doc-2.6.20-2.6.20-16.28 (Ubuntu 7.04)
- linux-headers-2.6.15-28-2.6.15-28.55 (Ubuntu 6.06)
- linux-headers-2.6.15-28-386-2.6.15-28.55 (Ubuntu 6.06)
- linux-headers-2.6.15-28-686-2.6.15-28.55 (Ubuntu 6.06)
- linux-headers-2.6.15-28-amd64-generic-2.6.15-28.55 (Ubuntu 6.06)
- linux-headers-2.6.15-28-amd64-k8-2.6.15-28.55 (Ubuntu 6.06)
- linux-headers-2.6.15-28-amd64-server-2.6.15-28.55 (Ubuntu 6
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2007-1357","CVE-2007-1388","CVE-2007-1496","CVE-2007-1497","CVE-2007-1592","CVE-2007-1730","CVE-2007-2172");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-doc-2.6.17", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-doc-2.6.17-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-doc-2.6.20", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-doc-2.6.20-2.6.20-16.28
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-386", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-386-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-686", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-686-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-amd64-generic", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-amd64-generic-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-amd64-k8", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-amd64-k8-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-amd64-server", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-amd64-server-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-amd64-xeon", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-amd64-xeon-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-k7", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-k7-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-powerpc", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-powerpc-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-powerpc-smp", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-powerpc-smp-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-powerpc64-smp", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-powerpc64-smp-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-server", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-server-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-server-bigiron", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-server-bigiron-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-sparc64", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-sparc64-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-sparc64-smp", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-sparc64-smp-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-386", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-386-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-generic", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-generic-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-powerpc", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-powerpc-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-powerpc-smp", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-powerpc-smp-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-powerpc64-smp", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-powerpc64-smp-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-server", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-server-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-server-bigiron", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-server-bigiron-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-sparc64", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-sparc64-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-sparc64-smp", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-sparc64-smp-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-386", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-386-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-generic", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-generic-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-lowlatency", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-lowlatency-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc-smp-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-powerpc64-smp-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-server", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-server-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-server-bigiron-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-sparc64", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-sparc64-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-headers-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-headers-2.6.20-16-sparc64-smp-2.6.20-16.28
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-386", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-386-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-686", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-686-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-amd64-generic", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-amd64-generic-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-amd64-k8", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-amd64-k8-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-amd64-server", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-amd64-server-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-amd64-xeon", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-amd64-xeon-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-k7", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-k7-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-powerpc", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-powerpc-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-powerpc-smp", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-powerpc-smp-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-powerpc64-smp", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-powerpc64-smp-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-server", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-server-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-server-bigiron", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-server-bigiron-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-sparc64", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-sparc64-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-sparc64-smp", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-sparc64-smp-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-386", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-386-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-generic", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-generic-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-powerpc", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-powerpc-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-powerpc-smp", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-powerpc-smp-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-powerpc64-smp", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-powerpc64-smp-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-server", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-server-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-server-bigiron", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-server-bigiron-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-sparc64", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-sparc64-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-sparc64-smp", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-sparc64-smp-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-386", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-386-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-generic", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-generic-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-lowlatency", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-lowlatency-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc-smp-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-powerpc64-smp-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-server", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-server-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-server-bigiron-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-sparc64", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-sparc64-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-2.6.20-16-sparc64-smp-2.6.20-16.28
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-386", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-386-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-generic", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-generic-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-powerpc", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-powerpc-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-powerpc-smp", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-powerpc-smp-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-powerpc64-smp", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-powerpc64-smp-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-server", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-server-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-server-bigiron", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-server-bigiron-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-sparc64", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-sparc64-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-sparc64-smp", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-sparc64-smp-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-386", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-386-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-386-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-generic", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-generic-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-generic-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-lowlatency", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-lowlatency-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-lowlatency-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc-smp", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc-smp-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-powerpc64-smp", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-powerpc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-powerpc64-smp-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-server", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-server-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-server-bigiron", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-server-bigiron-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-server-bigiron-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-sparc64", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-sparc64-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-sparc64-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-image-debug-2.6.20-16-sparc64-smp", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.20-16-sparc64-smp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-image-debug-2.6.20-16-sparc64-smp-2.6.20-16.28
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-kdump", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-kdump-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-kdump-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-kernel-devel", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-kernel-devel-2.6.20-16.28
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-libc-dev", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-libc-dev-2.6.20-16.28
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-28.55");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-28.55
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-source-2.6.17", pkgver: "2.6.17.1-11.38");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-source-2.6.17-2.6.17.1-11.38
');
}
found = ubuntu_check(osver: "7.04", pkgname: "linux-source-2.6.20", pkgver: "2.6.20-16.28");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.20-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to linux-source-2.6.20-2.6.20-16.28
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
