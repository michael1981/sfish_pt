# This script was automatically generated from the 395-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27981);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "395-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN395-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.12 
- linux-doc-2.6.15 
- linux-doc-2.6.17 
- linux-headers-2.6.12-10 
- linux-headers-2.6.12-10-386 
- linux-headers-2.6.12-10-686 
- linux-headers-2.6.12-10-686-smp 
- linux-headers-2.6.12-10-amd64-generic 
- linux-headers-2.6.12-10-amd64-k8 
- linux-headers-2.6.12-10-amd64-k8-smp 
- linux-headers-2.6.12-10-amd64-xeon 
- linux-headers-2.6.12-10-iseries-smp 
- linux-headers-2.6.12-10-k7 
- linux-headers-2.6.12-10-k7-smp 
- linux-headers-
[...]');
script_set_attribute(attribute:'description', value: 'Mark Dowd discovered that the netfilter iptables module did not
correcly handle fragmented packets. By sending specially crafted
packets, a remote attacker could exploit this to bypass firewall
rules. This has only be fixed for Ubuntu 6.10; the corresponding fix
for Ubuntu 5.10 and 6.06 will follow soon. (CVE-2006-4572)

Dmitriy Monakhov discovered an information leak in the
__block_prepare_write() function. During error recovery, this function
did not properly clear memory buffers which could allow local users to
read portions of unlinked files. This only affects Ubuntu 5.10.
(CVE-2006-4813)

ADLab Venustech Info Ltd discovered that the ATM network driver
referenced an already released pointer in some circumstances. By
sending specially crafted packets to a host over ATM, a remote
attacker could exploit this to crash that host. This does not affect
Ubuntu 6.10. (CVE-2006-4997)

Matthias Andree discovered that the NFS locking management daemon
(lockd) did not correctly handle mixing of \'lock\' and \'nolock\
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.12-2.6.12-10.42 (Ubuntu 5.10)
- linux-doc-2.6.15-2.6.15-27.50 (Ubuntu 6.06)
- linux-doc-2.6.17-2.6.17.1-10.34 (Ubuntu 6.10)
- linux-headers-2.6.12-10-2.6.12-10.42 (Ubuntu 5.10)
- linux-headers-2.6.12-10-386-2.6.12-10.42 (Ubuntu 5.10)
- linux-headers-2.6.12-10-686-2.6.12-10.42 (Ubuntu 5.10)
- linux-headers-2.6.12-10-686-smp-2.6.12-10.42 (Ubuntu 5.10)
- linux-headers-2.6.12-10-amd64-generic-2.6.12-10.42 (Ubuntu 5.10)
- linux-headers-2.6.12-10-amd64-k8-2.6.12-10.42 (Ubuntu 5.10)

[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2006-4572","CVE-2006-4813","CVE-2006-4997","CVE-2006-5158","CVE-2006-5173","CVE-2006-5619","CVE-2006-5648","CVE-2006-5649","CVE-2006-5701","CVE-2006-5751");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "linux-doc-2.6.12", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-doc-2.6.12-2.6.12-10.42
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-doc-2.6.17", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-doc-2.6.17-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-386", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-386-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-686-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-686-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-generic-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-k8-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-amd64-xeon-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-iseries-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-k7-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-k7-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-headers-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-headers-2.6.12-10-powerpc64-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-386", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-386-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-686", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-686-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-amd64-generic", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-amd64-generic-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-amd64-k8", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-amd64-k8-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-amd64-server", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-amd64-server-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-amd64-xeon", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-amd64-xeon-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-k7", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-k7-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-powerpc", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-powerpc-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-powerpc-smp", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-powerpc-smp-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-powerpc64-smp", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-powerpc64-smp-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-server", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-server-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-server-bigiron", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-server-bigiron-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-sparc64", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-sparc64-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-27-sparc64-smp", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-27-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-27-sparc64-smp-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-10", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-10-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-10-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-10-386", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-10-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-10-386-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-10-generic", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-10-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-10-generic-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-10-powerpc", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-10-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-10-powerpc-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-10-powerpc-smp", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-10-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-10-powerpc-smp-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-10-powerpc64-smp", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-10-powerpc64-smp-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-10-server", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-10-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-10-server-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-10-server-bigiron", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-10-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-10-server-bigiron-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-10-sparc64", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-10-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-10-sparc64-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-10-sparc64-smp", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-10-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-10-sparc64-smp-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-386", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-386-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-386-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-686-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-686-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-686-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-686-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-generic", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-amd64-generic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-generic-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-amd64-k8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-k8-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-amd64-k8-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-k8-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-amd64-xeon", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-amd64-xeon-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-amd64-xeon-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-iseries-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-iseries-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-iseries-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-k7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-k7-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-k7-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-k7-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-powerpc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-powerpc-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-image-2.6.12-10-powerpc64-smp", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.12-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-image-2.6.12-10-powerpc64-smp-2.6.12-10.42
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-386", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-386-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-686", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-686-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-amd64-generic", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-amd64-generic-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-amd64-k8", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-amd64-k8-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-amd64-server", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-amd64-server-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-amd64-xeon", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-amd64-xeon-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-k7", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-k7-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-powerpc", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-powerpc-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-powerpc-smp", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-powerpc-smp-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-powerpc64-smp", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-powerpc64-smp-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-server", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-server-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-server-bigiron", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-server-bigiron-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-sparc64", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-sparc64-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-27-sparc64-smp", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-27-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-27-sparc64-smp-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-10-386", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-10-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-10-386-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-10-generic", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-10-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-10-generic-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-10-powerpc", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-10-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-10-powerpc-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-10-powerpc-smp", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-10-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-10-powerpc-smp-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-10-powerpc64-smp", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-10-powerpc64-smp-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-10-server", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-10-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-10-server-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-10-server-bigiron", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-10-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-10-server-bigiron-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-10-sparc64", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-10-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-10-sparc64-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-10-sparc64-smp", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-10-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-10-sparc64-smp-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-10-386", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-10-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-10-386-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-10-generic", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-10-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-10-generic-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-10-powerpc", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-10-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-10-powerpc-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-10-powerpc-smp", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-10-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-10-powerpc-smp-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-10-powerpc64-smp", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-10-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-10-powerpc64-smp-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-10-server", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-10-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-10-server-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-10-server-bigiron", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-10-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-10-server-bigiron-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-10-sparc64", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-10-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-10-sparc64-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-10-sparc64-smp", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-10-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-10-sparc64-smp-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-kdump", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-kdump-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-kdump-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-kernel-devel", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-kernel-devel-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-libc-dev", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-libc-dev-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-patch-ubuntu-2.6.12", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-patch-ubuntu-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-patch-ubuntu-2.6.12-2.6.12-10.42
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-source-2.6.12", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-source-2.6.12-2.6.12-10.42
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-27.50");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-27.50
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-source-2.6.17", pkgver: "2.6.17.1-10.34");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-source-2.6.17-2.6.17.1-10.34
');
}
found = ubuntu_check(osver: "5.10", pkgname: "linux-tree-2.6.12", pkgver: "2.6.12-10.42");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-tree-2.6.12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to linux-tree-2.6.12-2.6.12-10.42
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
