# This script was automatically generated from the 451-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28048);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "451-1");
script_summary(english:"Linux kernel vulnerabilities");
script_name(english:"USN451-1 : Linux kernel vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.15 
- linux-doc-2.6.17 
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
- linux-headers-2.6.15-28-ser
[...]');
script_set_attribute(attribute:'description', value: 'The kernel key management code did not correctly handle key reuse.  A 
local attacker could create many key requests, leading to a denial of 
service. (CVE-2007-0006)

The kernel NFS code did not correctly validate NFSACL2 ACCESS requests.  
If a system was serving NFS mounts, a remote attacker could send a 
specially crafted packet, leading to a denial of service. 
(CVE-2007-0772)

When dumping core, the kernel did not correctly handle PT_INTERP 
processes.  A local attacker could create situations where they could 
read the contents of otherwise unreadable executable programs. 
(CVE-2007-0958)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.15-2.6.15-28.53 (Ubuntu 6.06)
- linux-doc-2.6.17-2.6.17.1-11.37 (Ubuntu 6.10)
- linux-headers-2.6.15-28-2.6.15-28.53 (Ubuntu 6.06)
- linux-headers-2.6.15-28-386-2.6.15-28.53 (Ubuntu 6.06)
- linux-headers-2.6.15-28-686-2.6.15-28.53 (Ubuntu 6.06)
- linux-headers-2.6.15-28-amd64-generic-2.6.15-28.53 (Ubuntu 6.06)
- linux-headers-2.6.15-28-amd64-k8-2.6.15-28.53 (Ubuntu 6.06)
- linux-headers-2.6.15-28-amd64-server-2.6.15-28.53 (Ubuntu 6.06)
- linux-headers-2.6.15-28-amd64-xeon-2.6.
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2007-0006","CVE-2007-0772","CVE-2007-0958");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "linux-doc-2.6.15", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-doc-2.6.15-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-doc-2.6.17", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-doc-2.6.17-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-386", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-386-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-686", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-686-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-amd64-generic", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-amd64-generic-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-amd64-k8", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-amd64-k8-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-amd64-server", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-amd64-server-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-amd64-xeon", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-amd64-xeon-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-k7", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-k7-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-powerpc", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-powerpc-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-powerpc-smp", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-powerpc-smp-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-powerpc64-smp", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-powerpc64-smp-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-server", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-server-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-server-bigiron", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-server-bigiron-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-sparc64", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-sparc64-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-headers-2.6.15-28-sparc64-smp", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.15-28-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-headers-2.6.15-28-sparc64-smp-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-386", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-386-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-generic", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-generic-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-powerpc", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-powerpc-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-powerpc-smp", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-powerpc-smp-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-powerpc64-smp", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-powerpc64-smp-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-server", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-server-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-server-bigiron", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-server-bigiron-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-sparc64", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-sparc64-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-headers-2.6.17-11-sparc64-smp", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.17-11-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-headers-2.6.17-11-sparc64-smp-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-386", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-386-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-386-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-686", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-686-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-686-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-amd64-generic", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-amd64-generic-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-amd64-generic-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-amd64-k8", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-amd64-k8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-amd64-k8-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-amd64-server", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-amd64-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-amd64-server-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-amd64-xeon", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-amd64-xeon-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-amd64-xeon-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-k7", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-k7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-k7-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-powerpc", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-powerpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-powerpc-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-powerpc-smp", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-powerpc-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-powerpc-smp-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-powerpc64-smp", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-powerpc64-smp-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-server", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-server-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-server-bigiron", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-server-bigiron-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-server-bigiron-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-sparc64", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-sparc64-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-sparc64-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-image-2.6.15-28-sparc64-smp", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.15-28-sparc64-smp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-image-2.6.15-28-sparc64-smp-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-386", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-386-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-generic", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-generic-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-powerpc", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-powerpc-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-powerpc-smp", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-powerpc-smp-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-powerpc64-smp", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-powerpc64-smp-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-server", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-server-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-server-bigiron", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-server-bigiron-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-sparc64", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-sparc64-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-2.6.17-11-sparc64-smp", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.17-11-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-2.6.17-11-sparc64-smp-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-386", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-386-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-386-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-generic", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-generic-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-generic-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-powerpc", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-powerpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-powerpc-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-powerpc-smp", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-powerpc-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-powerpc-smp-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-powerpc64-smp", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-powerpc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-powerpc64-smp-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-server", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-server-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-server-bigiron", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-server-bigiron-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-server-bigiron-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-sparc64", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-sparc64-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-sparc64-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-debug-2.6.17-11-sparc64-smp", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-debug-2.6.17-11-sparc64-smp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-debug-2.6.17-11-sparc64-smp-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-image-kdump", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-kdump-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-image-kdump-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-kernel-devel", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-kernel-devel-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-kernel-devel-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-libc-dev", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-libc-dev-2.6.17.1-11.37
');
}
found = ubuntu_check(osver: "6.06", pkgname: "linux-source-2.6.15", pkgver: "2.6.15-28.53");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.15-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to linux-source-2.6.15-2.6.15-28.53
');
}
found = ubuntu_check(osver: "6.10", pkgname: "linux-source-2.6.17", pkgver: "2.6.17.1-11.37");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.17-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to linux-source-2.6.17-2.6.17.1-11.37
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
