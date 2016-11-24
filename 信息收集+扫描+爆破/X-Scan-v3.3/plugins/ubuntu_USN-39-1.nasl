# This script was automatically generated from the 39-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20655);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "39-1");
script_summary(english:"linux-source-2.6.8.1 vulnerability");
script_name(english:"USN39-1 : linux-source-2.6.8.1 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.8.1 
- linux-headers-2.6.8.1-4 
- linux-headers-2.6.8.1-4-386 
- linux-headers-2.6.8.1-4-686 
- linux-headers-2.6.8.1-4-686-smp 
- linux-headers-2.6.8.1-4-amd64-generic 
- linux-headers-2.6.8.1-4-amd64-k8 
- linux-headers-2.6.8.1-4-amd64-k8-smp 
- linux-headers-2.6.8.1-4-amd64-xeon 
- linux-headers-2.6.8.1-4-k7 
- linux-headers-2.6.8.1-4-k7-smp 
- linux-headers-2.6.8.1-4-power3 
- linux-headers-2.6.8.1-4-power3-smp 
- linux-headers-2.6.8.
[...]');
script_set_attribute(attribute:'description', value: 'USN-30-1 fixed several flaws in the Linux ELF binary loader\'s handling
of setuid binaries. Unfortunately it was found that these patches were
not sufficient to prevent all possible attacks on 64-bit platforms, so
previous amd64 kernel images were still vulnerable to root privilege
escalation if setuid binaries were run under certain conditions.

This issue does not affect the i386 and powerpc platforms.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.8.1-2.6.8.1-16.4 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-2.6.8.1-16.4 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-386-2.6.8.1-16.4 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-686-2.6.8.1-16.4 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-686-smp-2.6.8.1-16.4 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-amd64-generic-2.6.8.1-16.4 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-amd64-k8-2.6.8.1-16.4 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-amd64-k8-smp-2.6.8.1-16.4 (Ubuntu 4.10)
- linux-headers-2.6.8.1-4-a
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2004-1074");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "linux-doc-2.6.8.1", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-doc-2.6.8.1-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-386", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-386-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-686", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-686-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-686-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-686-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-generic", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-generic-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-k8", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-k8-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-k8-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-k8-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-amd64-xeon", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-amd64-xeon-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-k7", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-k7-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-k7-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-k7-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power3", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power3-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power3-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power3-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power4", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power4-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-power4-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-power4-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-powerpc", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-powerpc-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-headers-2.6.8.1-4-powerpc-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.8.1-4-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-headers-2.6.8.1-4-powerpc-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-386", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-386-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-386-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-686", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-686-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-686-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-686-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-686-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-686-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-generic", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-amd64-generic-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-generic-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-k8", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-amd64-k8-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-k8-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-k8-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-amd64-k8-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-k8-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-amd64-xeon", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-amd64-xeon-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-amd64-xeon-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-k7", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-k7-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-k7-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-k7-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-k7-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-k7-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power3", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-power3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power3-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power3-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-power3-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power3-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power4", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-power4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power4-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-power4-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-power4-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-power4-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-powerpc", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-powerpc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-powerpc-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-image-2.6.8.1-4-powerpc-smp", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.8.1-4-powerpc-smp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-image-2.6.8.1-4-powerpc-smp-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-patch-debian-2.6.8.1", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-patch-debian-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-patch-debian-2.6.8.1-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-source-2.6.8.1", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-source-2.6.8.1-2.6.8.1-16.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "linux-tree-2.6.8.1", pkgver: "2.6.8.1-16.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-tree-2.6.8.1-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to linux-tree-2.6.8.1-2.6.8.1-16.4
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
