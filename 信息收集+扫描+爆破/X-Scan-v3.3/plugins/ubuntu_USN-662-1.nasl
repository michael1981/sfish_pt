# This script was automatically generated from the 662-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37499);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "662-1");
script_summary(english:"linux vulnerability");
script_name(english:"USN662-1 : linux vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.27 
- linux-headers-2.6.27-7 
- linux-headers-2.6.27-7-generic 
- linux-headers-2.6.27-7-server 
- linux-image-2.6.27-7-generic 
- linux-image-2.6.27-7-server 
- linux-image-2.6.27-7-virtual 
- linux-libc-dev 
- linux-source-2.6.27 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the Linux kernel could be made to hang temporarily
when mounting corrupted ext2/3 filesystems.  If a user were tricked into
mounting a specially crafted filesystem, a remote attacker could cause
system hangs, leading to a denial of service. (CVE-2008-3528)

Anders Kaseorg discovered that ndiswrapper did not correctly handle long
ESSIDs.  For a system using ndiswrapper, a physically near-by attacker
could generate specially crafted wireless network traffic and execute
arbitrary code with root privileges. (CVE-2008-4395)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.27-2.6.27-7.16 (Ubuntu 8.10)
- linux-headers-2.6.27-7-2.6.27-7.16 (Ubuntu 8.10)
- linux-headers-2.6.27-7-generic-2.6.27-7.16 (Ubuntu 8.10)
- linux-headers-2.6.27-7-server-2.6.27-7.16 (Ubuntu 8.10)
- linux-image-2.6.27-7-generic-2.6.27-7.16 (Ubuntu 8.10)
- linux-image-2.6.27-7-server-2.6.27-7.16 (Ubuntu 8.10)
- linux-image-2.6.27-7-virtual-2.6.27-7.16 (Ubuntu 8.10)
- linux-libc-dev-2.6.27-7.16 (Ubuntu 8.10)
- linux-source-2.6.27-2.6.27-7.16 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:A/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-3528","CVE-2008-4395");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "linux-doc-2.6.27", pkgver: "2.6.27-7.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-doc-2.6.27-2.6.27-7.16
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-7", pkgver: "2.6.27-7.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-7-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-7-2.6.27-7.16
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-7-generic", pkgver: "2.6.27-7.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-7-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-7-generic-2.6.27-7.16
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-7-server", pkgver: "2.6.27-7.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-7-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-7-server-2.6.27-7.16
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-7-generic", pkgver: "2.6.27-7.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-7-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-7-generic-2.6.27-7.16
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-7-server", pkgver: "2.6.27-7.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-7-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-7-server-2.6.27-7.16
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-7-virtual", pkgver: "2.6.27-7.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-7-virtual-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-7-virtual-2.6.27-7.16
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-libc-dev", pkgver: "2.6.27-7.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-libc-dev-2.6.27-7.16
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-source-2.6.27", pkgver: "2.6.27-7.16");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-source-2.6.27-2.6.27-7.16
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
