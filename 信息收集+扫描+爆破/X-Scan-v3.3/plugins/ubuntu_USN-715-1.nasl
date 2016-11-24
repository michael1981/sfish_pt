# This script was automatically generated from the 715-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36279);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "715-1");
script_summary(english:"linux vulnerabilities");
script_name(english:"USN715-1 : linux vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- linux-doc-2.6.27 
- linux-headers-2.6.27-11 
- linux-headers-2.6.27-11-generic 
- linux-headers-2.6.27-11-server 
- linux-image-2.6.27-11-generic 
- linux-image-2.6.27-11-server 
- linux-image-2.6.27-11-virtual 
- linux-libc-dev 
- linux-source-2.6.27 
');
script_set_attribute(attribute:'description', value: 'Hugo Dias discovered that the ATM subsystem did not correctly manage
socket counts. A local attacker could exploit this to cause a system hang,
leading to a denial of service. (CVE-2008-5079)

It was discovered that the inotify subsystem contained watch removal
race conditions. A local attacker could exploit this to crash the system,
leading to a denial of service. (CVE-2008-5182)

Dann Frazier discovered that in certain situations sendmsg did not
correctly release allocated memory. A local attacker could exploit
this to force the system to run out of free memory, leading to a denial
of service.  (CVE-2008-5300)

Helge Deller discovered that PA-RISC stack unwinding was not handled
correctly. A local attacker could exploit this to crash the system,
leading do a denial of service. This did not affect official Ubuntu
kernels, but was fixed in the source for anyone performing HPPA kernel
builds.  (CVE-2008-5395)

It was discovered that the ATA subsystem did not correctly set timeouts. A
local attacker could expl
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- linux-doc-2.6.27-2.6.27-11.27 (Ubuntu 8.10)
- linux-headers-2.6.27-11-2.6.27-11.27 (Ubuntu 8.10)
- linux-headers-2.6.27-11-generic-2.6.27-11.27 (Ubuntu 8.10)
- linux-headers-2.6.27-11-server-2.6.27-11.27 (Ubuntu 8.10)
- linux-image-2.6.27-11-generic-2.6.27-11.27 (Ubuntu 8.10)
- linux-image-2.6.27-11-server-2.6.27-11.27 (Ubuntu 8.10)
- linux-image-2.6.27-11-virtual-2.6.27-11.27 (Ubuntu 8.10)
- linux-libc-dev-2.6.27-11.27 (Ubuntu 8.10)
- linux-source-2.6.27-2.6.27-11.27 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-5079","CVE-2008-5182","CVE-2008-5300","CVE-2008-5395","CVE-2008-5700","CVE-2008-5702");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "linux-doc-2.6.27", pkgver: "2.6.27-11.27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-doc-2.6.27-2.6.27-11.27
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-11", pkgver: "2.6.27-11.27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-11-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-11-2.6.27-11.27
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-11-generic", pkgver: "2.6.27-11.27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-11-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-11-generic-2.6.27-11.27
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-11-server", pkgver: "2.6.27-11.27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-11-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-11-server-2.6.27-11.27
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-11-generic", pkgver: "2.6.27-11.27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-11-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-11-generic-2.6.27-11.27
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-11-server", pkgver: "2.6.27-11.27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-11-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-11-server-2.6.27-11.27
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-11-virtual", pkgver: "2.6.27-11.27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-11-virtual-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-11-virtual-2.6.27-11.27
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-libc-dev", pkgver: "2.6.27-11.27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-libc-dev-2.6.27-11.27
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-source-2.6.27", pkgver: "2.6.27-11.27");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-source-2.6.27-2.6.27-11.27
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
