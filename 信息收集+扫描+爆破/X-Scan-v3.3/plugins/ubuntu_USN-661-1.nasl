# This script was automatically generated from the 661-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37570);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "661-1");
script_summary(english:"linux regression");
script_name(english:"USN661-1 : linux regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libproc-dev 
- linux-doc-2.6.27 
- linux-headers-2.6.27-7 
- linux-headers-2.6.27-7-generic 
- linux-headers-2.6.27-7-server 
- linux-image-2.6.27-7-generic 
- linux-image-2.6.27-7-server 
- linux-image-2.6.27-7-virtual 
- linux-libc-dev 
- linux-source-2.6.27 
- procps 
');
script_set_attribute(attribute:'description', value: 'Version 2.6.27 of the Linux kernel changed the order of options in
TCP headers. While this change was RFC-compliant, it was found that
some old routers and consumer DSL modems would not route traffic for
these systems when TCP timestamps were enabled. As a workaround, TCP
timestamps were disabled via sysctl.

This update restores the previous ordering of TCP options, and
reenables TCP timestamps. We apologize for the inconvenience.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libproc-dev-3.2.7-9ubuntu2.1 (Ubuntu 8.10)
- linux-doc-2.6.27-2.6.27-7.15 (Ubuntu 8.10)
- linux-headers-2.6.27-7-2.6.27-7.15 (Ubuntu 8.10)
- linux-headers-2.6.27-7-generic-2.6.27-7.15 (Ubuntu 8.10)
- linux-headers-2.6.27-7-server-2.6.27-7.15 (Ubuntu 8.10)
- linux-image-2.6.27-7-generic-2.6.27-7.15 (Ubuntu 8.10)
- linux-image-2.6.27-7-server-2.6.27-7.15 (Ubuntu 8.10)
- linux-image-2.6.27-7-virtual-2.6.27-7.15 (Ubuntu 8.10)
- linux-libc-dev-2.6.27-7.15 (Ubuntu 8.10)
- linux-source-2.6.27-2.6.
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libproc-dev", pkgver: "3.2.7-9ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libproc-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libproc-dev-3.2.7-9ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-doc-2.6.27", pkgver: "2.6.27-7.15");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-doc-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-doc-2.6.27-2.6.27-7.15
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-7", pkgver: "2.6.27-7.15");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-7-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-7-2.6.27-7.15
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-7-generic", pkgver: "2.6.27-7.15");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-7-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-7-generic-2.6.27-7.15
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-headers-2.6.27-7-server", pkgver: "2.6.27-7.15");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-headers-2.6.27-7-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-headers-2.6.27-7-server-2.6.27-7.15
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-7-generic", pkgver: "2.6.27-7.15");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-7-generic-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-7-generic-2.6.27-7.15
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-7-server", pkgver: "2.6.27-7.15");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-7-server-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-7-server-2.6.27-7.15
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-image-2.6.27-7-virtual", pkgver: "2.6.27-7.15");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-image-2.6.27-7-virtual-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-image-2.6.27-7-virtual-2.6.27-7.15
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-libc-dev", pkgver: "2.6.27-7.15");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-libc-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-libc-dev-2.6.27-7.15
');
}
found = ubuntu_check(osver: "8.10", pkgname: "linux-source-2.6.27", pkgver: "2.6.27-7.15");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package linux-source-2.6.27-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to linux-source-2.6.27-2.6.27-7.15
');
}
found = ubuntu_check(osver: "8.10", pkgname: "procps", pkgver: "3.2.7-9ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package procps-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to procps-3.2.7-9ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
