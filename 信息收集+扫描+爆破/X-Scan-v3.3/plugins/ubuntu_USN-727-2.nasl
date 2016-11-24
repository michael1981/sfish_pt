# This script was automatically generated from the 727-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37740);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "727-2");
script_summary(english:"network-manager vulnerability");
script_name(english:"USN727-2 : network-manager vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libnm-glib-dev 
- libnm-glib0 
- libnm-glib0-dbg 
- libnm-util-dev 
- libnm-util0 
- libnm-util0-dbg 
- network-manager 
- network-manager-dbg 
- network-manager-dev 
- network-manager-gnome 
- network-manager-gnome-dbg 
');
script_set_attribute(attribute:'description', value: 'USN-727-1 fixed vulnerabilities in network-manager-applet. This advisory
provides the corresponding updates for NetworkManager.

It was discovered that NetworkManager did not properly enforce permissions when
responding to dbus requests. A local user could perform dbus queries to view
system and user network connection passwords and pre-shared keys.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnm-glib-dev-0.6.2-0ubuntu7.1 (Ubuntu 6.06)
- libnm-glib0-0.6.2-0ubuntu7.1 (Ubuntu 6.06)
- libnm-glib0-dbg-0.6.2-0ubuntu7.1 (Ubuntu 6.06)
- libnm-util-dev-0.6.2-0ubuntu7.1 (Ubuntu 6.06)
- libnm-util0-0.6.2-0ubuntu7.1 (Ubuntu 6.06)
- libnm-util0-dbg-0.6.2-0ubuntu7.1 (Ubuntu 6.06)
- network-manager-0.6.2-0ubuntu7.1 (Ubuntu 6.06)
- network-manager-dbg-0.6.2-0ubuntu7.1 (Ubuntu 6.06)
- network-manager-dev-0.6.2-0ubuntu7.1 (Ubuntu 6.06)
- network-manager-gnome-0.6.2-0ubuntu7.1 (Ubuntu 6.06)
- n
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:S/C:C/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2009-0365");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libnm-glib-dev", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnm-glib-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnm-glib-dev-0.6.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnm-glib0", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnm-glib0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnm-glib0-0.6.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnm-glib0-dbg", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnm-glib0-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnm-glib0-dbg-0.6.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnm-util-dev", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnm-util-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnm-util-dev-0.6.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnm-util0", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnm-util0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnm-util0-0.6.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnm-util0-dbg", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnm-util0-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnm-util0-dbg-0.6.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "network-manager", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package network-manager-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to network-manager-0.6.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "network-manager-dbg", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package network-manager-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to network-manager-dbg-0.6.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "network-manager-dev", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package network-manager-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to network-manager-dev-0.6.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "network-manager-gnome", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package network-manager-gnome-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to network-manager-gnome-0.6.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "network-manager-gnome-dbg", pkgver: "0.6.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package network-manager-gnome-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to network-manager-gnome-dbg-0.6.2-0ubuntu7.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
