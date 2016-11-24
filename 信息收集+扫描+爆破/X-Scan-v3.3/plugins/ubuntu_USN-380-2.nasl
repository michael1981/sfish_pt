# This script was automatically generated from the 380-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27963);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "380-2");
script_summary(english:"avahi regression");
script_name(english:"USN380-2 : avahi regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- avahi-daemon 
- avahi-discover 
- avahi-dnsconfd 
- avahi-utils 
- libavahi-cil 
- libavahi-client-dev 
- libavahi-client1 
- libavahi-client3 
- libavahi-common-data 
- libavahi-common-dev 
- libavahi-common0 
- libavahi-common3 
- libavahi-compat-howl-dev 
- libavahi-compat-howl0 
- libavahi-compat-libdnssd-dev 
- libavahi-compat-libdnssd1 
- libavahi-core-dev 
- libavahi-core1 
- libavahi-core4 
- libavahi-glib-dev 
- libavahi-glib0 
- libavahi-glib
[...]');
script_set_attribute(attribute:'description', value: 'USN-380-1 fixed a vulnerability in Avahi. However, if used with
Network manager, that version occasionally failed to resolve .local
DNS names until Avahi got restarted. This update fixes the problem.

We apologize for the inconvenience.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- avahi-daemon-0.6.13-2ubuntu2.3 (Ubuntu 6.10)
- avahi-discover-0.6.13-2ubuntu2.3 (Ubuntu 6.10)
- avahi-dnsconfd-0.6.13-2ubuntu2.3 (Ubuntu 6.10)
- avahi-utils-0.6.13-2ubuntu2.3 (Ubuntu 6.10)
- libavahi-cil-0.6.10-0ubuntu3.3 (Ubuntu 6.06)
- libavahi-client-dev-0.6.13-2ubuntu2.3 (Ubuntu 6.10)
- libavahi-client1-0.5.2-1ubuntu1.3 (Ubuntu 5.10)
- libavahi-client3-0.6.13-2ubuntu2.3 (Ubuntu 6.10)
- libavahi-common-data-0.6.13-2ubuntu2.3 (Ubuntu 6.10)
- libavahi-common-dev-0.6.13-2ubuntu2.3 (Ubuntu 6
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "avahi-daemon", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-daemon-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to avahi-daemon-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "avahi-discover", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-discover-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to avahi-discover-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "avahi-dnsconfd", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-dnsconfd-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to avahi-dnsconfd-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "avahi-utils", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package avahi-utils-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to avahi-utils-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libavahi-cil", pkgver: "0.6.10-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-cil-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libavahi-cil-0.6.10-0ubuntu3.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-client-dev", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-client-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-client-dev-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libavahi-client1", pkgver: "0.5.2-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-client1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libavahi-client1-0.5.2-1ubuntu1.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-client3", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-client3-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-client3-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-common-data", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-common-data-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-common-data-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-common-dev", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-common-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-common-dev-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libavahi-common0", pkgver: "0.5.2-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-common0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libavahi-common0-0.5.2-1ubuntu1.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-common3", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-common3-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-common3-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-compat-howl-dev", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-compat-howl-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-compat-howl-dev-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-compat-howl0", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-compat-howl0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-compat-howl0-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-compat-libdnssd-dev", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-compat-libdnssd-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-compat-libdnssd-dev-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-compat-libdnssd1", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-compat-libdnssd1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-compat-libdnssd1-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-core-dev", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-core-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-core-dev-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libavahi-core1", pkgver: "0.5.2-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-core1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libavahi-core1-0.5.2-1ubuntu1.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-core4", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-core4-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-core4-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-glib-dev", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-glib-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-glib-dev-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libavahi-glib0", pkgver: "0.5.2-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-glib0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libavahi-glib0-0.5.2-1ubuntu1.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-glib1", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-glib1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-glib1-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libavahi-qt3-0", pkgver: "0.5.2-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-qt3-0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libavahi-qt3-0-0.5.2-1ubuntu1.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-qt3-1", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-qt3-1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-qt3-1-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-qt3-dev", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-qt3-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-qt3-dev-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libavahi-qt4-0", pkgver: "0.5.2-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-qt4-0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libavahi-qt4-0-0.5.2-1ubuntu1.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-qt4-1", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-qt4-1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-qt4-1-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libavahi-qt4-dev", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavahi-qt4-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libavahi-qt4-dev-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "monodoc-avahi-manual", pkgver: "0.6.10-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package monodoc-avahi-manual-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to monodoc-avahi-manual-0.6.10-0ubuntu3.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "python-avahi", pkgver: "0.6.13-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-avahi-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to python-avahi-0.6.13-2ubuntu2.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-avahi", pkgver: "0.6.10-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-avahi-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-avahi-0.6.10-0ubuntu3.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
