# This script was automatically generated from the 401-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27989);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "401-1");
script_summary(english:"D-Bus vulnerability");
script_name(english:"USN401-1 : D-Bus vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dbus 
- dbus-1-doc 
- dbus-1-utils 
- libdbus-1-1 
- libdbus-1-2 
- libdbus-1-3 
- libdbus-1-cil 
- libdbus-1-dev 
- libdbus-glib-1-1 
- libdbus-glib-1-2 
- libdbus-glib-1-dev 
- libdbus-qt-1-1c2 
- libdbus-qt-1-dev 
- monodoc-dbus-1-manual 
- python2.4-dbus 
');
script_set_attribute(attribute:'description', value: 'Kimmo Hämäläinen discovered that local users could delete other users\' 
D-Bus match rules.  Applications would stop receiving D-Bus messages, 
resulting in a local denial of service, and potential data loss for 
applications that depended on D-Bus for storing information.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dbus-0.93-0ubuntu3.1 (Ubuntu 6.10)
- dbus-1-doc-0.93-0ubuntu3.1 (Ubuntu 6.10)
- dbus-1-utils-0.93-0ubuntu3.1 (Ubuntu 6.10)
- libdbus-1-1-0.36.2-0ubuntu7.1 (Ubuntu 5.10)
- libdbus-1-2-0.60-6ubuntu8.1 (Ubuntu 6.06)
- libdbus-1-3-0.93-0ubuntu3.1 (Ubuntu 6.10)
- libdbus-1-cil-0.60-6ubuntu8.1 (Ubuntu 6.06)
- libdbus-1-dev-0.93-0ubuntu3.1 (Ubuntu 6.10)
- libdbus-glib-1-1-0.36.2-0ubuntu7.1 (Ubuntu 5.10)
- libdbus-glib-1-2-0.60-6ubuntu8.1 (Ubuntu 6.06)
- libdbus-glib-1-dev-0.60-6ubuntu8.1 (Ubuntu 6
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:S/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-6107");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "dbus", pkgver: "0.93-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dbus-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to dbus-0.93-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "dbus-1-doc", pkgver: "0.93-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dbus-1-doc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to dbus-1-doc-0.93-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "dbus-1-utils", pkgver: "0.93-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dbus-1-utils-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to dbus-1-utils-0.93-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libdbus-1-1", pkgver: "0.36.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-1-1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libdbus-1-1-0.36.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-1-2", pkgver: "0.60-6ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-1-2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-1-2-0.60-6ubuntu8.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libdbus-1-3", pkgver: "0.93-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-1-3-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libdbus-1-3-0.93-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-1-cil", pkgver: "0.60-6ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-1-cil-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-1-cil-0.60-6ubuntu8.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libdbus-1-dev", pkgver: "0.93-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-1-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libdbus-1-dev-0.93-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libdbus-glib-1-1", pkgver: "0.36.2-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-glib-1-1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libdbus-glib-1-1-0.36.2-0ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-glib-1-2", pkgver: "0.60-6ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-glib-1-2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-glib-1-2-0.60-6ubuntu8.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-glib-1-dev", pkgver: "0.60-6ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-glib-1-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-glib-1-dev-0.60-6ubuntu8.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-qt-1-1c2", pkgver: "0.60-6ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-qt-1-1c2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-qt-1-1c2-0.60-6ubuntu8.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-qt-1-dev", pkgver: "0.60-6ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-qt-1-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-qt-1-dev-0.60-6ubuntu8.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "monodoc-dbus-1-manual", pkgver: "0.60-6ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package monodoc-dbus-1-manual-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to monodoc-dbus-1-manual-0.60-6ubuntu8.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-dbus", pkgver: "0.60-6ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-dbus-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-dbus-0.60-6ubuntu8.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
