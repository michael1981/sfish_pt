# This script was automatically generated from the 799-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39786);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "799-1");
script_summary(english:"dbus vulnerability");
script_name(english:"USN799-1 : dbus vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dbus 
- dbus-1-doc 
- dbus-1-utils 
- dbus-x11 
- libdbus-1-2 
- libdbus-1-3 
- libdbus-1-cil 
- libdbus-1-dev 
- libdbus-glib-1-2 
- libdbus-glib-1-dev 
- libdbus-qt-1-1c2 
- libdbus-qt-1-dev 
- monodoc-dbus-1-manual 
- python2.4-dbus 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the D-Bus library did not correctly validate
signatures. If a local user sent a specially crafted D-Bus key, they could
spoof a valid signature and bypass security policies.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dbus-1.2.12-0ubuntu2.1 (Ubuntu 9.04)
- dbus-1-doc-1.2.12-0ubuntu2.1 (Ubuntu 9.04)
- dbus-1-utils-0.60-6ubuntu8.4 (Ubuntu 6.06)
- dbus-x11-1.2.12-0ubuntu2.1 (Ubuntu 9.04)
- libdbus-1-2-0.60-6ubuntu8.4 (Ubuntu 6.06)
- libdbus-1-3-1.2.12-0ubuntu2.1 (Ubuntu 9.04)
- libdbus-1-cil-0.60-6ubuntu8.4 (Ubuntu 6.06)
- libdbus-1-dev-1.2.12-0ubuntu2.1 (Ubuntu 9.04)
- libdbus-glib-1-2-0.60-6ubuntu8.4 (Ubuntu 6.06)
- libdbus-glib-1-dev-0.60-6ubuntu8.4 (Ubuntu 6.06)
- libdbus-qt-1-1c2-0.60-6ubuntu8.4 (Ubunt
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-1189");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "dbus", pkgver: "1.2.12-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dbus-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dbus-1.2.12-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dbus-1-doc", pkgver: "1.2.12-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dbus-1-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dbus-1-doc-1.2.12-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "dbus-1-utils", pkgver: "0.60-6ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dbus-1-utils-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to dbus-1-utils-0.60-6ubuntu8.4
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dbus-x11", pkgver: "1.2.12-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dbus-x11-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dbus-x11-1.2.12-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-1-2", pkgver: "0.60-6ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-1-2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-1-2-0.60-6ubuntu8.4
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libdbus-1-3", pkgver: "1.2.12-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-1-3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libdbus-1-3-1.2.12-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-1-cil", pkgver: "0.60-6ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-1-cil-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-1-cil-0.60-6ubuntu8.4
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libdbus-1-dev", pkgver: "1.2.12-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-1-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libdbus-1-dev-1.2.12-0ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-glib-1-2", pkgver: "0.60-6ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-glib-1-2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-glib-1-2-0.60-6ubuntu8.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-glib-1-dev", pkgver: "0.60-6ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-glib-1-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-glib-1-dev-0.60-6ubuntu8.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-qt-1-1c2", pkgver: "0.60-6ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-qt-1-1c2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-qt-1-1c2-0.60-6ubuntu8.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdbus-qt-1-dev", pkgver: "0.60-6ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbus-qt-1-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdbus-qt-1-dev-0.60-6ubuntu8.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "monodoc-dbus-1-manual", pkgver: "0.60-6ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package monodoc-dbus-1-manual-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to monodoc-dbus-1-manual-0.60-6ubuntu8.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-dbus", pkgver: "0.60-6ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-dbus-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-dbus-0.60-6ubuntu8.4
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
