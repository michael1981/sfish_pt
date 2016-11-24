# This script was automatically generated from the 829-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40944);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "829-1");
script_summary(english:"qt4-x11 vulnerability");
script_name(english:"USN829-1 : qt4-x11 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libqt4-assistant 
- libqt4-core 
- libqt4-dbg 
- libqt4-dbus 
- libqt4-debug 
- libqt4-designer 
- libqt4-dev 
- libqt4-dev-dbg 
- libqt4-gui 
- libqt4-help 
- libqt4-network 
- libqt4-opengl 
- libqt4-opengl-dev 
- libqt4-qt3support 
- libqt4-script 
- libqt4-scripttools 
- libqt4-sql 
- libqt4-sql-mysql 
- libqt4-sql-odbc 
- libqt4-sql-psql 
- libqt4-sql-sqlite 
- libqt4-sql-sqlite2 
- libqt4-svg 
- libqt4-test 
- libqt4-webkit 
- libqt4-webkit-dbg 

[...]');
script_set_attribute(attribute:'description', value: 'It was discovered that Qt did not properly handle certificates with NULL
characters in the Subject Alternative Name field of X.509 certificates. An
attacker could exploit this to perform a man in the middle attack to view
sensitive information or alter encrypted communications. (CVE-2009-2700)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libqt4-assistant-4.5.0-0ubuntu4.2 (Ubuntu 9.04)
- libqt4-core-4.5.0-0ubuntu4.2 (Ubuntu 9.04)
- libqt4-dbg-4.5.0-0ubuntu4.2 (Ubuntu 9.04)
- libqt4-dbus-4.5.0-0ubuntu4.2 (Ubuntu 9.04)
- libqt4-debug-4.3.4-0ubuntu3.1 (Ubuntu 8.04)
- libqt4-designer-4.5.0-0ubuntu4.2 (Ubuntu 9.04)
- libqt4-dev-4.5.0-0ubuntu4.2 (Ubuntu 9.04)
- libqt4-dev-dbg-4.5.0-0ubuntu4.2 (Ubuntu 9.04)
- libqt4-gui-4.5.0-0ubuntu4.2 (Ubuntu 9.04)
- libqt4-help-4.5.0-0ubuntu4.2 (Ubuntu 9.04)
- libqt4-network-4.5.0-0ubuntu4.2 (Ub
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2009-2700");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libqt4-assistant", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-assistant-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-assistant-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-core", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-core-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-core-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-dbg", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-dbg-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-dbus", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-dbus-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-dbus-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libqt4-debug", pkgver: "4.3.4-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-debug-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libqt4-debug-4.3.4-0ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-designer", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-designer-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-designer-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-dev", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-dev-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-dev-dbg", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-dev-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-dev-dbg-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-gui", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-gui-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-gui-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-help", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-help-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-help-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-network", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-network-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-network-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-opengl", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-opengl-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-opengl-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-opengl-dev", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-opengl-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-opengl-dev-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-qt3support", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-qt3support-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-qt3support-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-script", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-script-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-script-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-scripttools", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-scripttools-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-scripttools-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-sql", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-sql-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-sql-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-sql-mysql", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-sql-mysql-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-sql-mysql-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-sql-odbc", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-sql-odbc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-sql-odbc-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-sql-psql", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-sql-psql-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-sql-psql-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-sql-sqlite", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-sql-sqlite-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-sql-sqlite-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-sql-sqlite2", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-sql-sqlite2-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-sql-sqlite2-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-svg", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-svg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-svg-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-test", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-test-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-test-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-webkit", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-webkit-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-webkit-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-webkit-dbg", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-webkit-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-webkit-dbg-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-xml", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-xml-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-xml-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-xmlpatterns", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-xmlpatterns-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-xmlpatterns-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqt4-xmlpatterns-dbg", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-xmlpatterns-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqt4-xmlpatterns-dbg-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqtcore4", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqtcore4-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqtcore4-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libqtgui4", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqtgui4-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libqtgui4-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "qt4-demos", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-demos-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to qt4-demos-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "qt4-demos-dbg", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-demos-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to qt4-demos-dbg-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "qt4-designer", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-designer-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to qt4-designer-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "qt4-dev-tools", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-dev-tools-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to qt4-dev-tools-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "qt4-dev-tools-dbg", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-dev-tools-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to qt4-dev-tools-dbg-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "qt4-doc", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to qt4-doc-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "qt4-doc-html", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-doc-html-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to qt4-doc-html-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "qt4-qmake", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-qmake-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to qt4-qmake-4.5.0-0ubuntu4.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "qt4-qtconfig", pkgver: "4.5.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-qtconfig-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to qt4-qtconfig-4.5.0-0ubuntu4.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
