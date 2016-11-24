# This script was automatically generated from the 368-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27948);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "368-1");
script_summary(english:"Qt vulnerability");
script_name(english:"USN368-1 : Qt vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libqt3-compat-headers 
- libqt3-dev 
- libqt3-headers 
- libqt3-i18n 
- libqt3-mt 
- libqt3-mt-dbg 
- libqt3-mt-dev 
- libqt3-mt-ibase 
- libqt3-mt-mysql 
- libqt3-mt-odbc 
- libqt3-mt-psql 
- libqt3-mt-sqlite 
- libqt3c102 
- libqt3c102-mt 
- libqt3c102-mt-mysql 
- libqt3c102-mt-odbc 
- libqt3c102-mt-psql 
- libqt3c102-mt-sqlite 
- libqt3c102-mysql 
- libqt3c102-odbc 
- libqt3c102-psql 
- libqt3c102-sqlite 
- qt-x11-free-dbg 
- qt3-apps-dev 
- qt3-ass
[...]');
script_set_attribute(attribute:'description', value: 'An integer overflow was discovered in Qt\'s image loader. By processing
a specially crafted image with an application that uses this library
(like Konqueror), a remote attacker could exploit this to execute
arbitrary code with the application\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libqt3-compat-headers-3.3.6-1ubuntu6.1 (Ubuntu 6.06)
- libqt3-dev-3.3.3-7ubuntu3.1 (Ubuntu 5.04)
- libqt3-headers-3.3.6-1ubuntu6.1 (Ubuntu 6.06)
- libqt3-i18n-3.3.6-1ubuntu6.1 (Ubuntu 6.06)
- libqt3-mt-3.3.6-1ubuntu6.1 (Ubuntu 6.06)
- libqt3-mt-dbg-3.3.4-8ubuntu5.1 (Ubuntu 5.10)
- libqt3-mt-dev-3.3.6-1ubuntu6.1 (Ubuntu 6.06)
- libqt3-mt-ibase-3.3.4-8ubuntu5.1 (Ubuntu 5.10)
- libqt3-mt-mysql-3.3.6-1ubuntu6.1 (Ubuntu 6.06)
- libqt3-mt-odbc-3.3.6-1ubuntu6.1 (Ubuntu 6.06)
- libqt3-mt-psql-3.3.6
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4811");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libqt3-compat-headers", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-compat-headers-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libqt3-compat-headers-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3-dev", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3-dev-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libqt3-headers", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-headers-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libqt3-headers-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libqt3-i18n", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-i18n-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libqt3-i18n-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libqt3-mt", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-mt-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libqt3-mt-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libqt3-mt-dbg", pkgver: "3.3.4-8ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-mt-dbg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libqt3-mt-dbg-3.3.4-8ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libqt3-mt-dev", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-mt-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libqt3-mt-dev-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libqt3-mt-ibase", pkgver: "3.3.4-8ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-mt-ibase-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libqt3-mt-ibase-3.3.4-8ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libqt3-mt-mysql", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-mt-mysql-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libqt3-mt-mysql-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libqt3-mt-odbc", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-mt-odbc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libqt3-mt-odbc-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libqt3-mt-psql", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-mt-psql-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libqt3-mt-psql-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libqt3-mt-sqlite", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3-mt-sqlite-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libqt3-mt-sqlite-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3c102", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3c102-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3c102-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3c102-mt", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3c102-mt-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3c102-mt-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3c102-mt-mysql", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3c102-mt-mysql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3c102-mt-mysql-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3c102-mt-odbc", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3c102-mt-odbc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3c102-mt-odbc-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3c102-mt-psql", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3c102-mt-psql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3c102-mt-psql-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3c102-mt-sqlite", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3c102-mt-sqlite-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3c102-mt-sqlite-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3c102-mysql", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3c102-mysql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3c102-mysql-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3c102-odbc", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3c102-odbc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3c102-odbc-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3c102-psql", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3c102-psql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3c102-psql-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libqt3c102-sqlite", pkgver: "3.3.3-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt3c102-sqlite-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libqt3c102-sqlite-3.3.3-7ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt-x11-free-dbg", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt-x11-free-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt-x11-free-dbg-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt3-apps-dev", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt3-apps-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt3-apps-dev-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt3-assistant", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt3-assistant-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt3-assistant-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt3-designer", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt3-designer-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt3-designer-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt3-dev-tools", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt3-dev-tools-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt3-dev-tools-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt3-dev-tools-compat", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt3-dev-tools-compat-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt3-dev-tools-compat-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt3-dev-tools-embedded", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt3-dev-tools-embedded-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt3-dev-tools-embedded-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt3-doc", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt3-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt3-doc-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt3-examples", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt3-examples-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt3-examples-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt3-linguist", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt3-linguist-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt3-linguist-3.3.6-1ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "qt3-qtconfig", pkgver: "3.3.6-1ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt3-qtconfig-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to qt3-qtconfig-3.3.6-1ubuntu6.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
