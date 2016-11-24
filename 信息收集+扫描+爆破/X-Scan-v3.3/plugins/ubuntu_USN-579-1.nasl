# This script was automatically generated from the 579-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31164);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "579-1");
script_summary(english:"Qt vulnerability");
script_name(english:"USN579-1 : Qt vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libqt4-core 
- libqt4-debug 
- libqt4-dev 
- libqt4-gui 
- libqt4-qt3support 
- libqt4-sql 
- qt4-designer 
- qt4-dev-tools 
- qt4-doc 
- qt4-qtconfig 
');
script_set_attribute(attribute:'description', value: 'It was discovered that QSslSocket did not properly verify SSL
certificates. A remote attacker may be able to trick applications
using QSslSocket into accepting invalid SSL certificates.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libqt4-core-4.3.2-0ubuntu3.2 (Ubuntu 7.10)
- libqt4-debug-4.3.2-0ubuntu3.2 (Ubuntu 7.10)
- libqt4-dev-4.3.2-0ubuntu3.2 (Ubuntu 7.10)
- libqt4-gui-4.3.2-0ubuntu3.2 (Ubuntu 7.10)
- libqt4-qt3support-4.3.2-0ubuntu3.2 (Ubuntu 7.10)
- libqt4-sql-4.3.2-0ubuntu3.2 (Ubuntu 7.10)
- qt4-designer-4.3.2-0ubuntu3.2 (Ubuntu 7.10)
- qt4-dev-tools-4.3.2-0ubuntu3.2 (Ubuntu 7.10)
- qt4-doc-4.3.2-0ubuntu3.2 (Ubuntu 7.10)
- qt4-qtconfig-4.3.2-0ubuntu3.2 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2007-5965");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libqt4-core", pkgver: "4.3.2-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-core-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libqt4-core-4.3.2-0ubuntu3.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libqt4-debug", pkgver: "4.3.2-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-debug-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libqt4-debug-4.3.2-0ubuntu3.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libqt4-dev", pkgver: "4.3.2-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libqt4-dev-4.3.2-0ubuntu3.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libqt4-gui", pkgver: "4.3.2-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-gui-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libqt4-gui-4.3.2-0ubuntu3.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libqt4-qt3support", pkgver: "4.3.2-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-qt3support-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libqt4-qt3support-4.3.2-0ubuntu3.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libqt4-sql", pkgver: "4.3.2-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libqt4-sql-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libqt4-sql-4.3.2-0ubuntu3.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "qt4-designer", pkgver: "4.3.2-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-designer-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to qt4-designer-4.3.2-0ubuntu3.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "qt4-dev-tools", pkgver: "4.3.2-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-dev-tools-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to qt4-dev-tools-4.3.2-0ubuntu3.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "qt4-doc", pkgver: "4.3.2-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to qt4-doc-4.3.2-0ubuntu3.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "qt4-qtconfig", pkgver: "4.3.2-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package qt4-qtconfig-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to qt4-qtconfig-4.3.2-0ubuntu3.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
