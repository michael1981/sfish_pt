# This script was automatically generated from the 850-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42237);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "850-2");
script_summary(english:"poppler regression");
script_name(english:"USN850-2 : poppler regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpoppler-dev 
- libpoppler-glib-dev 
- libpoppler-glib2 
- libpoppler-glib3 
- libpoppler-glib4 
- libpoppler-qt-dev 
- libpoppler-qt2 
- libpoppler-qt4-2 
- libpoppler-qt4-3 
- libpoppler-qt4-dev 
- libpoppler1 
- libpoppler1-glib 
- libpoppler1-qt 
- libpoppler2 
- libpoppler3 
- libpoppler4 
- poppler-dbg 
- poppler-utils 
');
script_set_attribute(attribute:'description', value: 'USN-850-1 fixed vulnerabilities in poppler. The security fix for
CVE-2009-3605 introduced a regression that would cause certain
applications, such as Okular, to segfault when opening certain PDF files.

This update fixes the problem. We apologize for the inconvenience.

Original advisory details:

 It was discovered that poppler contained multiple security issues when
 parsing malformed PDF documents. If a user or automated system were tricked
 into opening a crafted PDF file, an attacker could cause a denial of
 service or execute arbitrary code with privileges of the user invoking the
 program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpoppler-dev-0.10.5-1ubuntu2.5 (Ubuntu 9.04)
- libpoppler-glib-dev-0.10.5-1ubuntu2.5 (Ubuntu 9.04)
- libpoppler-glib2-0.6.4-1ubuntu3.4 (Ubuntu 8.04)
- libpoppler-glib3-0.8.7-1ubuntu0.5 (Ubuntu 8.10)
- libpoppler-glib4-0.10.5-1ubuntu2.5 (Ubuntu 9.04)
- libpoppler-qt-dev-0.10.5-1ubuntu2.5 (Ubuntu 9.04)
- libpoppler-qt2-0.10.5-1ubuntu2.5 (Ubuntu 9.04)
- libpoppler-qt4-2-0.6.4-1ubuntu3.4 (Ubuntu 8.04)
- libpoppler-qt4-3-0.10.5-1ubuntu2.5 (Ubuntu 9.04)
- libpoppler-qt4-dev-0.10.5-1ubuntu2.5 (U
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-3605");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libpoppler-dev", pkgver: "0.10.5-1ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpoppler-dev-0.10.5-1ubuntu2.5
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpoppler-glib-dev", pkgver: "0.10.5-1ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-glib-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpoppler-glib-dev-0.10.5-1ubuntu2.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libpoppler-glib2", pkgver: "0.6.4-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-glib2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libpoppler-glib2-0.6.4-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpoppler-glib3", pkgver: "0.8.7-1ubuntu0.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-glib3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpoppler-glib3-0.8.7-1ubuntu0.5
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpoppler-glib4", pkgver: "0.10.5-1ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-glib4-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpoppler-glib4-0.10.5-1ubuntu2.5
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpoppler-qt-dev", pkgver: "0.10.5-1ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpoppler-qt-dev-0.10.5-1ubuntu2.5
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpoppler-qt2", pkgver: "0.10.5-1ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt2-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpoppler-qt2-0.10.5-1ubuntu2.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libpoppler-qt4-2", pkgver: "0.6.4-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt4-2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libpoppler-qt4-2-0.6.4-1ubuntu3.4
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpoppler-qt4-3", pkgver: "0.10.5-1ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt4-3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpoppler-qt4-3-0.10.5-1ubuntu2.5
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpoppler-qt4-dev", pkgver: "0.10.5-1ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt4-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpoppler-qt4-dev-0.10.5-1ubuntu2.5
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpoppler1", pkgver: "0.5.1-0ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpoppler1-0.5.1-0ubuntu7.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpoppler1-glib", pkgver: "0.5.1-0ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler1-glib-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpoppler1-glib-0.5.1-0ubuntu7.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpoppler1-qt", pkgver: "0.5.1-0ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler1-qt-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpoppler1-qt-0.5.1-0ubuntu7.7
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libpoppler2", pkgver: "0.6.4-1ubuntu3.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libpoppler2-0.6.4-1ubuntu3.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpoppler3", pkgver: "0.8.7-1ubuntu0.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpoppler3-0.8.7-1ubuntu0.5
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpoppler4", pkgver: "0.10.5-1ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler4-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpoppler4-0.10.5-1ubuntu2.5
');
}
found = ubuntu_check(osver: "9.04", pkgname: "poppler-dbg", pkgver: "0.10.5-1ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package poppler-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to poppler-dbg-0.10.5-1ubuntu2.5
');
}
found = ubuntu_check(osver: "9.04", pkgname: "poppler-utils", pkgver: "0.10.5-1ubuntu2.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package poppler-utils-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to poppler-utils-0.10.5-1ubuntu2.5
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
