# This script was automatically generated from the 850-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42344);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "850-3");
script_summary(english:"poppler vulnerabilities");
script_name(english:"USN850-3 : poppler vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpoppler-dev 
- libpoppler-glib-dev 
- libpoppler-glib4 
- libpoppler-qt-dev 
- libpoppler-qt2 
- libpoppler-qt4-3 
- libpoppler-qt4-dev 
- libpoppler5 
- poppler-dbg 
- poppler-utils 
');
script_set_attribute(attribute:'description', value: 'USN-850-1 fixed vulnerabilities in poppler. This update provides the
corresponding updates for Ubuntu 9.10.

Original advisory details:

 It was discovered that poppler contained multiple security issues when
 parsing malformed PDF documents. If a user or automated system were tricked
 into opening a crafted PDF file, an attacker could cause a denial of
 service or execute arbitrary code with privileges of the user invoking the
 program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpoppler-dev-0.12.0-0ubuntu2.1 (Ubuntu 9.10)
- libpoppler-glib-dev-0.12.0-0ubuntu2.1 (Ubuntu 9.10)
- libpoppler-glib4-0.12.0-0ubuntu2.1 (Ubuntu 9.10)
- libpoppler-qt-dev-0.12.0-0ubuntu2.1 (Ubuntu 9.10)
- libpoppler-qt2-0.12.0-0ubuntu2.1 (Ubuntu 9.10)
- libpoppler-qt4-3-0.12.0-0ubuntu2.1 (Ubuntu 9.10)
- libpoppler-qt4-dev-0.12.0-0ubuntu2.1 (Ubuntu 9.10)
- libpoppler5-0.12.0-0ubuntu2.1 (Ubuntu 9.10)
- poppler-dbg-0.12.0-0ubuntu2.1 (Ubuntu 9.10)
- poppler-utils-0.12.0-0ubuntu2.1 (Ubuntu 9.10
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-3603","CVE-2009-3604","CVE-2009-3607","CVE-2009-3608","CVE-2009-3609");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.10", pkgname: "libpoppler-dev", pkgver: "0.12.0-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to libpoppler-dev-0.12.0-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "libpoppler-glib-dev", pkgver: "0.12.0-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-glib-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to libpoppler-glib-dev-0.12.0-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "libpoppler-glib4", pkgver: "0.12.0-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-glib4-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to libpoppler-glib4-0.12.0-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "libpoppler-qt-dev", pkgver: "0.12.0-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to libpoppler-qt-dev-0.12.0-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "libpoppler-qt2", pkgver: "0.12.0-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt2-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to libpoppler-qt2-0.12.0-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "libpoppler-qt4-3", pkgver: "0.12.0-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt4-3-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to libpoppler-qt4-3-0.12.0-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "libpoppler-qt4-dev", pkgver: "0.12.0-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler-qt4-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to libpoppler-qt4-dev-0.12.0-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "libpoppler5", pkgver: "0.12.0-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpoppler5-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to libpoppler5-0.12.0-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "poppler-dbg", pkgver: "0.12.0-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package poppler-dbg-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to poppler-dbg-0.12.0-0ubuntu2.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "poppler-utils", pkgver: "0.12.0-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package poppler-utils-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to poppler-utils-0.12.0-0ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
