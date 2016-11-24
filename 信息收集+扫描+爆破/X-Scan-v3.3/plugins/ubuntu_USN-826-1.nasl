# This script was automatically generated from the 826-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40794);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "826-1");
script_summary(english:"mono vulnerabilities");
script_name(english:"USN826-1 : mono vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmono-accessibility1.0-cil 
- libmono-accessibility2.0-cil 
- libmono-bytefx0.7.6.1-cil 
- libmono-bytefx0.7.6.2-cil 
- libmono-c5-1.0-cil 
- libmono-cairo1.0-cil 
- libmono-cairo2.0-cil 
- libmono-corlib1.0-cil 
- libmono-corlib2.0-cil 
- libmono-corlib2.1-cil 
- libmono-cscompmgd7.0-cil 
- libmono-cscompmgd8.0-cil 
- libmono-data-tds1.0-cil 
- libmono-data-tds2.0-cil 
- libmono-data1.0-cil 
- libmono-data2.0-cil 
- libmono-db2-1.0-cil 
- libmono-de
[...]');
script_set_attribute(attribute:'description', value: 'It was discovered that the XML HMAC signature system did not correctly
check certain lengths. If an attacker sent a truncated HMAC, it could
bypass authentication, leading to potential privilege escalation.
(CVE-2009-0217)

It was discovered that Mono did not properly escape certain attributes in
the ASP.net class libraries which could result in browsers becoming
vulnerable to cross-site scripting attacks when processing the output. With
cross-site scripting vulnerabilities, if a user were tricked into viewing
server output during a crafted server request, a remote attacker could
exploit this to modify the contents, or steal confidential data (such as
passwords), within the same domain. This issue only affected Ubuntu 8.04
LTS. (CVE-2008-3422)

It was discovered that Mono did not properly filter CRLF injections in the
query string. If a user were tricked into viewing server output during a
crafted server request, a remote attacker could exploit this to modify the
contents, steal confidential data (such as pa
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmono-accessibility1.0-cil-2.0.1-4ubuntu0.1 (Ubuntu 9.04)
- libmono-accessibility2.0-cil-2.0.1-4ubuntu0.1 (Ubuntu 9.04)
- libmono-bytefx0.7.6.1-cil-2.0.1-4ubuntu0.1 (Ubuntu 9.04)
- libmono-bytefx0.7.6.2-cil-2.0.1-4ubuntu0.1 (Ubuntu 9.04)
- libmono-c5-1.0-cil-2.0.1-4ubuntu0.1 (Ubuntu 9.04)
- libmono-cairo1.0-cil-2.0.1-4ubuntu0.1 (Ubuntu 9.04)
- libmono-cairo2.0-cil-2.0.1-4ubuntu0.1 (Ubuntu 9.04)
- libmono-corlib1.0-cil-2.0.1-4ubuntu0.1 (Ubuntu 9.04)
- libmono-corlib2.0-cil-2.0.1-4ubuntu0.1
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2008-3422","CVE-2008-3906","CVE-2009-0217");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libmono-accessibility1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-accessibility1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-accessibility1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-accessibility2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-accessibility2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-accessibility2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-bytefx0.7.6.1-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-bytefx0.7.6.1-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-bytefx0.7.6.1-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-bytefx0.7.6.2-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-bytefx0.7.6.2-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-bytefx0.7.6.2-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-c5-1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-c5-1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-c5-1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-cairo1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-cairo1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-cairo1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-cairo2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-cairo2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-cairo2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-corlib1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-corlib1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-corlib1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-corlib2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-corlib2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-corlib2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-corlib2.1-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-corlib2.1-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-corlib2.1-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-cscompmgd7.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-cscompmgd7.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-cscompmgd7.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-cscompmgd8.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-cscompmgd8.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-cscompmgd8.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-data-tds1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-data-tds1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-data-tds1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-data-tds2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-data-tds2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-data-tds2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-data1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-data1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-data1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-data2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-data2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-data2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-db2-1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-db2-1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-db2-1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-dev", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-dev-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-firebirdsql1.7-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-firebirdsql1.7-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-firebirdsql1.7-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-getoptions1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-getoptions1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-getoptions1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-getoptions2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-getoptions2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-getoptions2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-i18n1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-i18n1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-i18n1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-i18n2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-i18n2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-i18n2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-ldap1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-ldap1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-ldap1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-ldap2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-ldap2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-ldap2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-microsoft-build2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-microsoft-build2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-microsoft-build2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-microsoft7.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-microsoft7.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-microsoft7.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-microsoft8.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-microsoft8.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-microsoft8.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libmono-mozilla0.1-cil", pkgver: "1.2.6+dfsg-6ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-mozilla0.1-cil-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libmono-mozilla0.1-cil-1.2.6+dfsg-6ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libmono-mozilla0.2-cil", pkgver: "1.9.1+dfsg-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-mozilla0.2-cil-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libmono-mozilla0.2-cil-1.9.1+dfsg-4ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-npgsql1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-npgsql1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-npgsql1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-npgsql2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-npgsql2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-npgsql2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-nunit2.2-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-nunit2.2-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-nunit2.2-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-oracle1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-oracle1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-oracle1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-oracle2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-oracle2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-oracle2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-peapi1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-peapi1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-peapi1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-peapi2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-peapi2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-peapi2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-posix1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-posix1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-posix1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-posix2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-posix2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-posix2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-relaxng1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-relaxng1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-relaxng1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-relaxng2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-relaxng2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-relaxng2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-security1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-security1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-security1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-security2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-security2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-security2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-sharpzip0.6-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sharpzip0.6-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-sharpzip0.6-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-sharpzip0.84-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sharpzip0.84-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-sharpzip0.84-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-sharpzip2.6-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sharpzip2.6-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-sharpzip2.6-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-sharpzip2.84-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sharpzip2.84-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-sharpzip2.84-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-sqlite1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sqlite1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-sqlite1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-sqlite2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sqlite2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-sqlite2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system-data1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-data1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system-data1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system-data2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-data2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system-data2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system-ldap1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-ldap1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system-ldap1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system-ldap2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-ldap2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system-ldap2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system-messaging1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-messaging1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system-messaging1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system-messaging2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-messaging2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system-messaging2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system-runtime1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-runtime1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system-runtime1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system-runtime2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-runtime2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system-runtime2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system-web1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-web1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system-web1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system-web2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-web2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system-web2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-system2.1-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system2.1-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-system2.1-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-webbrowser0.5-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-webbrowser0.5-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-webbrowser0.5-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-winforms1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-winforms1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-winforms1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono-winforms2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-winforms2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono-winforms2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono0", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono0-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono0-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono0-dbg", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono0-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono0-dbg-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono1.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono1.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono1.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libmono2.0-cil", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono2.0-cil-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libmono2.0-cil-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-1.0-devel", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-1.0-devel-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-1.0-devel-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-1.0-gac", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-1.0-gac-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-1.0-gac-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-1.0-runtime", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-1.0-runtime-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-1.0-runtime-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-1.0-service", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-1.0-service-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-1.0-service-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-2.0-devel", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-2.0-devel-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-2.0-devel-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-2.0-gac", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-2.0-gac-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-2.0-gac-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-2.0-runtime", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-2.0-runtime-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-2.0-runtime-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-2.0-service", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-2.0-service-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-2.0-service-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-common", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-common-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-dbg", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-dbg-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-devel", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-devel-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-devel-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-gac", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-gac-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-gac-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-gmcs", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-gmcs-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-gmcs-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-jay", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-jay-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-jay-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-jit", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-jit-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-jit-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-jit-dbg", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-jit-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-jit-dbg-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-mcs", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-mcs-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-mcs-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-mjs", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-mjs-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-mjs-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-runtime", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-runtime-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-runtime-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-smcs", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-smcs-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-smcs-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-utils", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-utils-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-utils-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mono-xbuild", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-xbuild-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mono-xbuild-2.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "prj2make-sharp", pkgver: "2.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package prj2make-sharp-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to prj2make-sharp-2.0.1-4ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
