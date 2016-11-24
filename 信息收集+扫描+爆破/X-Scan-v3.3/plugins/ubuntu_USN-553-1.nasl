# This script was automatically generated from the 553-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29238);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "553-1");
script_summary(english:"Mono vulnerability");
script_name(english:"USN553-1 : Mono vulnerability");
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
- libmono-cscompmgd7.0-cil 
- libmono-cscompmgd8.0-cil 
- libmono-data-tds1.0-cil 
- libmono-data-tds2.0-cil 
- libmono-dev 
- libmono-firebirdsql1.7-cil 
- libmono-ldap1.0-cil 
- libmono-ldap2.0-cil 
- libmono-micro
[...]');
script_set_attribute(attribute:'description', value: 'It was discovered that Mono did not correctly bounds check certain BigInteger
actions.  Remote attackers could exploit this to crash a Mono application or
possibly execute arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmono-accessibility1.0-cil-1.2.4-6ubuntu6.1 (Ubuntu 7.10)
- libmono-accessibility2.0-cil-1.2.4-6ubuntu6.1 (Ubuntu 7.10)
- libmono-bytefx0.7.6.1-cil-1.2.4-6ubuntu6.1 (Ubuntu 7.10)
- libmono-bytefx0.7.6.2-cil-1.2.4-6ubuntu6.1 (Ubuntu 7.10)
- libmono-c5-1.0-cil-1.2.4-6ubuntu6.1 (Ubuntu 7.10)
- libmono-cairo1.0-cil-1.2.4-6ubuntu6.1 (Ubuntu 7.10)
- libmono-cairo2.0-cil-1.2.4-6ubuntu6.1 (Ubuntu 7.10)
- libmono-corlib1.0-cil-1.2.4-6ubuntu6.1 (Ubuntu 7.10)
- libmono-corlib2.0-cil-1.2.4-6ubuntu6.1
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-5197");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libmono-accessibility1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-accessibility1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-accessibility1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-accessibility2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-accessibility2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-accessibility2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-bytefx0.7.6.1-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-bytefx0.7.6.1-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-bytefx0.7.6.1-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-bytefx0.7.6.2-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-bytefx0.7.6.2-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-bytefx0.7.6.2-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-c5-1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-c5-1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-c5-1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-cairo1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-cairo1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-cairo1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-cairo2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-cairo2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-cairo2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-corlib1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-corlib1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-corlib1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-corlib2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-corlib2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-corlib2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-cscompmgd7.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-cscompmgd7.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-cscompmgd7.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-cscompmgd8.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-cscompmgd8.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-cscompmgd8.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-data-tds1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-data-tds1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-data-tds1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-data-tds2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-data-tds2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-data-tds2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-dev", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-dev-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-firebirdsql1.7-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-firebirdsql1.7-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-firebirdsql1.7-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-ldap1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-ldap1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-ldap1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-ldap2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-ldap2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-ldap2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-microsoft-build2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-microsoft-build2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-microsoft-build2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-microsoft7.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-microsoft7.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-microsoft7.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-microsoft8.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-microsoft8.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-microsoft8.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-npgsql1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-npgsql1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-npgsql1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-npgsql2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-npgsql2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-npgsql2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-oracle1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-oracle1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-oracle1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-oracle2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-oracle2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-oracle2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-peapi1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-peapi1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-peapi1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-peapi2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-peapi2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-peapi2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-relaxng1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-relaxng1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-relaxng1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-relaxng2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-relaxng2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-relaxng2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-security1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-security1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-security1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-security2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-security2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-security2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-sharpzip0.6-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sharpzip0.6-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-sharpzip0.6-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-sharpzip0.84-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sharpzip0.84-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-sharpzip0.84-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-sharpzip2.6-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sharpzip2.6-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-sharpzip2.6-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-sharpzip2.84-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sharpzip2.84-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-sharpzip2.84-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-sqlite1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sqlite1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-sqlite1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-sqlite2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-sqlite2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-sqlite2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system-data1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-data1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system-data1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system-data2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-data2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system-data2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system-ldap1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-ldap1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system-ldap1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system-ldap2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-ldap2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system-ldap2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system-messaging1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-messaging1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system-messaging1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system-messaging2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-messaging2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system-messaging2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system-runtime1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-runtime1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system-runtime1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system-runtime2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-runtime2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system-runtime2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system-web1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-web1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system-web1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system-web2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system-web2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system-web2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-system2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-system2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-system2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-winforms1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-winforms1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-winforms1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono-winforms2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono-winforms2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono-winforms2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono0", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono0-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono0-dbg", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono0-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono0-dbg-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono1.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono1.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono1.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmono2.0-cil", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmono2.0-cil-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmono2.0-cil-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-assemblies-base", pkgver: "1.1.13.6-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-assemblies-base-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-assemblies-base-1.1.13.6-0ubuntu3.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mono-classlib-1.0", pkgver: "1.1.17.1-1ubuntu7.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-classlib-1.0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mono-classlib-1.0-1.1.17.1-1ubuntu7.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-classlib-1.0-dbg", pkgver: "1.1.13.6-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-classlib-1.0-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-classlib-1.0-dbg-1.1.13.6-0ubuntu3.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mono-classlib-2.0", pkgver: "1.1.17.1-1ubuntu7.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-classlib-2.0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mono-classlib-2.0-1.1.17.1-1ubuntu7.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mono-classlib-2.0-dbg", pkgver: "1.1.13.6-0ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-classlib-2.0-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mono-classlib-2.0-dbg-1.1.13.6-0ubuntu3.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-common", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-common-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-dbg", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-dbg-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-devel", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-devel-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-devel-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-gac", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-gac-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-gac-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-gmcs", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-gmcs-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-gmcs-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-jay", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-jay-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-jay-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-jit", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-jit-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-jit-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-jit-dbg", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-jit-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-jit-dbg-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-mcs", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-mcs-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-mcs-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-mjs", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-mjs-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-mjs-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-runtime", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-runtime-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-runtime-1.2.4-6ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mono-utils", pkgver: "1.2.4-6ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mono-utils-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mono-utils-1.2.4-6ubuntu6.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
