# This script was automatically generated from the 832-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(41006);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "832-1");
script_summary(english:"freeradius vulnerability");
script_name(english:"USN832-1 : freeradius vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- freeradius 
- freeradius-dbg 
- freeradius-dialupadmin 
- freeradius-iodbc 
- freeradius-krb5 
- freeradius-ldap 
- freeradius-mysql 
- freeradius-postgresql 
');
script_set_attribute(attribute:'description', value: 'It was discovered that FreeRADIUS did not correctly handle certain 
malformed attributes. A remote attacker could exploit this flaw and cause
the FreeRADIUS server to crash, resulting in a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- freeradius-1.1.7-1ubuntu0.2 (Ubuntu 8.04)
- freeradius-dbg-1.1.7-1ubuntu0.2 (Ubuntu 8.04)
- freeradius-dialupadmin-1.1.7-1ubuntu0.2 (Ubuntu 8.04)
- freeradius-iodbc-1.1.7-1ubuntu0.2 (Ubuntu 8.04)
- freeradius-krb5-1.1.7-1ubuntu0.2 (Ubuntu 8.04)
- freeradius-ldap-1.1.7-1ubuntu0.2 (Ubuntu 8.04)
- freeradius-mysql-1.1.7-1ubuntu0.2 (Ubuntu 8.04)
- freeradius-postgresql-1.1.7-1ubuntu0.2 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2009-3111");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "freeradius", pkgver: "1.1.7-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freeradius-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to freeradius-1.1.7-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "freeradius-dbg", pkgver: "1.1.7-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freeradius-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to freeradius-dbg-1.1.7-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "freeradius-dialupadmin", pkgver: "1.1.7-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freeradius-dialupadmin-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to freeradius-dialupadmin-1.1.7-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "freeradius-iodbc", pkgver: "1.1.7-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freeradius-iodbc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to freeradius-iodbc-1.1.7-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "freeradius-krb5", pkgver: "1.1.7-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freeradius-krb5-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to freeradius-krb5-1.1.7-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "freeradius-ldap", pkgver: "1.1.7-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freeradius-ldap-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to freeradius-ldap-1.1.7-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "freeradius-mysql", pkgver: "1.1.7-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freeradius-mysql-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to freeradius-mysql-1.1.7-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "freeradius-postgresql", pkgver: "1.1.7-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freeradius-postgresql-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to freeradius-postgresql-1.1.7-1ubuntu0.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
