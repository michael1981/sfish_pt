# This script was automatically generated from the 834-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(41045);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "834-1");
script_summary(english:"postgresql-8.1, postgresql-8.3 vulnerabilities");
script_name(english:"USN834-1 : postgresql-8.1, postgresql-8.3 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libecpg-compat2 
- libecpg-compat3 
- libecpg-dev 
- libecpg5 
- libecpg6 
- libpgtypes2 
- libpgtypes3 
- libpq-dev 
- libpq4 
- libpq5 
- postgresql 
- postgresql-8.1 
- postgresql-8.3 
- postgresql-client 
- postgresql-client-8.1 
- postgresql-client-8.3 
- postgresql-contrib 
- postgresql-contrib-8.1 
- postgresql-contrib-8.3 
- postgresql-doc 
- postgresql-doc-8.1 
- postgresql-doc-8.3 
- postgresql-plperl-8.1 
- postgresql-plperl-8.3 
- postgresq
[...]');
script_set_attribute(attribute:'description', value: 'It was discovered that PostgreSQL could be made to unload and reload an
already loaded module by using the LOAD command. A remote authenticated
attacker could exploit this to cause a denial of service. This issue did
not affect Ubuntu 6.06 LTS. (CVE-2009-3229)

Due to an incomplete fix for CVE-2007-6600, RESET ROLE and RESET SESSION
AUTHORIZATION operations were allowed inside security-definer functions. A
remote authenticated attacker could exploit this to escalate privileges
within PostgreSQL. (CVE-2009-3230)

It was discovered that PostgreSQL did not properly perform LDAP
authentication under certain circumstances. When configured to use LDAP
with anonymous binds, a remote attacker could bypass authentication by
supplying an empty password. This issue did not affect Ubuntu 6.06 LTS.
(CVE-2009-3231)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libecpg-compat2-8.1.18-0ubuntu0.6.06 (Ubuntu 6.06)
- libecpg-compat3-8.3.8-0ubuntu9.04 (Ubuntu 9.04)
- libecpg-dev-8.3.8-0ubuntu9.04 (Ubuntu 9.04)
- libecpg5-8.1.18-0ubuntu0.6.06 (Ubuntu 6.06)
- libecpg6-8.3.8-0ubuntu9.04 (Ubuntu 9.04)
- libpgtypes2-8.1.18-0ubuntu0.6.06 (Ubuntu 6.06)
- libpgtypes3-8.3.8-0ubuntu9.04 (Ubuntu 9.04)
- libpq-dev-8.3.8-0ubuntu9.04 (Ubuntu 9.04)
- libpq4-8.1.18-0ubuntu0.6.06 (Ubuntu 6.06)
- libpq5-8.3.8-0ubuntu9.04 (Ubuntu 9.04)
- postgresql-8.3.8-0ubuntu9.04 (Ubu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-6600","CVE-2009-3229","CVE-2009-3230","CVE-2009-3231");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libecpg-compat2", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libecpg-compat2-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libecpg-compat3", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libecpg-compat3-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libecpg-dev", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libecpg-dev-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libecpg5", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg5-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libecpg5-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libecpg6", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg6-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libecpg6-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpgtypes2", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpgtypes2-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpgtypes3", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpgtypes3-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpq-dev", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpq-dev-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpq4", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpq4-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpq5", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq5-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpq5-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-8.1", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-8.1-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-8.3", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-8.3-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-client", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-client-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-client-8.1", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-client-8.1-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-client-8.3", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-client-8.3-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-contrib", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-contrib-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-contrib-8.1", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-contrib-8.1-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-contrib-8.3", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-contrib-8.3-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-doc", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-doc-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-doc-8.1", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-doc-8.1-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-doc-8.3", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-doc-8.3-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-plperl-8.1", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-plperl-8.1-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-plperl-8.3", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-plperl-8.3-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-plpython-8.1", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-plpython-8.1-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-plpython-8.3", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-plpython-8.3-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-pltcl-8.1", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-pltcl-8.1-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-pltcl-8.3", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-pltcl-8.3-8.3.8-0ubuntu9.04
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-server-dev-8.1", pkgver: "8.1.18-0ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-server-dev-8.1-8.1.18-0ubuntu0.6.06
');
}
found = ubuntu_check(osver: "9.04", pkgname: "postgresql-server-dev-8.3", pkgver: "8.3.8-0ubuntu9.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to postgresql-server-dev-8.3-8.3.8-0ubuntu9.04
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
