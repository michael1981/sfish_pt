# This script was automatically generated from the 568-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29978);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "568-1");
script_summary(english:"PostgreSQL vulnerabilities");
script_name(english:"USN568-1 : PostgreSQL vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libecpg-compat2 
- libecpg-dev 
- libecpg5 
- libpgtypes2 
- libpq-dev 
- libpq4 
- libpq5 
- postgresql 
- postgresql-8.1 
- postgresql-8.2 
- postgresql-client 
- postgresql-client-8.1 
- postgresql-client-8.2 
- postgresql-contrib 
- postgresql-contrib-8.1 
- postgresql-contrib-8.2 
- postgresql-doc 
- postgresql-doc-8.1 
- postgresql-doc-8.2 
- postgresql-plperl-8.1 
- postgresql-plperl-8.2 
- postgresql-plpython-8.1 
- postgresql-plpython-8.2 
- p
[...]');
script_set_attribute(attribute:'description', value: 'Nico Leidecker discovered that PostgreSQL did not properly
restrict dblink functions. An authenticated user could exploit
this flaw to access arbitrary accounts and execute arbitrary
SQL queries. (CVE-2007-3278, CVE-2007-6601)

It was discovered that the TCL regular expression parser used
by PostgreSQL did not properly check its input. An attacker
could send crafted regular expressions to PostgreSQL and cause
a denial of service via resource exhaustion or database crash.
(CVE-2007-4769, CVE-2007-4772, CVE-2007-6067)

It was discovered that PostgreSQL executed VACUUM and ANALYZE
operations within index functions with superuser privileges and
also allowed SET ROLE and SET SESSION AUTHORIZATION within index
functions. A remote authenticated user could exploit these flaws
to gain privileges. (CVE-2007-6600)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libecpg-compat2-8.2.6-0ubuntu0.7.10.1 (Ubuntu 7.10)
- libecpg-dev-8.2.6-0ubuntu0.7.10.1 (Ubuntu 7.10)
- libecpg5-8.2.6-0ubuntu0.7.10.1 (Ubuntu 7.10)
- libpgtypes2-8.2.6-0ubuntu0.7.10.1 (Ubuntu 7.10)
- libpq-dev-8.2.6-0ubuntu0.7.10.1 (Ubuntu 7.10)
- libpq4-8.1.11-0ubuntu0.6.10.1 (Ubuntu 6.10)
- libpq5-8.2.6-0ubuntu0.7.10.1 (Ubuntu 7.10)
- postgresql-8.2.6-0ubuntu0.7.10.1 (Ubuntu 7.10)
- postgresql-8.1-8.1.11-0ubuntu0.6.10.1 (Ubuntu 6.10)
- postgresql-8.2-8.2.6-0ubuntu0.7.10.1 (Ubuntu 7.10)
-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-3278","CVE-2007-4769","CVE-2007-4772","CVE-2007-6067","CVE-2007-6600","CVE-2007-6601");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libecpg-compat2", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libecpg-compat2-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libecpg-dev", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libecpg-dev-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libecpg5", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg5-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libecpg5-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpgtypes2", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpgtypes2-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpq-dev", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpq-dev-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpq4", pkgver: "8.1.11-0ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq4-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpq4-8.1.11-0ubuntu0.6.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpq5", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq5-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpq5-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-8.1", pkgver: "8.1.11-0ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-8.1-8.1.11-0ubuntu0.6.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-8.2", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-8.2-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-client", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-client-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-client-8.1", pkgver: "8.1.11-0ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-client-8.1-8.1.11-0ubuntu0.6.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-client-8.2", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-client-8.2-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-contrib", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-contrib-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-contrib-8.1", pkgver: "8.1.11-0ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-contrib-8.1-8.1.11-0ubuntu0.6.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-contrib-8.2", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-contrib-8.2-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-doc", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-doc-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-doc-8.1", pkgver: "8.1.11-0ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-doc-8.1-8.1.11-0ubuntu0.6.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-doc-8.2", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-doc-8.2-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-plperl-8.1", pkgver: "8.1.11-0ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-plperl-8.1-8.1.11-0ubuntu0.6.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-plperl-8.2", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-plperl-8.2-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-plpython-8.1", pkgver: "8.1.11-0ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-plpython-8.1-8.1.11-0ubuntu0.6.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-plpython-8.2", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-plpython-8.2-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-pltcl-8.1", pkgver: "8.1.11-0ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-pltcl-8.1-8.1.11-0ubuntu0.6.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-pltcl-8.2", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-pltcl-8.2-8.2.6-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-server-dev-8.1", pkgver: "8.1.11-0ubuntu0.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-server-dev-8.1-8.1.11-0ubuntu0.6.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "postgresql-server-dev-8.2", pkgver: "8.2.6-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to postgresql-server-dev-8.2-8.2.6-0ubuntu0.7.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
