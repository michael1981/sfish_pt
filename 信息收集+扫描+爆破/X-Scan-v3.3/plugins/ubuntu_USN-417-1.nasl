# This script was automatically generated from the 417-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28007);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "417-1");
script_summary(english:"PostgreSQL vulnerabilities");
script_name(english:"USN417-1 : PostgreSQL vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libecpg-compat2 
- libecpg-dev 
- libecpg5 
- libpgtypes2 
- libpq-dev 
- libpq3 
- libpq4 
- postgresql-7.4 
- postgresql-8.0 
- postgresql-8.1 
- postgresql-client-7.4 
- postgresql-client-8.0 
- postgresql-client-8.1 
- postgresql-contrib-7.4 
- postgresql-contrib-8.0 
- postgresql-contrib-8.1 
- postgresql-doc-7.4 
- postgresql-doc-8.0 
- postgresql-doc-8.1 
- postgresql-plperl-7.4 
- postgresql-plperl-8.0 
- postgresql-plperl-8.1 
- postgresql-plp
[...]');
script_set_attribute(attribute:'description', value: 'Jeff Trout discovered that the PostgreSQL server did not sufficiently
check data types of SQL function arguments in some cases. An
authenticated attacker could exploit this to crash the database server
or read out arbitrary locations in the server\'s memory, which could
allow retrieving database content the attacker should not be able to
see. (CVE-2007-0555)

Jeff Trout reported that the query planner did not verify that a table
was still compatible with a previously made query plan. By using ALTER
COLUMN TYPE during query execution, an attacker could exploit this to
read out arbitrary locations in the server\'s memory, which could allow
retrieving database content the attacker should not be able to see.
(CVE-2007-0556)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libecpg-compat2-8.1.4-7ubuntu0.2 (Ubuntu 6.10)
- libecpg-dev-8.1.4-7ubuntu0.2 (Ubuntu 6.10)
- libecpg5-8.1.4-7ubuntu0.2 (Ubuntu 6.10)
- libpgtypes2-8.1.4-7ubuntu0.2 (Ubuntu 6.10)
- libpq-dev-8.1.4-7ubuntu0.2 (Ubuntu 6.10)
- libpq3-7.4.8-17ubuntu1.4 (Ubuntu 5.10)
- libpq4-8.1.4-7ubuntu0.2 (Ubuntu 6.10)
- postgresql-7.4-7.4.8-17ubuntu1.4 (Ubuntu 5.10)
- postgresql-8.0-8.0.3-15ubuntu2.3 (Ubuntu 5.10)
- postgresql-8.1-8.1.4-7ubuntu0.2 (Ubuntu 6.10)
- postgresql-client-7.4-7.4.8-17ubuntu1.4 (Ubu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:C/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2007-0555","CVE-2007-0556");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libecpg-compat2", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libecpg-compat2-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libecpg-dev", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libecpg-dev-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libecpg5", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg5-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libecpg5-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpgtypes2", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpgtypes2-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpq-dev", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpq-dev-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libpq3", pkgver: "7.4.8-17ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libpq3-7.4.8-17ubuntu1.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpq4", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq4-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpq4-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-7.4", pkgver: "7.4.8-17ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-7.4-7.4.8-17ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-8.0", pkgver: "8.0.3-15ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-8.0-8.0.3-15ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-8.1", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-8.1-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-client-7.4", pkgver: "7.4.8-17ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-client-7.4-7.4.8-17ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-client-8.0", pkgver: "8.0.3-15ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-client-8.0-8.0.3-15ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-client-8.1", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-client-8.1-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-contrib-7.4", pkgver: "7.4.8-17ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-contrib-7.4-7.4.8-17ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-contrib-8.0", pkgver: "8.0.3-15ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-contrib-8.0-8.0.3-15ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-contrib-8.1", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-contrib-8.1-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-doc-7.4", pkgver: "7.4.8-17ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-doc-7.4-7.4.8-17ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-doc-8.0", pkgver: "8.0.3-15ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-doc-8.0-8.0.3-15ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-doc-8.1", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-doc-8.1-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-plperl-7.4", pkgver: "7.4.8-17ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-plperl-7.4-7.4.8-17ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-plperl-8.0", pkgver: "8.0.3-15ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-plperl-8.0-8.0.3-15ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-plperl-8.1", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-plperl-8.1-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-plpython-7.4", pkgver: "7.4.8-17ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-plpython-7.4-7.4.8-17ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-plpython-8.0", pkgver: "8.0.3-15ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-plpython-8.0-8.0.3-15ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-plpython-8.1", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-plpython-8.1-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-pltcl-7.4", pkgver: "7.4.8-17ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-pltcl-7.4-7.4.8-17ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-pltcl-8.0", pkgver: "8.0.3-15ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-pltcl-8.0-8.0.3-15ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-pltcl-8.1", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-pltcl-8.1-8.1.4-7ubuntu0.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-server-dev-7.4", pkgver: "7.4.8-17ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-7.4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-server-dev-7.4-7.4.8-17ubuntu1.4
');
}
found = ubuntu_check(osver: "5.10", pkgname: "postgresql-server-dev-8.0", pkgver: "8.0.3-15ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.0-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to postgresql-server-dev-8.0-8.0.3-15ubuntu2.3
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-server-dev-8.1", pkgver: "8.1.4-7ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-server-dev-8.1-8.1.4-7ubuntu0.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
