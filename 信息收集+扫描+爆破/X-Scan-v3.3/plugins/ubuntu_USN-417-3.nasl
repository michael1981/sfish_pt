# This script was automatically generated from the 417-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28009);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "417-3");
script_summary(english:"PostgreSQL regression");
script_name(english:"USN417-3 : PostgreSQL regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libecpg-compat2 
- libecpg-dev 
- libecpg5 
- libpgtypes2 
- libpq-dev 
- libpq4 
- postgresql-8.1 
- postgresql-client-8.1 
- postgresql-contrib-8.1 
- postgresql-doc-8.1 
- postgresql-plperl-8.1 
- postgresql-plpython-8.1 
- postgresql-pltcl-8.1 
- postgresql-server-dev-8.1 
');
script_set_attribute(attribute:'description', value: 'USN-417-2 fixed a severe regression in the PostgreSQL server that was
introduced in USN-417-1 and caused some valid queries to be aborted
with a type error. This update fixes a similar (but much less
prominent) error.

At the same time, PostgreSQL is updated to version 8.1.8, which fixes
a range of important bugs.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libecpg-compat2-8.1.8-0ubuntu6.10 (Ubuntu 6.10)
- libecpg-dev-8.1.8-0ubuntu6.10 (Ubuntu 6.10)
- libecpg5-8.1.8-0ubuntu6.10 (Ubuntu 6.10)
- libpgtypes2-8.1.8-0ubuntu6.10 (Ubuntu 6.10)
- libpq-dev-8.1.8-0ubuntu6.10 (Ubuntu 6.10)
- libpq4-8.1.8-0ubuntu6.10 (Ubuntu 6.10)
- postgresql-8.1-8.1.8-0ubuntu6.10 (Ubuntu 6.10)
- postgresql-client-8.1-8.1.8-0ubuntu6.10 (Ubuntu 6.10)
- postgresql-contrib-8.1-8.1.8-0ubuntu6.10 (Ubuntu 6.10)
- postgresql-doc-8.1-8.1.8-0ubuntu6.10 (Ubuntu 6.10)
- postgresql
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libecpg-compat2", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libecpg-compat2-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libecpg-dev", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libecpg-dev-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libecpg5", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg5-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libecpg5-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpgtypes2", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpgtypes2-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpq-dev", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpq-dev-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpq4", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq4-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpq4-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-8.1", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-8.1-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-client-8.1", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-client-8.1-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-contrib-8.1", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-contrib-8.1-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-doc-8.1", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-doc-8.1-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-plperl-8.1", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-plperl-8.1-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-plpython-8.1", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-plpython-8.1-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-pltcl-8.1", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-pltcl-8.1-8.1.8-0ubuntu6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-server-dev-8.1", pkgver: "8.1.8-0ubuntu6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-server-dev-8.1-8.1.8-0ubuntu6.10
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
