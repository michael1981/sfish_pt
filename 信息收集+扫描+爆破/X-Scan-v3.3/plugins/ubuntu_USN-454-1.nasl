# This script was automatically generated from the 454-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28052);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "454-1");
script_summary(english:"PostgreSQL vulnerability");
script_name(english:"USN454-1 : PostgreSQL vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libecpg-compat2 
- libecpg-dev 
- libecpg5 
- libpgtypes2 
- libpq-dev 
- libpq4 
- libpq5 
- postgresql-8.1 
- postgresql-8.2 
- postgresql-client-8.1 
- postgresql-client-8.2 
- postgresql-contrib-8.1 
- postgresql-contrib-8.2 
- postgresql-doc-8.1 
- postgresql-doc-8.2 
- postgresql-plperl-8.1 
- postgresql-plperl-8.2 
- postgresql-plpython-8.1 
- postgresql-plpython-8.2 
- postgresql-pltcl-8.1 
- postgresql-pltcl-8.2 
- postgresql-server-dev-8.1 
-
[...]');
script_set_attribute(attribute:'description', value: 'PostgreSQL did not handle the "search_path" configuration option in a
secure way for functions declared as "SECURITY DEFINER". 

Previously, an attacker could override functions and operators used by
the security definer function to execute arbitrary SQL commands with
the privileges of the user who created the security definer function.
The updated version does not search the temporary table schema for
functions and operators any more.

Similarly, an attacker could put forged tables into the temporary
table schema to trick the security definer function into using
attacker defined data for processing. This was possible because the
temporary schema was always implicitly searched first before all other
entries in "search_path". The updated version now supports explicit
placement of the temporary schema. Please see the HTML documentation
or the manual page for "CREATE FUNCTION" for details and an example
how to write security definer functions in a secure way.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libecpg-compat2-8.2.4-0ubuntu0.7.04 (Ubuntu 7.04)
- libecpg-dev-8.2.4-0ubuntu0.7.04 (Ubuntu 7.04)
- libecpg5-8.2.4-0ubuntu0.7.04 (Ubuntu 7.04)
- libpgtypes2-8.2.4-0ubuntu0.7.04 (Ubuntu 7.04)
- libpq-dev-8.2.4-0ubuntu0.7.04 (Ubuntu 7.04)
- libpq4-8.1.9-0ubuntu0.6.10 (Ubuntu 6.10)
- libpq5-8.2.4-0ubuntu0.7.04 (Ubuntu 7.04)
- postgresql-8.1-8.1.9-0ubuntu0.6.10 (Ubuntu 6.10)
- postgresql-8.2-8.2.4-0ubuntu0.7.04 (Ubuntu 7.04)
- postgresql-client-8.1-8.1.9-0ubuntu0.6.10 (Ubuntu 6.10)
- postgresql
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-2138");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libecpg-compat2", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libecpg-compat2-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libecpg-dev", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libecpg-dev-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libecpg5", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg5-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libecpg5-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libpgtypes2", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libpgtypes2-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libpq-dev", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libpq-dev-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpq4", pkgver: "8.1.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq4-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpq4-8.1.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libpq5", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq5-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libpq5-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-8.1", pkgver: "8.1.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-8.1-8.1.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "7.04", pkgname: "postgresql-8.2", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to postgresql-8.2-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-client-8.1", pkgver: "8.1.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-client-8.1-8.1.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "7.04", pkgname: "postgresql-client-8.2", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to postgresql-client-8.2-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-contrib-8.1", pkgver: "8.1.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-contrib-8.1-8.1.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "7.04", pkgname: "postgresql-contrib-8.2", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to postgresql-contrib-8.2-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-doc-8.1", pkgver: "8.1.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-doc-8.1-8.1.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "7.04", pkgname: "postgresql-doc-8.2", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to postgresql-doc-8.2-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-plperl-8.1", pkgver: "8.1.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-plperl-8.1-8.1.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "7.04", pkgname: "postgresql-plperl-8.2", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to postgresql-plperl-8.2-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-plpython-8.1", pkgver: "8.1.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-plpython-8.1-8.1.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "7.04", pkgname: "postgresql-plpython-8.2", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to postgresql-plpython-8.2-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-pltcl-8.1", pkgver: "8.1.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-pltcl-8.1-8.1.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "7.04", pkgname: "postgresql-pltcl-8.2", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to postgresql-pltcl-8.2-8.2.4-0ubuntu0.7.04
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-server-dev-8.1", pkgver: "8.1.9-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-server-dev-8.1-8.1.9-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "7.04", pkgname: "postgresql-server-dev-8.2", pkgver: "8.2.4-0ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to postgresql-server-dev-8.2-8.2.4-0ubuntu0.7.04
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
