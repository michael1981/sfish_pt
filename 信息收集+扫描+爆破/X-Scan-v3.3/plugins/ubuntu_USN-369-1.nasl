# This script was automatically generated from the 369-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27949);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "369-1");
script_summary(english:"PostgreSQL vulnerabilities");
script_name(english:"USN369-1 : PostgreSQL vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'Michael Fuhr discovered an incorrect type check when handling unknown
literals. By attempting to coerce such a literal to the ANYARRAY type,
a local authenticated attacker could cause a server crash.

Josh Drake and Alvaro Herrera reported a crash when using aggregate
functions in UPDATE statements. A local authenticated attacker could
exploit this to crash the server backend. This update disables this
construct, since it is not very well defined and forbidden by the SQL
standard.

Sergey Koposov discovered a flaw in the duration logging. This could
cause a server crash under certain circumstances.

Please note that these flaws can usually not be exploited through web
and other applications that use a database and are exposed to
untrusted input, so these flaws do not pose a threat in usual setups.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libecpg-compat2-8.1.4-0ubuntu1.1 (Ubuntu 6.06)
- libecpg-dev-8.1.4-0ubuntu1.1 (Ubuntu 6.06)
- libecpg5-8.1.4-0ubuntu1.1 (Ubuntu 6.06)
- libpgtypes2-8.1.4-0ubuntu1.1 (Ubuntu 6.06)
- libpq-dev-8.1.4-0ubuntu1.1 (Ubuntu 6.06)
- libpq4-8.1.4-0ubuntu1.1 (Ubuntu 6.06)
- postgresql-8.1-8.1.4-0ubuntu1.1 (Ubuntu 6.06)
- postgresql-client-8.1-8.1.4-0ubuntu1.1 (Ubuntu 6.06)
- postgresql-contrib-8.1-8.1.4-0ubuntu1.1 (Ubuntu 6.06)
- postgresql-doc-8.1-8.1.4-0ubuntu1.1 (Ubuntu 6.06)
- postgresql-plperl-8.
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libecpg-compat2", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libecpg-compat2-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libecpg-dev", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libecpg-dev-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libecpg5", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg5-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libecpg5-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpgtypes2", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpgtypes2-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpq-dev", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpq-dev-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpq4", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpq4-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-8.1", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-8.1-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-client-8.1", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-client-8.1-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-contrib-8.1", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-contrib-8.1-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-doc-8.1", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-doc-8.1-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-plperl-8.1", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-plperl-8.1-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-plpython-8.1", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-plpython-8.1-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-pltcl-8.1", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-pltcl-8.1-8.1.4-0ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-server-dev-8.1", pkgver: "8.1.4-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-server-dev-8.1-8.1.4-0ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
