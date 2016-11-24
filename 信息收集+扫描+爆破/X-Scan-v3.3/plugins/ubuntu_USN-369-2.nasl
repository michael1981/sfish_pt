# This script was automatically generated from the 369-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27950);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "369-2");
script_summary(english:"postgresql-8.1 vulnerabilities");
script_name(english:"USN369-2 : postgresql-8.1 vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'USN-369-1 fixed three minor PostgreSQL 8.1 vulnerabilities for Ubuntu 6.06 LTS.
This update provides the corresponding update for Ubuntu 6.10.

Original advisory details:

  Michael Fuhr discovered an incorrect type check when handling unknown
  literals. By attempting to coerce such a literal to the ANYARRAY type,
  a local authenticated attacker could cause a server crash. (CVE-2006-5541)
  
  Josh Drake and Alvaro Herrera reported a crash when using aggregate
  functions in UPDATE statements. A local authenticated attacker could
  exploit this to crash the server backend. This update disables this
  construct, since it is not very well defined and forbidden by the SQL
  standard. (CVE-2006-5540)
  
  Sergey Koposov discovered a flaw in the duration logging. This could
  cause a server crash under certain circumstances. (CVE-2006-5542)
  
  Please note that these flaws can usually not be exploited through web
  and other applications that use a database and are exposed to
  untrusted input, so these flaws 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libecpg-compat2-8.1.4-7ubuntu0.1 (Ubuntu 6.10)
- libecpg-dev-8.1.4-7ubuntu0.1 (Ubuntu 6.10)
- libecpg5-8.1.4-7ubuntu0.1 (Ubuntu 6.10)
- libpgtypes2-8.1.4-7ubuntu0.1 (Ubuntu 6.10)
- libpq-dev-8.1.4-7ubuntu0.1 (Ubuntu 6.10)
- libpq4-8.1.4-7ubuntu0.1 (Ubuntu 6.10)
- postgresql-8.1-8.1.4-7ubuntu0.1 (Ubuntu 6.10)
- postgresql-client-8.1-8.1.4-7ubuntu0.1 (Ubuntu 6.10)
- postgresql-contrib-8.1-8.1.4-7ubuntu0.1 (Ubuntu 6.10)
- postgresql-doc-8.1-8.1.4-7ubuntu0.1 (Ubuntu 6.10)
- postgresql-plperl-8.
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-5540","CVE-2006-5541","CVE-2006-5542");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libecpg-compat2", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libecpg-compat2-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libecpg-dev", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libecpg-dev-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libecpg5", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg5-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libecpg5-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpgtypes2", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpgtypes2-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpq-dev", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpq-dev-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpq4", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq4-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpq4-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-8.1", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-8.1-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-client-8.1", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-client-8.1-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-contrib-8.1", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-contrib-8.1-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-doc-8.1", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-doc-8.1-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-plperl-8.1", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-plperl-8.1-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-plpython-8.1", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-plpython-8.1-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-pltcl-8.1", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-pltcl-8.1-8.1.4-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "postgresql-server-dev-8.1", pkgver: "8.1.4-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to postgresql-server-dev-8.1-8.1.4-7ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
