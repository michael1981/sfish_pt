# This script was automatically generated from the 753-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37152);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "753-1");
script_summary(english:"postgresql-8.1, postgresql-8.3 vulnerability");
script_name(english:"USN753-1 : postgresql-8.1, postgresql-8.3 vulnerability");
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
script_set_attribute(attribute:'description', value: 'It was discovered that PostgreSQL did not properly handle encoding
conversion failures. An attacker could exploit this by sending specially
crafted requests to PostgreSQL, leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libecpg-compat2-8.1.17-0ubuntu0.6.06.1 (Ubuntu 6.06)
- libecpg-compat3-8.3.7-0ubuntu8.10.1 (Ubuntu 8.10)
- libecpg-dev-8.3.7-0ubuntu8.10.1 (Ubuntu 8.10)
- libecpg5-8.1.17-0ubuntu0.6.06.1 (Ubuntu 6.06)
- libecpg6-8.3.7-0ubuntu8.10.1 (Ubuntu 8.10)
- libpgtypes2-8.1.17-0ubuntu0.6.06.1 (Ubuntu 6.06)
- libpgtypes3-8.3.7-0ubuntu8.10.1 (Ubuntu 8.10)
- libpq-dev-8.3.7-0ubuntu8.10.1 (Ubuntu 8.10)
- libpq4-8.1.17-0ubuntu0.6.06.1 (Ubuntu 6.06)
- libpq5-8.3.7-0ubuntu8.10.1 (Ubuntu 8.10)
- postgresql-8.
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2009-0922");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libecpg-compat2", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libecpg-compat2-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libecpg-compat3", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-compat3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libecpg-compat3-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libecpg-dev", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libecpg-dev-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libecpg5", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg5-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libecpg5-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libecpg6", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg6-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libecpg6-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpgtypes2", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpgtypes2-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpgtypes3", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtypes3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpgtypes3-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpq-dev", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpq-dev-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpq4", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpq4-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpq5", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq5-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpq5-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-8.1", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-8.1-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-8.3", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-8.3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-8.3-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-client", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-client-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-client-8.1", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-client-8.1-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-client-8.3", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-8.3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-client-8.3-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-contrib", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-contrib-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-contrib-8.1", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-contrib-8.1-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-contrib-8.3", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-8.3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-contrib-8.3-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-doc", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-doc-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-doc-8.1", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-doc-8.1-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-doc-8.3", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-8.3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-doc-8.3-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-plperl-8.1", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-plperl-8.1-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-plperl-8.3", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plperl-8.3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-plperl-8.3-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-plpython-8.1", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-plpython-8.1-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-plpython-8.3", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-plpython-8.3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-plpython-8.3-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-pltcl-8.1", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-pltcl-8.1-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-pltcl-8.3", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-pltcl-8.3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-pltcl-8.3-8.3.7-0ubuntu8.10.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postgresql-server-dev-8.1", pkgver: "8.1.17-0ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postgresql-server-dev-8.1-8.1.17-0ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "postgresql-server-dev-8.3", pkgver: "8.3.7-0ubuntu8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-server-dev-8.3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to postgresql-server-dev-8.3-8.3.7-0ubuntu8.10.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
