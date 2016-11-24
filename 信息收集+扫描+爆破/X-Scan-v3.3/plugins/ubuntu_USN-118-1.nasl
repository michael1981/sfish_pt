# This script was automatically generated from the 118-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20506);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "118-1");
script_summary(english:"postgresql vulnerabilities");
script_name(english:"USN118-1 : postgresql vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libecpg-dev 
- libecpg4 
- libpgtcl 
- libpgtcl-dev 
- libpq3 
- postgresql 
- postgresql-client 
- postgresql-contrib 
- postgresql-dev 
- postgresql-doc 
');
script_set_attribute(attribute:'description', value: 'It was discovered that unprivileged users were allowed to call
internal character conversion functions. However, since these
functions were not designed to be safe against malicious choices of
argument values, this could potentially be exploited to execute
arbitrary code with the privileges of the PostgreSQL server (user
"postgres"). (CVE-2005-1409)

Another vulnerability was found in the "tsearch2" module of
postgresql-contrib. This module declared several functions as
internal, although they did not accept any internal argument; this
breaks the type safety of "internal" by allowing users to construct
SQL commands that invoke other functions accepting "internal"
arguments. This could eventually be exploited to crash the server, or
possibly even execute arbitrary code with the privileges of the
PostgreSQL server. (CVE-2005-1410)

These vulnerabilities must also be fixed in all existing databases
when upgrading. The post-installation script of the updated package
attempts to do this automatically; if the pack
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libecpg-dev-7.4.7-2ubuntu2.1 (Ubuntu 5.04)
- libecpg4-7.4.7-2ubuntu2.1 (Ubuntu 5.04)
- libpgtcl-7.4.7-2ubuntu2.1 (Ubuntu 5.04)
- libpgtcl-dev-7.4.7-2ubuntu2.1 (Ubuntu 5.04)
- libpq3-7.4.7-2ubuntu2.1 (Ubuntu 5.04)
- postgresql-7.4.7-2ubuntu2.1 (Ubuntu 5.04)
- postgresql-client-7.4.7-2ubuntu2.1 (Ubuntu 5.04)
- postgresql-contrib-7.4.7-2ubuntu2.1 (Ubuntu 5.04)
- postgresql-dev-7.4.7-2ubuntu2.1 (Ubuntu 5.04)
- postgresql-doc-7.4.7-2ubuntu2.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-1409","CVE-2005-1410");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "libecpg-dev", pkgver: "7.4.7-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libecpg-dev-7.4.7-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libecpg4", pkgver: "7.4.7-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libecpg4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libecpg4-7.4.7-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpgtcl", pkgver: "7.4.7-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtcl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpgtcl-7.4.7-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpgtcl-dev", pkgver: "7.4.7-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpgtcl-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpgtcl-dev-7.4.7-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpq3", pkgver: "7.4.7-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpq3-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpq3-7.4.7-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql", pkgver: "7.4.7-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-7.4.7-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-client", pkgver: "7.4.7-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-client-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-client-7.4.7-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-contrib", pkgver: "7.4.7-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-contrib-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-contrib-7.4.7-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-dev", pkgver: "7.4.7-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-dev-7.4.7-2ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postgresql-doc", pkgver: "7.4.7-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postgresql-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postgresql-doc-7.4.7-2ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
