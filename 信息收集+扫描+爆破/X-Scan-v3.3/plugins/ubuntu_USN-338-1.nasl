# This script was automatically generated from the 338-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27917);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "338-1");
script_summary(english:"MySQL vulnerabilities");
script_name(english:"USN338-1 : MySQL vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmysqlclient15-dev 
- libmysqlclient15off 
- mysql-client 
- mysql-client-5.0 
- mysql-common 
- mysql-server 
- mysql-server-5.0 
');
script_set_attribute(attribute:'description', value: 'Dmitri Lenev discovered that arguments of setuid SQL functions were
evaluated in the security context of the functions\' definer instead of
its caller. An authenticated user with the privilege to call such a
function could exploit this to execute arbitrary statements with the
privileges of the definer of that function. (CVE-2006-4227)

Peter Gulutzan reported a potentially confusing situation of the MERGE
table engine. If an user creates a merge table, and the administrator
later revokes privileges on the original table only (without changing
the privileges on the merge table), that user still has access to the
data by using the merge table. This is intended behaviour, but might
be undesirable in some installations; this update introduces a new
server option "--skip-merge" which disables the MERGE engine
completely. (CVE-2006-4031)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmysqlclient15-dev-5.0.22-0ubuntu6.06.2 (Ubuntu 6.06)
- libmysqlclient15off-5.0.22-0ubuntu6.06.2 (Ubuntu 6.06)
- mysql-client-5.0.22-0ubuntu6.06.2 (Ubuntu 6.06)
- mysql-client-5.0-5.0.22-0ubuntu6.06.2 (Ubuntu 6.06)
- mysql-common-5.0.22-0ubuntu6.06.2 (Ubuntu 6.06)
- mysql-server-5.0.22-0ubuntu6.06.2 (Ubuntu 6.06)
- mysql-server-5.0-5.0.22-0ubuntu6.06.2 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4031","CVE-2006-4227");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libmysqlclient15-dev", pkgver: "5.0.22-0ubuntu6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmysqlclient15-dev-5.0.22-0ubuntu6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmysqlclient15off", pkgver: "5.0.22-0ubuntu6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15off-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmysqlclient15off-5.0.22-0ubuntu6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-client", pkgver: "5.0.22-0ubuntu6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-client-5.0.22-0ubuntu6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-client-5.0", pkgver: "5.0.22-0ubuntu6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-5.0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-client-5.0-5.0.22-0ubuntu6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-common", pkgver: "5.0.22-0ubuntu6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-common-5.0.22-0ubuntu6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-server", pkgver: "5.0.22-0ubuntu6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-server-5.0.22-0ubuntu6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-server-5.0", pkgver: "5.0.22-0ubuntu6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-5.0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-server-5.0-5.0.22-0ubuntu6.06.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
