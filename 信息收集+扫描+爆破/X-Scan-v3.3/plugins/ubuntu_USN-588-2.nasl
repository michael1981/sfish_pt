# This script was automatically generated from the 588-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31783);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "588-2");
script_summary(english:"MySQL regression");
script_name(english:"USN588-2 : MySQL regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmysqlclient15-dev 
- libmysqlclient15off 
- mysql-client 
- mysql-client-5.0 
- mysql-common 
- mysql-server 
- mysql-server-5.0 
');
script_set_attribute(attribute:'description', value: 'USN-588-1 fixed vulnerabilities in MySQL. In fixing CVE-2007-2692 for
Ubuntu 6.06, additional improvements were made to make privilege checks
more restictive. As a result, an upstream bug was exposed which could
cause operations on tables or views in a different database to fail. This
update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Masaaki Hirose discovered that MySQL could be made to dereference
 a NULL pointer. An authenticated user could cause a denial of service
 (application crash) via an EXPLAIN SELECT FROM on the INFORMATION_SCHEMA
 table. This issue only affects Ubuntu 6.06 and 6.10. (CVE-2006-7232)
 
 Alexander Nozdrin discovered that MySQL did not restore database access
 privileges when returning from SQL SECURITY INVOKER stored routines. An
 authenticated user could exploit this to gain privileges. This issue
 does not affect Ubuntu 7.10. (CVE-2007-2692)
 
 Martin Friebe discovered that MySQL did not properly update the DEFINER
 value of an altered vie
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmysqlclient15-dev-5.0.22-0ubuntu6.06.9 (Ubuntu 6.06)
- libmysqlclient15off-5.0.22-0ubuntu6.06.9 (Ubuntu 6.06)
- mysql-client-5.0.22-0ubuntu6.06.9 (Ubuntu 6.06)
- mysql-client-5.0-5.0.22-0ubuntu6.06.9 (Ubuntu 6.06)
- mysql-common-5.0.22-0ubuntu6.06.9 (Ubuntu 6.06)
- mysql-server-5.0.22-0ubuntu6.06.9 (Ubuntu 6.06)
- mysql-server-5.0-5.0.22-0ubuntu6.06.9 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-7232","CVE-2007-2692","CVE-2007-6303","CVE-2008-0226","CVE-2008-0227");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libmysqlclient15-dev", pkgver: "5.0.22-0ubuntu6.06.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmysqlclient15-dev-5.0.22-0ubuntu6.06.9
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmysqlclient15off", pkgver: "5.0.22-0ubuntu6.06.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15off-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmysqlclient15off-5.0.22-0ubuntu6.06.9
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-client", pkgver: "5.0.22-0ubuntu6.06.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-client-5.0.22-0ubuntu6.06.9
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-client-5.0", pkgver: "5.0.22-0ubuntu6.06.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-5.0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-client-5.0-5.0.22-0ubuntu6.06.9
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-common", pkgver: "5.0.22-0ubuntu6.06.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-common-5.0.22-0ubuntu6.06.9
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-server", pkgver: "5.0.22-0ubuntu6.06.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-server-5.0.22-0ubuntu6.06.9
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mysql-server-5.0", pkgver: "5.0.22-0ubuntu6.06.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-5.0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mysql-server-5.0-5.0.22-0ubuntu6.06.9
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
