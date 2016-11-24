# This script was automatically generated from the 588-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31638);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "588-1");
script_summary(english:"MySQL vulnerabilities");
script_name(english:"USN588-1 : MySQL vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmysqlclient15-dev 
- libmysqlclient15off 
- mysql-client 
- mysql-client-5.0 
- mysql-common 
- mysql-server 
- mysql-server-4.1 
- mysql-server-5.0 
');
script_set_attribute(attribute:'description', value: 'Masaaki Hirose discovered that MySQL could be made to dereference
a NULL pointer. An authenticated user could cause a denial of service
(application crash) via an EXPLAIN SELECT FROM on the INFORMATION_SCHEMA
table. This issue only affects Ubuntu 6.06 and 6.10. (CVE-2006-7232)

Alexander Nozdrin discovered that MySQL did not restore database access
privileges when returning from SQL SECURITY INVOKER stored routines. An
authenticated user could exploit this to gain privileges. This issue
does not affect Ubuntu 7.10. (CVE-2007-2692)

Martin Friebe discovered that MySQL did not properly update the DEFINER
value of an altered view. An authenticated user could use CREATE SQL
SECURITY DEFINER VIEW and ALTER VIEW statements to gain privileges.
(CVE-2007-6303)

Luigi Auriemma discovered that yaSSL as included in MySQL did not
properly validate its input. A remote attacker could send crafted
requests and cause a denial of service or possibly execute arbitrary
code. This issue did not affect Ubuntu 6.06 in the default
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmysqlclient15-dev-5.0.45-1ubuntu3.3 (Ubuntu 7.10)
- libmysqlclient15off-5.0.45-1ubuntu3.3 (Ubuntu 7.10)
- mysql-client-5.0.45-1ubuntu3.3 (Ubuntu 7.10)
- mysql-client-5.0-5.0.45-1ubuntu3.3 (Ubuntu 7.10)
- mysql-common-5.0.45-1ubuntu3.3 (Ubuntu 7.10)
- mysql-server-5.0.45-1ubuntu3.3 (Ubuntu 7.10)
- mysql-server-4.1-5.0.38-0ubuntu1.4 (Ubuntu 7.04)
- mysql-server-5.0-5.0.45-1ubuntu3.3 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-7232","CVE-2007-2692","CVE-2007-6303","CVE-2008-0226","CVE-2008-0227");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libmysqlclient15-dev", pkgver: "5.0.45-1ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmysqlclient15-dev-5.0.45-1ubuntu3.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmysqlclient15off", pkgver: "5.0.45-1ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15off-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmysqlclient15off-5.0.45-1ubuntu3.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mysql-client", pkgver: "5.0.45-1ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mysql-client-5.0.45-1ubuntu3.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mysql-client-5.0", pkgver: "5.0.45-1ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-5.0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mysql-client-5.0-5.0.45-1ubuntu3.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mysql-common", pkgver: "5.0.45-1ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mysql-common-5.0.45-1ubuntu3.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mysql-server", pkgver: "5.0.45-1ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mysql-server-5.0.45-1ubuntu3.3
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mysql-server-4.1", pkgver: "5.0.38-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-4.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mysql-server-4.1-5.0.38-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mysql-server-5.0", pkgver: "5.0.45-1ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-5.0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mysql-server-5.0-5.0.45-1ubuntu3.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
