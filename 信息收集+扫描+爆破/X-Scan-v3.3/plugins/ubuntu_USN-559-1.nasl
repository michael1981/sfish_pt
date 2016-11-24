# This script was automatically generated from the 559-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29793);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "559-1");
script_summary(english:"mysql-dfsg-5.0 vulnerabilities");
script_name(english:"USN559-1 : mysql-dfsg-5.0 vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'Joe Gallo and Artem Russakovskii discovered that the InnoDB
engine in MySQL did not properly perform input validation. An
authenticated user could use a crafted CONTAINS statement to
cause a denial of service. (CVE-2007-5925)

It was discovered that under certain conditions MySQL could be
made to overwrite system table information. An authenticated
user could use a crafted RENAME statement to escalate privileges.
(CVE-2007-5969)

Philip Stoev discovered that the the federated engine of MySQL
did not properly handle responses with a small number of columns.
An authenticated user could use a crafted response to a SHOW
TABLE STATUS query and cause a denial of service. (CVE-2007-6304)

It was discovered that MySQL did not properly enforce access
controls. An authenticated user could use a crafted CREATE TABLE
LIKE statement to escalate privileges. (CVE-2007-3781)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmysqlclient15-dev-5.0.45-1ubuntu3.1 (Ubuntu 7.10)
- libmysqlclient15off-5.0.45-1ubuntu3.1 (Ubuntu 7.10)
- mysql-client-5.0.45-1ubuntu3.1 (Ubuntu 7.10)
- mysql-client-5.0-5.0.45-1ubuntu3.1 (Ubuntu 7.10)
- mysql-common-5.0.45-1ubuntu3.1 (Ubuntu 7.10)
- mysql-server-5.0.45-1ubuntu3.1 (Ubuntu 7.10)
- mysql-server-4.1-5.0.38-0ubuntu1.2 (Ubuntu 7.04)
- mysql-server-5.0-5.0.45-1ubuntu3.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-3781","CVE-2007-5925","CVE-2007-5969","CVE-2007-6304");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libmysqlclient15-dev", pkgver: "5.0.45-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmysqlclient15-dev-5.0.45-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libmysqlclient15off", pkgver: "5.0.45-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15off-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libmysqlclient15off-5.0.45-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mysql-client", pkgver: "5.0.45-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mysql-client-5.0.45-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mysql-client-5.0", pkgver: "5.0.45-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-5.0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mysql-client-5.0-5.0.45-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mysql-common", pkgver: "5.0.45-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mysql-common-5.0.45-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mysql-server", pkgver: "5.0.45-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mysql-server-5.0.45-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mysql-server-4.1", pkgver: "5.0.38-0ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-4.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mysql-server-4.1-5.0.38-0ubuntu1.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mysql-server-5.0", pkgver: "5.0.45-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-5.0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mysql-server-5.0-5.0.45-1ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
