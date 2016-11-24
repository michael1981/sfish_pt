# This script was automatically generated from the 671-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37299);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "671-1");
script_summary(english:"mysql-dfsg-5.0 vulnerabilities");
script_name(english:"USN671-1 : mysql-dfsg-5.0 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmysqlclient15-dev 
- libmysqlclient15off 
- mysql-client 
- mysql-client-5.0 
- mysql-common 
- mysql-server 
- mysql-server-5.0 
');
script_set_attribute(attribute:'description', value: 'It was discovered that MySQL could be made to overwrite existing table
files in the data directory. An authenticated user could use the
DATA DIRECTORY and INDEX DIRECTORY options to possibly bypass privilege
checks. This update alters table creation behaviour by disallowing the
use of the MySQL data directory in DATA DIRECTORY and INDEX DIRECTORY
options. (CVE-2008-2079, CVE-2008-4097 and CVE-2008-4098)

It was discovered that MySQL did not handle empty bit-string literals
properly. An attacker could exploit this problem and cause the MySQL
server to crash, leading to a denial of service. (CVE-2008-3963)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmysqlclient15-dev-5.0.51a-3ubuntu5.4 (Ubuntu 8.04)
- libmysqlclient15off-5.0.51a-3ubuntu5.4 (Ubuntu 8.04)
- mysql-client-5.0.51a-3ubuntu5.4 (Ubuntu 8.04)
- mysql-client-5.0-5.0.51a-3ubuntu5.4 (Ubuntu 8.04)
- mysql-common-5.0.51a-3ubuntu5.4 (Ubuntu 8.04)
- mysql-server-5.0.51a-3ubuntu5.4 (Ubuntu 8.04)
- mysql-server-5.0-5.0.51a-3ubuntu5.4 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-2079","CVE-2008-3963","CVE-2008-4097","CVE-2008-4098");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "libmysqlclient15-dev", pkgver: "5.0.51a-3ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libmysqlclient15-dev-5.0.51a-3ubuntu5.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libmysqlclient15off", pkgver: "5.0.51a-3ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15off-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libmysqlclient15off-5.0.51a-3ubuntu5.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "mysql-client", pkgver: "5.0.51a-3ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to mysql-client-5.0.51a-3ubuntu5.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "mysql-client-5.0", pkgver: "5.0.51a-3ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-5.0-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to mysql-client-5.0-5.0.51a-3ubuntu5.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "mysql-common", pkgver: "5.0.51a-3ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to mysql-common-5.0.51a-3ubuntu5.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "mysql-server", pkgver: "5.0.51a-3ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to mysql-server-5.0.51a-3ubuntu5.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "mysql-server-5.0", pkgver: "5.0.51a-3ubuntu5.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-5.0-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to mysql-server-5.0-5.0.51a-3ubuntu5.4
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
