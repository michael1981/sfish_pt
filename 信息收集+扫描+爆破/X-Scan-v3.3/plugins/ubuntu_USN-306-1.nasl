# This script was automatically generated from the 306-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27881);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "306-1");
script_summary(english:"MySQL 4.1 vulnerability");
script_name(english:"USN306-1 : MySQL 4.1 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmysqlclient14 
- libmysqlclient14-dev 
- mysql-client-4.1 
- mysql-common-4.1 
- mysql-server-4.1 
');
script_set_attribute(attribute:'description', value: 'MySQL did not correctly handle NULL as the second argument to the
str_to_date() function. An authenticated user could exploit this to
crash the server.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmysqlclient14-4.1.12-1ubuntu3.6 (Ubuntu 5.10)
- libmysqlclient14-dev-4.1.12-1ubuntu3.6 (Ubuntu 5.10)
- mysql-client-4.1-4.1.12-1ubuntu3.6 (Ubuntu 5.10)
- mysql-common-4.1-4.1.12-1ubuntu3.6 (Ubuntu 5.10)
- mysql-server-4.1-4.1.12-1ubuntu3.6 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-3081");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient14", pkgver: "4.1.12-1ubuntu3.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient14-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient14-4.1.12-1ubuntu3.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient14-dev", pkgver: "4.1.12-1ubuntu3.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient14-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient14-dev-4.1.12-1ubuntu3.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-client-4.1", pkgver: "4.1.12-1ubuntu3.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-client-4.1-4.1.12-1ubuntu3.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-common-4.1", pkgver: "4.1.12-1ubuntu3.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-common-4.1-4.1.12-1ubuntu3.6
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-server-4.1", pkgver: "4.1.12-1ubuntu3.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-4.1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-server-4.1-4.1.12-1ubuntu3.6
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
