# This script was automatically generated from the 440-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28037);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "440-1");
script_summary(english:"MySQL vulnerability");
script_name(english:"USN440-1 : MySQL vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmysqlclient15-dev 
- libmysqlclient15off 
- mysql-client 
- mysql-client-5.0 
- mysql-common 
- mysql-server 
- mysql-server-5.0 
');
script_set_attribute(attribute:'description', value: 'Stefan Streichbier and B. Mueller of SEC Consult discovered that MySQL 
subselect queries using "ORDER BY" could be made to crash the MySQL 
server.  An attacker with access to a MySQL instance could cause an
intermitant denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmysqlclient15-dev-5.0.24a-9ubuntu0.1 (Ubuntu 6.10)
- libmysqlclient15off-5.0.24a-9ubuntu0.1 (Ubuntu 6.10)
- mysql-client-5.0.24a-9ubuntu0.1 (Ubuntu 6.10)
- mysql-client-5.0-5.0.24a-9ubuntu0.1 (Ubuntu 6.10)
- mysql-common-5.0.24a-9ubuntu0.1 (Ubuntu 6.10)
- mysql-server-5.0.24a-9ubuntu0.1 (Ubuntu 6.10)
- mysql-server-5.0-5.0.24a-9ubuntu0.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-1420");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libmysqlclient15-dev", pkgver: "5.0.24a-9ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmysqlclient15-dev-5.0.24a-9ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libmysqlclient15off", pkgver: "5.0.24a-9ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15off-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libmysqlclient15off-5.0.24a-9ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mysql-client", pkgver: "5.0.24a-9ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mysql-client-5.0.24a-9ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mysql-client-5.0", pkgver: "5.0.24a-9ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-5.0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mysql-client-5.0-5.0.24a-9ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mysql-common", pkgver: "5.0.24a-9ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mysql-common-5.0.24a-9ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mysql-server", pkgver: "5.0.24a-9ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mysql-server-5.0.24a-9ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mysql-server-5.0", pkgver: "5.0.24a-9ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-5.0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mysql-server-5.0-5.0.24a-9ubuntu0.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
