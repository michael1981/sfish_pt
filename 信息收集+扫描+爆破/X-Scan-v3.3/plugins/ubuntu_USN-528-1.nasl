# This script was automatically generated from the 528-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28133);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "528-1");
script_summary(english:"MySQL vulnerabilities");
script_name(english:"USN528-1 : MySQL vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'Neil Kettle discovered that MySQL could be made to dereference a NULL
pointer and divide by zero.  An authenticated user could exploit this
with a crafted IF clause, leading to a denial of service. (CVE-2007-2583)

Victoria Reznichenko discovered that MySQL did not always require the
DROP privilege.  An authenticated user could exploit this via RENAME
TABLE statements to rename arbitrary tables, possibly gaining additional
database access. (CVE-2007-2691)

It was discovered that MySQL could be made to overflow a signed char
during authentication.  Remote attackers could use crafted authentication
requests to cause a denial of service. (CVE-2007-3780)

Phil Anderton discovered that MySQL did not properly verify access
privileges when accessing external tables.  As a result, authenticated
users could exploit this to obtain UPDATE privileges to external
tables. (CVE-2007-3782)

In certain situations, when installing or upgrading mysql, there was no
notification that the mysql root user password needed to be set
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmysqlclient15-dev-5.0.38-0ubuntu1.1 (Ubuntu 7.04)
- libmysqlclient15off-5.0.38-0ubuntu1.1 (Ubuntu 7.04)
- mysql-client-5.0.38-0ubuntu1.1 (Ubuntu 7.04)
- mysql-client-5.0-5.0.38-0ubuntu1.1 (Ubuntu 7.04)
- mysql-common-5.0.38-0ubuntu1.1 (Ubuntu 7.04)
- mysql-server-5.0.38-0ubuntu1.1 (Ubuntu 7.04)
- mysql-server-4.1-5.0.38-0ubuntu1.1 (Ubuntu 7.04)
- mysql-server-5.0-5.0.38-0ubuntu1.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-2583","CVE-2007-2691","CVE-2007-3780","CVE-2007-3782");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libmysqlclient15-dev", pkgver: "5.0.38-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libmysqlclient15-dev-5.0.38-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libmysqlclient15off", pkgver: "5.0.38-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient15off-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libmysqlclient15off-5.0.38-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mysql-client", pkgver: "5.0.38-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mysql-client-5.0.38-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mysql-client-5.0", pkgver: "5.0.38-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-5.0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mysql-client-5.0-5.0.38-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mysql-common", pkgver: "5.0.38-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mysql-common-5.0.38-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mysql-server", pkgver: "5.0.38-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mysql-server-5.0.38-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mysql-server-4.1", pkgver: "5.0.38-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-4.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mysql-server-4.1-5.0.38-0ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mysql-server-5.0", pkgver: "5.0.38-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-5.0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mysql-server-5.0-5.0.38-0ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
