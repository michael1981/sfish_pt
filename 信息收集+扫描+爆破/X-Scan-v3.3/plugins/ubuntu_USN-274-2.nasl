# This script was automatically generated from the 274-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21568);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "274-2");
script_summary(english:"mysql-dfsg vulnerability");
script_name(english:"USN274-2 : mysql-dfsg vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmysqlclient12 
- libmysqlclient12-dev 
- mysql-client 
- mysql-common 
- mysql-server 
');
script_set_attribute(attribute:'description', value: 'USN-274-1 fixed a logging bypass in the MySQL server. Unfortunately it
was determined that the original update was not sufficient to
completely fix the vulnerability, thus another update is necessary. We
apologize for the inconvenience.

For reference, these are the details of the original USN:

  A logging bypass was discovered in the MySQL query parser. A local
  attacker could exploit this by inserting NUL characters into query
  strings (even into comments), which would cause the query to be
  logged incompletely.

  This only affects you if you enabled the \'log\' parameter in the
  MySQL configuration.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmysqlclient12-4.0.24-10ubuntu2.3 (Ubuntu 5.10)
- libmysqlclient12-dev-4.0.24-10ubuntu2.3 (Ubuntu 5.10)
- mysql-client-4.0.24-10ubuntu2.3 (Ubuntu 5.10)
- mysql-common-4.0.24-10ubuntu2.3 (Ubuntu 5.10)
- mysql-server-4.0.24-10ubuntu2.3 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-0903");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient12", pkgver: "4.0.24-10ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient12-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient12-4.0.24-10ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmysqlclient12-dev", pkgver: "4.0.24-10ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmysqlclient12-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmysqlclient12-dev-4.0.24-10ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-client", pkgver: "4.0.24-10ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-client-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-client-4.0.24-10ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-common", pkgver: "4.0.24-10ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-common-4.0.24-10ubuntu2.3
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mysql-server", pkgver: "4.0.24-10ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mysql-server-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mysql-server-4.0.24-10ubuntu2.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
