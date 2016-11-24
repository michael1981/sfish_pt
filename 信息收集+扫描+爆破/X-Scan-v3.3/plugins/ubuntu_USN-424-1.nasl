# This script was automatically generated from the 424-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28016);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "424-1");
script_summary(english:"PHP vulnerabilities");
script_name(english:"USN424-1 : PHP vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libapache2-mod-php5 
- php-pear 
- php5 
- php5-cgi 
- php5-cli 
- php5-common 
- php5-curl 
- php5-dev 
- php5-gd 
- php5-ldap 
- php5-mhash 
- php5-mysql 
- php5-mysqli 
- php5-odbc 
- php5-pgsql 
- php5-recode 
- php5-snmp 
- php5-sqlite 
- php5-sybase 
- php5-xmlrpc 
- php5-xsl 
');
script_set_attribute(attribute:'description', value: 'Multiple buffer overflows have been discovered in various PHP modules.
If a PHP application processes untrusted data with functions of the
session or zip module, or various string functions, a remote attacker
could exploit this to execute arbitrary code with the privileges of
the web server. (CVE-2007-0906)

The sapi_header_op() function had a buffer underflow that could be
exploited to crash the PHP interpreter. (CVE-2007-0907)

The wddx unserialization handler did not correctly check for some
buffer boundaries and had an uninitialized variable. By unserializing
untrusted data, this could be exploited to expose memory regions that
were not meant to be accessible. Depending on the PHP application this
could lead to disclosure of potentially sensitive information.
(CVE-2007-0908)

On 64 bit systems (the amd64 and sparc platforms), various print
functions and the odbc_result_all() were susceptible to a format
string vulnerability. A remote attacker could exploit this to execute
arbitrary code with the privileg
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libapache2-mod-php5-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php-pear-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php5-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php5-cgi-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php5-cli-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php5-common-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php5-curl-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php5-dev-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php5-gd-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php5-ldap-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php5-mhash-5.1.6-1ubuntu2.2 (Ubuntu 6.10)
- php5-mysql-5.1.6-1ub
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-0906","CVE-2007-0907","CVE-2007-0908","CVE-2007-0909","CVE-2007-0910","CVE-2007-0988");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libapache2-mod-php5", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-php5-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libapache2-mod-php5-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php-pear", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php-pear-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php-pear-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-cgi", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-cgi-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-cgi-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-cli", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-cli-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-cli-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-common", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-common-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-curl", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-curl-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-curl-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-dev", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-dev-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-gd", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-gd-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-gd-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-ldap", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-ldap-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-ldap-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-mhash", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mhash-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-mhash-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-mysql", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mysql-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-mysql-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-mysqli", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mysqli-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-mysqli-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-odbc", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-odbc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-odbc-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-pgsql", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-pgsql-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-pgsql-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-recode", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-recode-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-recode-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-snmp", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-snmp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-snmp-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-sqlite", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-sqlite-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-sqlite-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-sybase", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-sybase-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-sybase-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-xmlrpc", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-xmlrpc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-xmlrpc-5.1.6-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-xsl", pkgver: "5.1.6-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-xsl-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-xsl-5.1.6-1ubuntu2.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
