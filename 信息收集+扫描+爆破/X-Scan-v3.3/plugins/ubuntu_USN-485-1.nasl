# This script was automatically generated from the 485-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28086);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "485-1");
script_summary(english:"PHP vulnerabilities");
script_name(english:"USN485-1 : PHP vulnerabilities");
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
- php5-pspell 
- php5-recode 
- php5-snmp 
- php5-sqlite 
- php5-sybase 
- php5-tidy 
- php5-xmlrpc 
- php5-xsl 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the PHP xmlrpc extension did not correctly check
heap memory allocation sizes.  A remote attacker could send a specially
crafted request to a PHP application using xmlrpc and execute arbitrary
code as the Apache user. (CVE-2007-1864)

Stefan Esser discovered a flaw in the random number initialization of the
PHP SOAP extension.  This could lead to remote attackers being able to
predict certain elements of the authentication mechanism. (CVE-2007-2728)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libapache2-mod-php5-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php-pear-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php5-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php5-cgi-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php5-cli-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php5-common-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php5-curl-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php5-dev-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php5-gd-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php5-ldap-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php5-mhash-5.2.1-0ubuntu1.4 (Ubuntu 7.04)
- php5-mysql-5.2.1-0ub
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-1864","CVE-2007-2728");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libapache2-mod-php5", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-php5-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libapache2-mod-php5-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php-pear", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php-pear-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php-pear-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-cgi", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-cgi-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-cgi-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-cli", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-cli-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-cli-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-common", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-common-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-common-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-curl", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-curl-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-curl-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-dev", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-dev-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-gd", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-gd-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-gd-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-ldap", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-ldap-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-ldap-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-mhash", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mhash-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-mhash-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-mysql", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mysql-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-mysql-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "6.10", pkgname: "php5-mysqli", pkgver: "5.1.6-1ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mysqli-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to php5-mysqli-5.1.6-1ubuntu2.6
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-odbc", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-odbc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-odbc-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-pgsql", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-pgsql-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-pgsql-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-pspell", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-pspell-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-pspell-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-recode", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-recode-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-recode-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-snmp", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-snmp-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-snmp-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-sqlite", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-sqlite-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-sqlite-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-sybase", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-sybase-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-sybase-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-tidy", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-tidy-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-tidy-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-xmlrpc", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-xmlrpc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-xmlrpc-5.2.1-0ubuntu1.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "php5-xsl", pkgver: "5.2.1-0ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-xsl-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to php5-xsl-5.2.1-0ubuntu1.4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
