# This script was automatically generated from the 549-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29213);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "549-2");
script_summary(english:"PHP regression");
script_name(english:"USN549-2 : PHP regression");
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
script_set_attribute(attribute:'description', value: 'USN-549-1 fixed vulnerabilities in PHP.  However, some upstream changes
were incomplete, which caused crashes in certain situations with Ubuntu
7.10.  This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 It was discovered that the wordwrap function did not correctly
 check lengths.  Remote attackers could exploit this to cause
 a crash or monopolize CPU resources, resulting in a denial of
 service. (CVE-2007-3998)

 Integer overflows were discovered in the strspn and strcspn functions.
 Attackers could exploit this to read arbitrary areas of memory, possibly
 gaining access to sensitive information. (CVE-2007-4657)

 Stanislav Malyshev discovered that money_format function did not correctly
 handle certain tokens.  If a PHP application were tricked into processing
 a bad format string, a remote attacker could execute arbitrary code with
 application privileges. (CVE-2007-4658)

 It was discovered that the php_openssl_make_REQ function did not
 correctly check buff
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libapache2-mod-php5-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php-pear-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php5-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php5-cgi-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php5-cli-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php5-common-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php5-curl-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php5-dev-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php5-gd-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php5-ldap-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php5-mhash-5.2.3-1ubuntu6.2 (Ubuntu 7.10)
- php5-mysql-5.2.3-1ub
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-1285","CVE-2007-2872","CVE-2007-3799","CVE-2007-3998","CVE-2007-4657","CVE-2007-4658","CVE-2007-4660","CVE-2007-4661","CVE-2007-4662","CVE-2007-4670","CVE-2007-5898","CVE-2007-5899");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libapache2-mod-php5", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-php5-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libapache2-mod-php5-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php-pear", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php-pear-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php-pear-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-cgi", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-cgi-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-cgi-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-cli", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-cli-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-cli-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-common", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-common-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-curl", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-curl-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-curl-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-dev", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-dev-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-gd", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-gd-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-gd-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-ldap", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-ldap-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-ldap-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-mhash", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mhash-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-mhash-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-mysql", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mysql-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-mysql-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-odbc", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-odbc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-odbc-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-pgsql", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-pgsql-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-pgsql-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-pspell", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-pspell-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-pspell-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-recode", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-recode-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-recode-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-snmp", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-snmp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-snmp-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-sqlite", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-sqlite-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-sqlite-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-sybase", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-sybase-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-sybase-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-tidy", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-tidy-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-tidy-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-xmlrpc", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-xmlrpc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-xmlrpc-5.2.3-1ubuntu6.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "php5-xsl", pkgver: "5.2.3-1ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-xsl-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to php5-xsl-5.2.3-1ubuntu6.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
