# This script was automatically generated from the 342-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27921);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "342-1");
script_summary(english:"PHP vulnerabilities");
script_name(english:"USN342-1 : PHP vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libapache2-mod-php4 
- libapache2-mod-php5 
- php-pear 
- php4 
- php4-cgi 
- php4-cli 
- php4-common 
- php4-dev 
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
script_set_attribute(attribute:'description', value: 'The sscanf() function did not properly check array boundaries. In
applications which use sscanf() with argument swapping, a remote attacker
could potentially exploit this to crash the affected web application
or even execute arbitrary code with the application\'s privileges.
(CVE-2006-4020)

The file_exists() and imap_reopen() functions did not perform
proper open_basedir and safe_mode checks which could allow local
scripts to bypass intended restrictions. (CVE-2006-4481)

On 64 bit systems the str_repeat() and wordwrap() functions did not
properly check buffer boundaries. Depending on the application, this
could potentially be exploited to execute arbitrary code with the
applications\' privileges. This only affects the amd64 and sparc
platforms. (CVE-2006-4482)

A buffer overflow was discovered in the LWZReadByte_() function of the
GIF image file parser. By tricking a PHP application into processing a
specially crafted GIF image, a remote attacker could exploit this to
execute arbitrary code with the applic
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libapache2-mod-php4-4.3.10-10ubuntu4.7 (Ubuntu 5.04)
- libapache2-mod-php5-5.1.2-1ubuntu3.2 (Ubuntu 6.06)
- php-pear-5.1.2-1ubuntu3.2 (Ubuntu 6.06)
- php4-4.3.10-10ubuntu4.7 (Ubuntu 5.04)
- php4-cgi-4.3.10-10ubuntu4.7 (Ubuntu 5.04)
- php4-cli-4.3.10-10ubuntu4.7 (Ubuntu 5.04)
- php4-common-4.3.10-10ubuntu4.7 (Ubuntu 5.04)
- php4-dev-4.3.10-10ubuntu4.7 (Ubuntu 5.04)
- php5-5.1.2-1ubuntu3.2 (Ubuntu 6.06)
- php5-cgi-5.1.2-1ubuntu3.2 (Ubuntu 6.06)
- php5-cli-5.1.2-1ubuntu3.2 (Ubuntu 6.06)
- php5
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-4020","CVE-2006-4481","CVE-2006-4482","CVE-2006-4484");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "libapache2-mod-php4", pkgver: "4.3.10-10ubuntu4.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-php4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapache2-mod-php4-4.3.10-10ubuntu4.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapache2-mod-php5", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-php5-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapache2-mod-php5-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php-pear", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php-pear-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php-pear-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4", pkgver: "4.3.10-10ubuntu4.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-4.3.10-10ubuntu4.7
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-cgi", pkgver: "4.3.10-10ubuntu4.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-cgi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-cgi-4.3.10-10ubuntu4.7
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-cli", pkgver: "4.3.10-10ubuntu4.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-cli-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-cli-4.3.10-10ubuntu4.7
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-common", pkgver: "4.3.10-10ubuntu4.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-common-4.3.10-10ubuntu4.7
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-dev", pkgver: "4.3.10-10ubuntu4.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-dev-4.3.10-10ubuntu4.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-cgi", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-cgi-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-cgi-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-cli", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-cli-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-cli-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-common", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-common-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-curl", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-curl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-curl-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-dev", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-dev-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-gd", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-gd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-gd-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-ldap", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-ldap-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-ldap-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-mhash", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mhash-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-mhash-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-mysql", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mysql-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-mysql-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-mysqli", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-mysqli-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-mysqli-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-odbc", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-odbc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-odbc-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-pgsql", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-pgsql-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-pgsql-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-recode", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-recode-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-recode-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-snmp", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-snmp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-snmp-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-sqlite", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-sqlite-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-sqlite-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-sybase", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-sybase-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-sybase-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-xmlrpc", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-xmlrpc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-xmlrpc-5.1.2-1ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "php5-xsl", pkgver: "5.1.2-1ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php5-xsl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to php5-xsl-5.1.2-1ubuntu3.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
