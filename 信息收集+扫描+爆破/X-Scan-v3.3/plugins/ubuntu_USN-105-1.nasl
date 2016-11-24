# This script was automatically generated from the 105-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20491);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "105-1");
script_summary(english:"php4 vulnerabilities");
script_name(english:"USN105-1 : php4 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libapache2-mod-php4 
- php4 
- php4-cgi 
- php4-curl 
- php4-dev 
- php4-domxml 
- php4-gd 
- php4-ldap 
- php4-mcal 
- php4-mhash 
- php4-mysql 
- php4-odbc 
- php4-pear 
- php4-recode 
- php4-snmp 
- php4-sybase 
- php4-xslt 
');
script_set_attribute(attribute:'description', value: 'Two Denial of Service vulnerabilities have been discovered in the
getimagesize() function. getimagesize() uses format specific internal
functions php_handle_iff() and php_handle_jpeg() which get stuck in
infinite loops when certain (invalid) size parameters are read from
the image. In web applications that allow users to upload arbitrary
image files, a remote attacker could render the server unavailable by
uploading specially crafted images.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libapache2-mod-php4-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-cgi-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-curl-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-dev-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-domxml-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-gd-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-ldap-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-mcal-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-mhash-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-mysql-4.3.8-3ubuntu7.7 (Ubuntu 4.10)
- php4-odbc-4.3.8-3
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0524","CVE-2005-0525");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "libapache2-mod-php4", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-php4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapache2-mod-php4-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-cgi", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-cgi-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-cgi-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-curl", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-curl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-curl-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-dev", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-dev-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-domxml", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-domxml-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-domxml-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-gd", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-gd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-gd-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-ldap", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-ldap-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-ldap-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-mcal", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-mcal-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-mcal-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-mhash", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-mhash-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-mhash-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-mysql", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-mysql-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-mysql-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-odbc", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-odbc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-odbc-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-pear", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-pear-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-pear-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-recode", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-recode-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-recode-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-snmp", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-snmp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-snmp-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-sybase", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-sybase-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-sybase-4.3.8-3ubuntu7.7
');
}
found = ubuntu_check(osver: "4.10", pkgname: "php4-xslt", pkgver: "4.3.8-3ubuntu7.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-xslt-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to php4-xslt-4.3.8-3ubuntu7.7
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
