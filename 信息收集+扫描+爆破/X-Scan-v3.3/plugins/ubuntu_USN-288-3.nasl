# This script was automatically generated from the 288-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27859);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "288-3");
script_summary(english:"PostgreSQL client vulnerabilities");
script_name(english:"USN288-3 : PostgreSQL client vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dovecot 
- dovecot-common 
- dovecot-imapd 
- dovecot-pop3d 
- exim4 
- exim4-base 
- exim4-config 
- exim4-daemon-heavy 
- exim4-daemon-light 
- eximon4 
- postfix 
- postfix-dev 
- postfix-doc 
- postfix-ldap 
- postfix-mysql 
- postfix-pcre 
- postfix-pgsql 
- postfix-tls 
');
script_set_attribute(attribute:'description', value: 'USN-288-1 described a PostgreSQL client vulnerability in the way 
the >>\'<< character is escaped in SQL queries. It was determined that
the PostgreSQL backends of Exim, Dovecot, and Postfix used this unsafe
escaping method.

For reference, these are the details of the original USN:

  CVE-2006-2313:
    Akio Ishida and Yasuo Ohgaki discovered a weakness in the handling of
    invalidly-encoded multibyte text data. If a client application
    processed untrusted input without respecting its encoding and applied
    standard string escaping techniques (such as replacing a single quote
    >>\'<< with >>\\\'<< or >>\'\'<<), the PostgreSQL server could interpret the
    resulting string in a way that allowed an attacker to inject arbitrary
    SQL commands into the resulting SQL query. The PostgreSQL server has
    been modified to reject such invalidly encoded strings now, which
    completely fixes the problem for some \'safe\' multibyte encodings like
    UTF-8.

  CVE-2006-2314:
    However, there are some 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dovecot-0.99.14-1ubuntu1.1 (Ubuntu 5.10)
- dovecot-common-1.0.beta3-3ubuntu5.1 (Ubuntu 6.06)
- dovecot-imapd-1.0.beta3-3ubuntu5.1 (Ubuntu 6.06)
- dovecot-pop3d-1.0.beta3-3ubuntu5.1 (Ubuntu 6.06)
- exim4-4.60-3ubuntu3.1 (Ubuntu 6.06)
- exim4-base-4.60-3ubuntu3.1 (Ubuntu 6.06)
- exim4-config-4.60-3ubuntu3.1 (Ubuntu 6.06)
- exim4-daemon-heavy-4.60-3ubuntu3.1 (Ubuntu 6.06)
- exim4-daemon-light-4.60-3ubuntu3.1 (Ubuntu 6.06)
- eximon4-4.60-3ubuntu3.1 (Ubuntu 6.06)
- postfix-2.2.10-1ubuntu0.1 (Ubu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2313","CVE-2006-2314","CVE-2006-2753");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "dovecot", pkgver: "0.99.14-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to dovecot-0.99.14-1ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "dovecot-common", pkgver: "1.0.beta3-3ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to dovecot-common-1.0.beta3-3ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "dovecot-imapd", pkgver: "1.0.beta3-3ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-imapd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to dovecot-imapd-1.0.beta3-3ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "dovecot-pop3d", pkgver: "1.0.beta3-3ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dovecot-pop3d-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to dovecot-pop3d-1.0.beta3-3ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "exim4", pkgver: "4.60-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package exim4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to exim4-4.60-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "exim4-base", pkgver: "4.60-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package exim4-base-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to exim4-base-4.60-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "exim4-config", pkgver: "4.60-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package exim4-config-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to exim4-config-4.60-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "exim4-daemon-heavy", pkgver: "4.60-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package exim4-daemon-heavy-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to exim4-daemon-heavy-4.60-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "exim4-daemon-light", pkgver: "4.60-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package exim4-daemon-light-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to exim4-daemon-light-4.60-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "eximon4", pkgver: "4.60-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package eximon4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to eximon4-4.60-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postfix", pkgver: "2.2.10-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postfix-2.2.10-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postfix-dev", pkgver: "2.2.10-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postfix-dev-2.2.10-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postfix-doc", pkgver: "2.2.10-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postfix-doc-2.2.10-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postfix-ldap", pkgver: "2.2.10-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-ldap-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postfix-ldap-2.2.10-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postfix-mysql", pkgver: "2.2.10-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-mysql-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postfix-mysql-2.2.10-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postfix-pcre", pkgver: "2.2.10-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-pcre-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postfix-pcre-2.2.10-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "postfix-pgsql", pkgver: "2.2.10-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-pgsql-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to postfix-pgsql-2.2.10-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "postfix-tls", pkgver: "2.1.5-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-tls-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to postfix-tls-2.1.5-9ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
