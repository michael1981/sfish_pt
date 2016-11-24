# This script was automatically generated from the 201-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20617);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "201-1");
script_summary(english:"courier vulnerabilities");
script_name(english:"USN201-1 : courier vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- courier-authdaemon 
- courier-authmysql 
- courier-authpostgresql 
- courier-base 
- courier-doc 
- courier-faxmail 
- courier-imap 
- courier-imap-ssl 
- courier-ldap 
- courier-maildrop 
- courier-mlm 
- courier-mta 
- courier-mta-ssl 
- courier-pcp 
- courier-pop 
- courier-pop-ssl 
- courier-ssl 
- courier-webadmin 
- sqwebmail 
');
script_set_attribute(attribute:'description', value: 'Several Cross Site Scripting vulnerabilities were discovered in
SqWebmail. A remote attacker could exploit this to execute arbitrary
JavaScript or other active HTML embeddable content in the web browser
of an SqWebmail user by sending specially crafted emails to him.

Please note that the "sqwebmail" package is not officially supported
by Ubuntu (it is in the "universe" section of the archive).');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- courier-authdaemon-0.47-3ubuntu1.3 (Ubuntu 5.04)
- courier-authmysql-0.47-3ubuntu1.3 (Ubuntu 5.04)
- courier-authpostgresql-0.47-3ubuntu1.3 (Ubuntu 5.04)
- courier-base-0.47-3ubuntu1.3 (Ubuntu 5.04)
- courier-doc-0.47-3ubuntu1.3 (Ubuntu 5.04)
- courier-faxmail-0.47-3ubuntu1.3 (Ubuntu 5.04)
- courier-imap-3.0.8-3ubuntu1.3 (Ubuntu 5.04)
- courier-imap-ssl-3.0.8-3ubuntu1.3 (Ubuntu 5.04)
- courier-ldap-0.47-3ubuntu1.3 (Ubuntu 5.04)
- courier-maildrop-0.47-3ubuntu1.3 (Ubuntu 5.04)
- courier-mlm-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2005-2724","CVE-2005-2769","CVE-2005-2820");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "courier-authdaemon", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-authdaemon-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-authdaemon-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-authmysql", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-authmysql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-authmysql-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-authpostgresql", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-authpostgresql-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-authpostgresql-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-base", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-base-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-base-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-doc", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-doc-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-faxmail", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-faxmail-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-faxmail-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-imap", pkgver: "3.0.8-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-imap-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-imap-3.0.8-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-imap-ssl", pkgver: "3.0.8-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-imap-ssl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-imap-ssl-3.0.8-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-ldap", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-ldap-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-ldap-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-maildrop", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-maildrop-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-maildrop-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-mlm", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-mlm-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-mlm-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-mta", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-mta-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-mta-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-mta-ssl", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-mta-ssl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-mta-ssl-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-pcp", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-pcp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-pcp-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-pop", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-pop-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-pop-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-pop-ssl", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-pop-ssl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-pop-ssl-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-ssl", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-ssl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-ssl-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "courier-webadmin", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package courier-webadmin-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to courier-webadmin-0.47-3ubuntu1.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "sqwebmail", pkgver: "0.47-3ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sqwebmail-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to sqwebmail-0.47-3ubuntu1.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
