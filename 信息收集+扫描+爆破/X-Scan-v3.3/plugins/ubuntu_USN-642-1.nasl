# This script was automatically generated from the 642-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36904);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "642-1");
script_summary(english:"Postfix vulnerabilities");
script_name(english:"USN642-1 : Postfix vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- postfix 
- postfix-cdb 
- postfix-dev 
- postfix-doc 
- postfix-ldap 
- postfix-mysql 
- postfix-pcre 
- postfix-pgsql 
');
script_set_attribute(attribute:'description', value: 'Wietse Venema discovered that Postfix leaked internal file descriptors
when executing non-Postfix commands.  A local attacker could exploit
this to cause Postfix to run out of descriptors, leading to a denial
of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- postfix-2.5.1-2ubuntu1.2 (Ubuntu 8.04)
- postfix-cdb-2.5.1-2ubuntu1.2 (Ubuntu 8.04)
- postfix-dev-2.5.1-2ubuntu1.2 (Ubuntu 8.04)
- postfix-doc-2.5.1-2ubuntu1.2 (Ubuntu 8.04)
- postfix-ldap-2.5.1-2ubuntu1.2 (Ubuntu 8.04)
- postfix-mysql-2.5.1-2ubuntu1.2 (Ubuntu 8.04)
- postfix-pcre-2.5.1-2ubuntu1.2 (Ubuntu 8.04)
- postfix-pgsql-2.5.1-2ubuntu1.2 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2008-3889");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "postfix", pkgver: "2.5.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to postfix-2.5.1-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "postfix-cdb", pkgver: "2.5.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-cdb-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to postfix-cdb-2.5.1-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "postfix-dev", pkgver: "2.5.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to postfix-dev-2.5.1-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "postfix-doc", pkgver: "2.5.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to postfix-doc-2.5.1-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "postfix-ldap", pkgver: "2.5.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-ldap-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to postfix-ldap-2.5.1-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "postfix-mysql", pkgver: "2.5.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-mysql-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to postfix-mysql-2.5.1-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "postfix-pcre", pkgver: "2.5.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-pcre-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to postfix-pcre-2.5.1-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "postfix-pgsql", pkgver: "2.5.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package postfix-pgsql-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to postfix-pgsql-2.5.1-2ubuntu1.2
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
