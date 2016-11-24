# This script was automatically generated from the 384-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27967);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "384-1");
script_summary(english:"OpenLDAP vulnerability");
script_name(english:"USN384-1 : OpenLDAP vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ldap-utils 
- libldap-2.2-7 
- slapd 
');
script_set_attribute(attribute:'description', value: 'Evgeny Legerov discovered that the OpenLDAP libraries did not correctly 
truncate authcid names.  This situation would trigger an assert and 
abort the program using the libraries.  A remote attacker could send 
specially crafted bind requests that would lead to an LDAP server denial 
of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ldap-utils-2.2.26-5ubuntu3.1 (Ubuntu 6.10)
- libldap-2.2-7-2.2.26-5ubuntu3.1 (Ubuntu 6.10)
- slapd-2.2.26-5ubuntu3.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-5779");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "ldap-utils", pkgver: "2.2.26-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ldap-utils-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to ldap-utils-2.2.26-5ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libldap-2.2-7", pkgver: "2.2.26-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap-2.2-7-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libldap-2.2-7-2.2.26-5ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "slapd", pkgver: "2.2.26-5ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package slapd-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to slapd-2.2.26-5ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
