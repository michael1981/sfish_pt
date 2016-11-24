# This script was automatically generated from the 858-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42795);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "858-1");
script_summary(english:"openldap2.2 vulnerability");
script_name(english:"USN858-1 : openldap2.2 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ldap-utils 
- libldap-2.2-7 
- slapd 
');
script_set_attribute(attribute:'description', value: 'It was discovered that OpenLDAP did not correctly handle SSL certificates
with zero bytes in the Common Name. A remote attacker could exploit this to
perform a man in the middle attack to view sensitive information or alter
encrypted communications.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ldap-utils-2.2.26-5ubuntu2.9 (Ubuntu 6.06)
- libldap-2.2-7-2.2.26-5ubuntu2.9 (Ubuntu 6.06)
- slapd-2.2.26-5ubuntu2.9 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-3767");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "ldap-utils", pkgver: "2.2.26-5ubuntu2.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ldap-utils-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ldap-utils-2.2.26-5ubuntu2.9
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libldap-2.2-7", pkgver: "2.2.26-5ubuntu2.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap-2.2-7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libldap-2.2-7-2.2.26-5ubuntu2.9
');
}
found = ubuntu_check(osver: "6.06", pkgname: "slapd", pkgver: "2.2.26-5ubuntu2.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package slapd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to slapd-2.2.26-5ubuntu2.9
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
