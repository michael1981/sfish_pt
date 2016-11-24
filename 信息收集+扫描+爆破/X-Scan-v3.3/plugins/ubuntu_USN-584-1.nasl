# This script was automatically generated from the 584-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31406);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "584-1");
script_summary(english:"OpenLDAP vulnerabilities");
script_name(english:"USN584-1 : OpenLDAP vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ldap-utils 
- libldap-2.2-7 
- libldap-2.3-0 
- slapd 
');
script_set_attribute(attribute:'description', value: 'Jonathan Clarke discovered that the OpenLDAP slapd server did not
properly handle modify requests when using the Berkeley DB backend
and the NOOP control was used. An authenticated user with modify
permissions could send a crafted modify request and cause a denial
of service via application crash. Ubuntu 7.10 is not affected by
this issue. (CVE-2007-6698)

Ralf Haferkamp discovered that the OpenLDAP slapd server did not
properly handle modrdn requests when using the Berkeley DB backend
and the NOOP control was used. An authenticated user with modrdn
permissions could send a crafted modrdn request and possibly cause a
denial of service via application crash. (CVE-2007-6698)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ldap-utils-2.3.35-1ubuntu0.2 (Ubuntu 7.10)
- libldap-2.2-7-2.2.26-5ubuntu3.3 (Ubuntu 6.10)
- libldap-2.3-0-2.3.35-1ubuntu0.2 (Ubuntu 7.10)
- slapd-2.3.35-1ubuntu0.2 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:S/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-6698","CVE-2008-0658");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "ldap-utils", pkgver: "2.3.35-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ldap-utils-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ldap-utils-2.3.35-1ubuntu0.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libldap-2.2-7", pkgver: "2.2.26-5ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap-2.2-7-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libldap-2.2-7-2.2.26-5ubuntu3.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libldap-2.3-0", pkgver: "2.3.35-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap-2.3-0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libldap-2.3-0-2.3.35-1ubuntu0.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "slapd", pkgver: "2.3.35-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package slapd-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to slapd-2.3.35-1ubuntu0.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
