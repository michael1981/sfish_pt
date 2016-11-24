# This script was automatically generated from the 634-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33809);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "634-1");
script_summary(english:"OpenLDAP vulnerability");
script_name(english:"USN634-1 : OpenLDAP vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ldap-utils 
- libldap-2.2-7 
- libldap-2.3-0 
- libldap-2.4-2 
- libldap-2.4-2-dbg 
- libldap2-dev 
- slapd 
- slapd-dbg 
');
script_set_attribute(attribute:'description', value: 'Cameron Hotchkies discovered that OpenLDAP did not correctly handle
certain ASN.1 BER data.  A remote attacker could send a specially crafted
packet and crash slapd, leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ldap-utils-2.4.9-0ubuntu0.8.04.1 (Ubuntu 8.04)
- libldap-2.2-7-2.2.26-5ubuntu2.8 (Ubuntu 6.06)
- libldap-2.3-0-2.3.35-1ubuntu0.3 (Ubuntu 7.10)
- libldap-2.4-2-2.4.9-0ubuntu0.8.04.1 (Ubuntu 8.04)
- libldap-2.4-2-dbg-2.4.9-0ubuntu0.8.04.1 (Ubuntu 8.04)
- libldap2-dev-2.4.9-0ubuntu0.8.04.1 (Ubuntu 8.04)
- slapd-2.4.9-0ubuntu0.8.04.1 (Ubuntu 8.04)
- slapd-dbg-2.4.9-0ubuntu0.8.04.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2008-2952");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "ldap-utils", pkgver: "2.4.9-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ldap-utils-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ldap-utils-2.4.9-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libldap-2.2-7", pkgver: "2.2.26-5ubuntu2.8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap-2.2-7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libldap-2.2-7-2.2.26-5ubuntu2.8
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libldap-2.3-0", pkgver: "2.3.35-1ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap-2.3-0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libldap-2.3-0-2.3.35-1ubuntu0.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libldap-2.4-2", pkgver: "2.4.9-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap-2.4-2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libldap-2.4-2-2.4.9-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libldap-2.4-2-dbg", pkgver: "2.4.9-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap-2.4-2-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libldap-2.4-2-dbg-2.4.9-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libldap2-dev", pkgver: "2.4.9-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap2-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libldap2-dev-2.4.9-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "slapd", pkgver: "2.4.9-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package slapd-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to slapd-2.4.9-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "slapd-dbg", pkgver: "2.4.9-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package slapd-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to slapd-dbg-2.4.9-0ubuntu0.8.04.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
