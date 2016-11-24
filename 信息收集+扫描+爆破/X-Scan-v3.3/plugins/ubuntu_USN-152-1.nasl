# This script was automatically generated from the 152-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20553);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "152-1");
script_summary(english:"openldap2, libpam-ldap, libnss-ldap vulnerabilities");
script_name(english:"USN152-1 : openldap2, libpam-ldap, libnss-ldap vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ldap-utils 
- libldap2 
- libldap2-dev 
- libnss-ldap 
- libpam-ldap 
- libslapd2-dev 
- slapd 
');
script_set_attribute(attribute:'description', value: 'Andrea Barisani discovered a flaw in the SSL handling of pam-ldap and
libnss-ldap. When a client connected to a slave LDAP server using SSL,
the slave server did not use SSL as well when contacting the LDAP
master server. This caused passwords and other confident information
to be transmitted unencrypted between the slave and the master.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ldap-utils-2.1.30-3ubuntu3.1 (Ubuntu 5.04)
- libldap2-2.1.30-3ubuntu3.1 (Ubuntu 5.04)
- libldap2-dev-2.1.30-3ubuntu3.1 (Ubuntu 5.04)
- libnss-ldap-220-1ubuntu0.1 (Ubuntu 5.04)
- libpam-ldap-169-1ubuntu0.1 (Ubuntu 5.04)
- libslapd2-dev-2.1.30-3ubuntu3.1 (Ubuntu 5.04)
- slapd-2.1.30-3ubuntu3.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:N/A:N');
script_end_attributes();

script_cve_id("CVE-2005-2069");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "ldap-utils", pkgver: "2.1.30-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ldap-utils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ldap-utils-2.1.30-3ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libldap2", pkgver: "2.1.30-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libldap2-2.1.30-3ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libldap2-dev", pkgver: "2.1.30-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libldap2-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libldap2-dev-2.1.30-3ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libnss-ldap", pkgver: "220-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss-ldap-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libnss-ldap-220-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpam-ldap", pkgver: "169-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-ldap-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpam-ldap-169-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libslapd2-dev", pkgver: "2.1.30-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libslapd2-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libslapd2-dev-2.1.30-3ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "slapd", pkgver: "2.1.30-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package slapd-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to slapd-2.1.30-3ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
