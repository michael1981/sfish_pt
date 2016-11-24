# This script was automatically generated from the 803-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39800);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "803-1");
script_summary(english:"dhcp3 vulnerability");
script_name(english:"USN803-1 : dhcp3 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dhcp-client 
- dhcp3-client 
- dhcp3-common 
- dhcp3-dev 
- dhcp3-relay 
- dhcp3-server 
- dhcp3-server-ldap 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the DHCP client as included in dhcp3 did not verify
the length of certain option fields when processing a response from an IPv4
dhcp server. If a user running Ubuntu 6.06 LTS or 8.04 LTS connected to a
malicious dhcp server, a remote attacker could cause a denial of service or
execute arbitrary code as the user invoking the program, typically the
\'dhcp\' user. For users running Ubuntu 8.10 or 9.04, a remote attacker
should only be able to cause a denial of service in the DHCP client. In
Ubuntu 9.04, attackers would also be isolated by the AppArmor dhclient3
profile.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dhcp-client-3.1.1-5ubuntu8.1 (Ubuntu 9.04)
- dhcp3-client-3.1.1-5ubuntu8.1 (Ubuntu 9.04)
- dhcp3-common-3.1.1-5ubuntu8.1 (Ubuntu 9.04)
- dhcp3-dev-3.1.1-5ubuntu8.1 (Ubuntu 9.04)
- dhcp3-relay-3.1.1-5ubuntu8.1 (Ubuntu 9.04)
- dhcp3-server-3.1.1-5ubuntu8.1 (Ubuntu 9.04)
- dhcp3-server-ldap-3.1.1-5ubuntu8.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0692");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "dhcp-client", pkgver: "3.1.1-5ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dhcp-client-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dhcp-client-3.1.1-5ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dhcp3-client", pkgver: "3.1.1-5ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dhcp3-client-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dhcp3-client-3.1.1-5ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dhcp3-common", pkgver: "3.1.1-5ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dhcp3-common-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dhcp3-common-3.1.1-5ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dhcp3-dev", pkgver: "3.1.1-5ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dhcp3-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dhcp3-dev-3.1.1-5ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dhcp3-relay", pkgver: "3.1.1-5ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dhcp3-relay-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dhcp3-relay-3.1.1-5ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dhcp3-server", pkgver: "3.1.1-5ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dhcp3-server-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dhcp3-server-3.1.1-5ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dhcp3-server-ldap", pkgver: "3.1.1-5ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dhcp3-server-ldap-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dhcp3-server-ldap-3.1.1-5ubuntu8.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
