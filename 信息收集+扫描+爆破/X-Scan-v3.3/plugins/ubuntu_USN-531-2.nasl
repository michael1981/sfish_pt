# This script was automatically generated from the 531-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28137);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "531-2");
script_summary(english:"dhcp vulnerability");
script_name(english:"USN531-2 : dhcp vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dhcp 
- dhcp-client 
- dhcp-relay 
');
script_set_attribute(attribute:'description', value: 'USN-531-1 fixed vulnerabilities in dhcp.  The fixes were incomplete,
and only reduced the scope of the vulnerability, without fully solving
it. This update fixes the problem.

Original advisory details:

 Nahuel Riva and Gerardo Richarte discovered that the DHCP server did not
 correctly handle certain client options. A remote attacker could send
 malicious DHCP replies to the server and execute arbitrary code.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dhcp-2.0pl5dfsg1-20ubuntu1.2 (Ubuntu 7.10)
- dhcp-client-2.0pl5dfsg1-20ubuntu1.2 (Ubuntu 7.10)
- dhcp-relay-2.0pl5dfsg1-20ubuntu1.2 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-5365");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "dhcp", pkgver: "2.0pl5dfsg1-20ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dhcp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to dhcp-2.0pl5dfsg1-20ubuntu1.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "dhcp-client", pkgver: "2.0pl5dfsg1-20ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dhcp-client-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to dhcp-client-2.0pl5dfsg1-20ubuntu1.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "dhcp-relay", pkgver: "2.0pl5dfsg1-20ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dhcp-relay-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to dhcp-relay-2.0pl5dfsg1-20ubuntu1.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
