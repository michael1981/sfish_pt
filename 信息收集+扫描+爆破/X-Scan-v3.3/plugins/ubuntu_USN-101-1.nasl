# This script was automatically generated from the 101-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20487);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "101-1");
script_summary(english:"netkit-telnet vulnerabilities");
script_name(english:"USN101-1 : netkit-telnet vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- telnet 
- telnetd 
');
script_set_attribute(attribute:'description', value: 'A buffer overflow was discovered in the telnet client\'s handling of
the LINEMODE suboptions. By sending a specially constructed reply
containing a large number of SLC (Set Local Character) commands, a
remote attacker (i. e. a malicious telnet server) could execute
arbitrary commands with the privileges of the user running the telnet
client. (CVE-2005-0469)

Michal Zalewski discovered a Denial of Service vulnerability in the
telnet server (telnetd). A remote attacker could cause the telnetd
process to free an invalid pointer, which caused the server process to
crash, leading to a denial of service (inetd will disable the service
if telnetd crashed repeatedly), or possibly the execution of arbitrary
code with the privileges of the telnetd process (by default,
the \'telnetd\' user). Please note that the telnet server is not
officially supported by Ubuntu, it is in the "universe"
component. (CVE-2004-0911)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- telnet-0.17-24ubuntu0.1 (Ubuntu 4.10)
- telnetd-0.17-24ubuntu0.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2004-0911","CVE-2005-0469");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "telnet", pkgver: "0.17-24ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package telnet-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to telnet-0.17-24ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "telnetd", pkgver: "0.17-24ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package telnetd-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to telnetd-0.17-24ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
