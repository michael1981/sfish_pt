# This script was automatically generated from the 689-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36896);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "689-1");
script_summary(english:"vinagre vulnerability");
script_name(english:"USN689-1 : vinagre vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "vinagre" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Alfredo Ortega discovered a flaw in Vinagre\'s use of format strings. A
remote attacker could exploit this vulnerability if they tricked a user
into connecting to a malicious VNC server, or opening a specially crafted
URI with Vinagre. In Ubuntu 8.04, it was possible to execute arbitrary
code with user privileges. In Ubuntu 8.10, Vinagre would simply abort,
leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- vinagre-2.24.1-0ubuntu1.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "vinagre", pkgver: "2.24.1-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package vinagre-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to vinagre-2.24.1-0ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
