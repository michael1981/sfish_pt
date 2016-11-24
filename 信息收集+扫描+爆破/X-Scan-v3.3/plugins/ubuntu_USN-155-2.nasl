# This script was automatically generated from the 155-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20557);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "155-2");
script_summary(english:"epiphany-browser regressions");
script_name(english:"USN155-2 : epiphany-browser regressions");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- epiphany-browser 
- epiphany-browser-dev 
');
script_set_attribute(attribute:'description', value: 'USN-155-1 fixed some security vulnerabilities of the Mozilla suite.
Unfortunately this update caused regressions in the Epiphany web
browser, which uses parts of the Mozilla browser. The updated packages
fix these problems.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- epiphany-browser-1.4.4-0ubuntu2.1 (Ubuntu 4.10)
- epiphany-browser-dev-1.4.4-0ubuntu2.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "epiphany-browser", pkgver: "1.4.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package epiphany-browser-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to epiphany-browser-1.4.4-0ubuntu2.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "epiphany-browser-dev", pkgver: "1.4.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package epiphany-browser-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to epiphany-browser-dev-1.4.4-0ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
