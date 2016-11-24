# This script was automatically generated from the 399-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27987);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "399-1");
script_summary(english:"w3m vulnerabilities");
script_name(english:"USN399-1 : w3m vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- w3m 
- w3m-img 
');
script_set_attribute(attribute:'description', value: 'A format string vulnerability was discovered in w3m.  If a user were 
tricked into visiting an HTTPS URL protected by a specially crafted SSL 
certificate, an attacker could execute arbitrary code with user 
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- w3m-0.5.1-4ubuntu2.6.10 (Ubuntu 6.10)
- w3m-img-0.5.1-4ubuntu2.6.10 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "w3m", pkgver: "0.5.1-4ubuntu2.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package w3m-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to w3m-0.5.1-4ubuntu2.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "w3m-img", pkgver: "0.5.1-4ubuntu2.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package w3m-img-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to w3m-img-0.5.1-4ubuntu2.6.10
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
