# This script was automatically generated from the 817-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40751);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "817-1");
script_summary(english:"thunderbird vulnerabilities");
script_name(english:"USN817-1 : thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- thunderbird 
- thunderbird-dev 
- thunderbird-gnome-support 
');
script_set_attribute(attribute:'description', value: 'Several flaws were discovered in the rendering engine of Thunderbird. If
Javascript were enabled, an attacker could exploit these flaws to crash
Thunderbird.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1 (Ubuntu 9.04)
- mozilla-thunderbird-dev-2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1 (Ubuntu 9.04)
- thunderbird-2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1 (Ubuntu 9.04)
- thunderbird-dev-2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1 (Ubuntu 9.04)
- thunderbird-gnome-support-2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "mozilla-thunderbird", pkgver: "2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mozilla-thunderbird-2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mozilla-thunderbird-dev", pkgver: "2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mozilla-thunderbird-dev-2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "thunderbird", pkgver: "2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to thunderbird-2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "thunderbird-dev", pkgver: "2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to thunderbird-dev-2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "thunderbird-gnome-support", pkgver: "2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-gnome-support-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to thunderbird-gnome-support-2.0.0.23+build1+nobinonly-0ubuntu0.9.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
