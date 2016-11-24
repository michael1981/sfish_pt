# This script was automatically generated from the 327-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27906);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "327-2");
script_summary(english:"firefox regression");
script_name(english:"USN327-2 : firefox regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- firefox 
- firefox-dbg 
- firefox-dev 
- firefox-dom-inspector 
- firefox-gnome-support 
- libnspr-dev 
- libnspr4 
- libnss-dev 
- libnss3 
- mozilla-firefox 
- mozilla-firefox-dev 
');
script_set_attribute(attribute:'description', value: 'USN-327-1 fixed several vulnerabilities in Firefox. Unfortunately the
new version introduced a regression in the handling of streamed media.
Embedded media which were linked with a scheme other than http:// did
not work any more. This update fixes this regression.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- firefox-1.5.dfsg+1.5.0.5-0ubuntu6.06.1 (Ubuntu 6.06)
- firefox-dbg-1.5.dfsg+1.5.0.5-0ubuntu6.06.1 (Ubuntu 6.06)
- firefox-dev-1.5.dfsg+1.5.0.5-0ubuntu6.06.1 (Ubuntu 6.06)
- firefox-dom-inspector-1.5.dfsg+1.5.0.5-0ubuntu6.06.1 (Ubuntu 6.06)
- firefox-gnome-support-1.5.dfsg+1.5.0.5-0ubuntu6.06.1 (Ubuntu 6.06)
- libnspr-dev-1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1 (Ubuntu 6.06)
- libnspr4-1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1 (Ubuntu 6.06)
- libnss-dev-1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1 
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "firefox", pkgver: "1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-dbg", pkgver: "1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-dbg-1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-dev", pkgver: "1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-dev-1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-dom-inspector", pkgver: "1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-dom-inspector-1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-gnome-support", pkgver: "1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-gnome-support-1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnspr-dev", pkgver: "1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnspr-dev-1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnspr4", pkgver: "1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnspr4-1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnss-dev", pkgver: "1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnss-dev-1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnss3", pkgver: "1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnss3-1.firefox1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-firefox", pkgver: "1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-firefox-1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-firefox-dev", pkgver: "1.5.dfsg+1.5.0.5-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-firefox-dev-1.5.dfsg+1.5.0.5-0ubuntu6.06.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
