# This script was automatically generated from the 149-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20545);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "149-2");
script_summary(english:"mozilla-firefox regressions");
script_name(english:"USN149-2 : mozilla-firefox regressions");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-firefox 
- mozilla-firefox-dev 
- mozilla-firefox-dom-inspector 
- mozilla-firefox-gnome-support 
');
script_set_attribute(attribute:'description', value: 'USN-149-1 fixed several vulnerabilities in the Firefox web browser.
Unfortunately that update introduced a lot of regressions, especially
when using extensions, so another update is necessary. The new
packages ship Firefox version 1.0.6 which should now work well with
most extensions (one known exception is the package
"mozilla-tabextensions").

We apologize for the inconvenience.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-firefox-1.0.6-0ubuntu0.1 (Ubuntu 5.04)
- mozilla-firefox-dev-1.0.6-0ubuntu0.1 (Ubuntu 5.04)
- mozilla-firefox-dom-inspector-1.0.6-0ubuntu0.1 (Ubuntu 5.04)
- mozilla-firefox-gnome-support-1.0.6-0ubuntu0.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox", pkgver: "1.0.6-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-1.0.6-0ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dev", pkgver: "1.0.6-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dev-1.0.6-0ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dom-inspector", pkgver: "1.0.6-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dom-inspector-1.0.6-0ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-gnome-support", pkgver: "1.0.6-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-gnome-support-1.0.6-0ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
