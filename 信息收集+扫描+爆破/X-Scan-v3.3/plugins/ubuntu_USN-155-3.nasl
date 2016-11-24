# This script was automatically generated from the 155-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20558);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "155-3");
script_summary(english:"mozilla-locale-... updates");
script_name(english:"USN155-3 : mozilla-locale-... updates");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-locale-da 
- mozilla-locale-de-at 
- mozilla-locale-fr 
');
script_set_attribute(attribute:'description', value: 'USN-155-3 and USN-186-3 updated the version of the mozilla-browser
package to fix several vulnerabilities. It was determined that this
rendered the Dansk, German, and French locale packages uninstallable
since their dependencies were too specific. The updated locale
packages work with all present and future versions of mozilla-browser.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-locale-da-1.7.6-2ubuntu0.1 (Ubuntu 5.04)
- mozilla-locale-de-at-1.7.6-1ubuntu0.1 (Ubuntu 5.04)
- mozilla-locale-fr-1.7.6-1ubuntu0.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "mozilla-locale-da", pkgver: "1.7.6-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-locale-da-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-locale-da-1.7.6-2ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-locale-de-at", pkgver: "1.7.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-locale-de-at-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-locale-de-at-1.7.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-locale-fr", pkgver: "1.7.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-locale-fr-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-locale-fr-1.7.6-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
