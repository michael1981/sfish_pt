# This script was automatically generated from the 297-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27871);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "297-2");
script_summary(english:"Thunderbird extensions update for recent security update");
script_name(english:"USN297-2 : Thunderbird extensions update for recent security update");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- mozilla-thunderbird-inspector 
- mozilla-thunderbird-typeaheadfind 
- thunderbird-quickfile 
');
script_set_attribute(attribute:'description', value: 'USN-297-1 fixed some security vulnerabilities in Thunderbird. This
update provides new versions of packaged extensions which work with
the current Thunderbird version.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-1.5.0.4-0ubuntu6.06.1 (Ubuntu 6.06)
- mozilla-thunderbird-dev-1.5.0.4-0ubuntu6.06.1 (Ubuntu 6.06)
- mozilla-thunderbird-inspector-1.5.0.4-0ubuntu6.06.1 (Ubuntu 6.06)
- mozilla-thunderbird-typeaheadfind-1.5.0.4-0ubuntu6.06.1 (Ubuntu 6.06)
- thunderbird-quickfile-0.15-0ubuntu1.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird", pkgver: "1.5.0.4-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-1.5.0.4-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird-dev", pkgver: "1.5.0.4-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-dev-1.5.0.4-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird-inspector", pkgver: "1.5.0.4-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-inspector-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-inspector-1.5.0.4-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-thunderbird-typeaheadfind", pkgver: "1.5.0.4-0ubuntu6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-typeaheadfind-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-thunderbird-typeaheadfind-1.5.0.4-0ubuntu6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "thunderbird-quickfile", pkgver: "0.15-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-quickfile-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to thunderbird-quickfile-0.15-0ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
