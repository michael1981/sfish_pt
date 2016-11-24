# This script was automatically generated from the 157-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20561);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "157-2");
script_summary(english:"updated enigmail");
script_name(english:"USN157-2 : updated enigmail");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-enigmail 
- mozilla-thunderbird-enigmail 
');
script_set_attribute(attribute:'description', value: 'USN-157-1 fixed some vulnerabilities in the Mozilla Thunderbird email
client. The updated Thunderbird version broke compatibility with the
Enigmail plugin. As announced in USN-157-1, the Enigmail package was
now updated for Ubuntu 4.10 (Warty Warthog) to work with the new
Thunderbird version.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-enigmail-0.92-1ubuntu04.10.1 (Ubuntu 4.10)
- mozilla-thunderbird-enigmail-0.92-1ubuntu04.10.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "mozilla-enigmail", pkgver: "0.92-1ubuntu04.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-enigmail-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-enigmail-0.92-1ubuntu04.10.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-thunderbird-enigmail", pkgver: "0.92-1ubuntu04.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-enigmail-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-thunderbird-enigmail-0.92-1ubuntu04.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
