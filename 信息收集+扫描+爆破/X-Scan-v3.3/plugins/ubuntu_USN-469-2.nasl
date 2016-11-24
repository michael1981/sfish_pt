# This script was automatically generated from the 469-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28070);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "469-2");
script_summary(english:"Enigmail regression");
script_name(english:"USN469-2 : Enigmail regression");
script_set_attribute(attribute:'synopsis', value: 'The remote package "mozilla-thunderbird-enigmail" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-469-1 fixed vulnerabilities in the Mozilla Thunderbird email client.
The updated Thunderbird version broken compatibility with the Enigmail
plugin.  This update corrects the problem.  We apologize for the
inconvenience.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-enigmail-0.94.2-0ubuntu3 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "mozilla-thunderbird-enigmail", pkgver: "0.94.2-0ubuntu3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-enigmail-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-thunderbird-enigmail-0.94.2-0ubuntu3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
