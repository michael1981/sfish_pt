# This script was automatically generated from the 248-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21057);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "248-2");
script_summary(english:"unzip regression fix");
script_name(english:"USN248-2 : unzip regression fix");
script_set_attribute(attribute:'synopsis', value: 'The remote package "unzip" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-248-1 fixed a vulnerability in unzip. However, that update
inadvertedly changed the field order in the contents listing output,
which broke unzip frontends like file-roller. The updated packages fix
this regression.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- unzip-5.52-3ubuntu2.2 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "unzip", pkgver: "5.52-3ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package unzip-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to unzip-5.52-3ubuntu2.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
