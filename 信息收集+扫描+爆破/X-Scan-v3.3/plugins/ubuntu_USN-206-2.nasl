# This script was automatically generated from the 206-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20623);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "206-2");
script_summary(english:"lynx regression fix");
script_name(english:"USN206-2 : lynx regression fix");
script_set_attribute(attribute:'synopsis', value: 'The remote package "lynx" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-206-1 fixed a security vulnerability in lynx. Unfortunately the
fix contained an error that caused lynx to crash under certain
circumstances. The updated packages fix this.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- lynx-2.8.5-2ubuntu0.5.10.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "lynx", pkgver: "2.8.5-2ubuntu0.5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lynx-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to lynx-2.8.5-2ubuntu0.5.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
