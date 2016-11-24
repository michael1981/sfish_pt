# This script was automatically generated from the 688-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37422);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "688-1");
script_summary(english:"compiz-fusion-plugins-main vulnerability");
script_name(english:"USN688-1 : compiz-fusion-plugins-main vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "compiz-fusion-plugins-main" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'It was discovered that the Expo plugin for Compiz did not correctly
restrict the screensaver window from being moved with the mouse.  A local
attacker could use the mouse to move the screensaver off the screen and
gain access to the locked desktop session underneath. Default installs
of Ubuntu were not vulnerable as Expo does not come pre-configured with
mouse bindings.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- compiz-fusion-plugins-main-0.7.8-0ubuntu2.2 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "compiz-fusion-plugins-main", pkgver: "0.7.8-0ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package compiz-fusion-plugins-main-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to compiz-fusion-plugins-main-0.7.8-0ubuntu2.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
