# This script was automatically generated from the 308-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27883);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "308-1");
script_summary(english:"shadow vulnerability");
script_name(english:"USN308-1 : shadow vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- login 
- passwd 
');
script_set_attribute(attribute:'description', value: 'Ilja van Sprundel discovered that passwd, when called with the -f, -g,
or -s option, did not check the result of the setuid() call. On
systems that configure PAM limits for the maximum number of user
processes, a local attacker could exploit this to execute chfn,
gpasswd, or chsh with root privileges.

This does not affect the default configuration of Ubuntu.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- login-4.0.13-7ubuntu3.1 (Ubuntu 6.06)
- passwd-4.0.13-7ubuntu3.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "login", pkgver: "4.0.13-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package login-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to login-4.0.13-7ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "passwd", pkgver: "4.0.13-7ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package passwd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to passwd-4.0.13-7ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
