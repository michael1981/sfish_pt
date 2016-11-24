# This script was automatically generated from the 695-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37654);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "695-1");
script_summary(english:"shadow vulnerability");
script_name(english:"USN695-1 : shadow vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- login 
- passwd 
');
script_set_attribute(attribute:'description', value: 'Paul Szabo discovered a race condition in login.  While setting up
tty permissions, login did not correctly handle symlinks.  If a local
attacker were able to gain control of the system utmp file, they could
cause login to change the ownership and permissions on arbitrary files,
leading to a root privilege escalation.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- login-4.1.1-1ubuntu1.2 (Ubuntu 8.10)
- passwd-4.1.1-1ubuntu1.2 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "login", pkgver: "4.1.1-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package login-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to login-4.1.1-1ubuntu1.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "passwd", pkgver: "4.1.1-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package passwd-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to passwd-4.1.1-1ubuntu1.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
