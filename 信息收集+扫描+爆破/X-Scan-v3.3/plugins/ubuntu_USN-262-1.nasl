# This script was automatically generated from the 262-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21069);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "262-1");
script_summary(english:"Ubuntu 5.10 installer vulnerability");
script_name(english:"USN262-1 : Ubuntu 5.10 installer vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- base-config 
- login 
- passwd 
');
script_set_attribute(attribute:'description', value: 'Karl Øie discovered that the Ubuntu 5.10 installer failed to clean
passwords in the installer log files. Since these files were
world-readable, any local user could see the password of the first
user account, which has full sudo privileges by default.

The updated packages remove the passwords and additionally make the
log files readable only by root.

This does not affect the Ubuntu 4.10, 5.04, or the upcoming 6.04
installer.  However, if you upgraded from Ubuntu 5.10 to the current
development version of Ubuntu 6.04 (\'Dapper Drake\'), please ensure
that you upgrade the passwd package to version 1:4.0.13-7ubuntu2 to
fix the installer log files.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- base-config-2.67ubuntu20 (Ubuntu 5.10)
- login-4.0.3-37ubuntu8 (Ubuntu 5.10)
- passwd-4.0.3-37ubuntu8 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "base-config", pkgver: "2.67ubuntu20");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package base-config-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to base-config-2.67ubuntu20
');
}
found = ubuntu_check(osver: "5.10", pkgname: "login", pkgver: "4.0.3-37ubuntu8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package login-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to login-4.0.3-37ubuntu8
');
}
found = ubuntu_check(osver: "5.10", pkgname: "passwd", pkgver: "4.0.3-37ubuntu8");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package passwd-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to passwd-4.0.3-37ubuntu8
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
