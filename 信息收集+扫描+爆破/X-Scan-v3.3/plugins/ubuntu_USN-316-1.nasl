# This script was automatically generated from the 316-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27892);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "316-1");
script_summary(english:"installer vulnerability");
script_name(english:"USN316-1 : installer vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- login 
- passwd 
- user-setup 
');
script_set_attribute(attribute:'description', value: 'Iwan Pieterse discovered that, if you select "Go Back" at the final
message displayed by the alternate or server CD installer ("Installation
complete") and then continue with the installation from the installer\'s
main menu, the root password is left blank rather than locked. This was
due to an error while clearing out the root password from the
installer\'s memory to avoid possible information leaks.

Installations from the alternate or server CDs when the user selected
"Continue" when the "Installation complete" message was first displayed
are not affected by this bug. Installations from the desktop CD are not
affected by this bug at all.

When you upgrade your passwd package to the newest version, it will
detect this condition and lock the root password if it was previously
blank. The next point release of Ubuntu 6.06 LTS will include a
corrected installer.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- login-4.0.13-7ubuntu3.2 (Ubuntu 6.06)
- passwd-4.0.13-7ubuntu3.2 (Ubuntu 6.06)
- user-setup-1.1ubuntu4 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "login", pkgver: "4.0.13-7ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package login-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to login-4.0.13-7ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "passwd", pkgver: "4.0.13-7ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package passwd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to passwd-4.0.13-7ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "user-setup", pkgver: "1.1ubuntu4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package user-setup-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to user-setup-1.1ubuntu4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
