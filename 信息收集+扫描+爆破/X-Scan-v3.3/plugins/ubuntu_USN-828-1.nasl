# This script was automatically generated from the 828-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40906);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "828-1");
script_summary(english:"pam vulnerability");
script_name(english:"USN828-1 : pam vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpam-cracklib 
- libpam-doc 
- libpam-modules 
- libpam-runtime 
- libpam0g 
- libpam0g-dev 
');
script_set_attribute(attribute:'description', value: 'Russell Senior discovered that the system authentication module
selection mechanism for PAM did not safely handle an empty selection.
If an administrator had specifically removed the default list of modules
or failed to chose a module when operating debconf in a very unlikely
non-default configuration, PAM would allow any authentication attempt,
which could lead to remote attackers gaining access to a system with
arbitrary privileges.  This did not affect default Ubuntu installations.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpam-cracklib-1.0.1-9ubuntu1.1 (Ubuntu 9.04)
- libpam-doc-1.0.1-9ubuntu1.1 (Ubuntu 9.04)
- libpam-modules-1.0.1-9ubuntu1.1 (Ubuntu 9.04)
- libpam-runtime-1.0.1-9ubuntu1.1 (Ubuntu 9.04)
- libpam0g-1.0.1-9ubuntu1.1 (Ubuntu 9.04)
- libpam0g-dev-1.0.1-9ubuntu1.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libpam-cracklib", pkgver: "1.0.1-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-cracklib-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpam-cracklib-1.0.1-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpam-doc", pkgver: "1.0.1-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpam-doc-1.0.1-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpam-modules", pkgver: "1.0.1-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-modules-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpam-modules-1.0.1-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpam-runtime", pkgver: "1.0.1-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam-runtime-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpam-runtime-1.0.1-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpam0g", pkgver: "1.0.1-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam0g-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpam0g-1.0.1-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpam0g-dev", pkgver: "1.0.1-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpam0g-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpam0g-dev-1.0.1-9ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
