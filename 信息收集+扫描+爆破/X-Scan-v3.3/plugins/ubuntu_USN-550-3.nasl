# This script was automatically generated from the 550-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29696);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "550-3");
script_summary(english:"Cairo regression");
script_name(english:"USN550-3 : Cairo regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libcairo-directfb2 
- libcairo-directfb2-dev 
- libcairo2 
- libcairo2-dev 
- libcairo2-doc 
');
script_set_attribute(attribute:'description', value: 'USN-550-1 fixed vulnerabilities in Cairo.  A bug in font glyph rendering
was uncovered as a result of the new memory allocation routines.  In
certain situations, fonts containing characters with no width or height
would not render any more.  This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Peter Valchev discovered that Cairo did not correctly decode PNG image data.
 By tricking a user or automated system into processing a specially crafted
 PNG with Cairo, a remote attacker could execute arbitrary code with user
 privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libcairo-directfb2-1.4.10-1ubuntu4.4 (Ubuntu 7.10)
- libcairo-directfb2-dev-1.4.10-1ubuntu4.4 (Ubuntu 7.10)
- libcairo2-1.4.10-1ubuntu4.4 (Ubuntu 7.10)
- libcairo2-dev-1.4.10-1ubuntu4.4 (Ubuntu 7.10)
- libcairo2-doc-1.4.10-1ubuntu4.4 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libcairo-directfb2", pkgver: "1.4.10-1ubuntu4.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcairo-directfb2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcairo-directfb2-1.4.10-1ubuntu4.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcairo-directfb2-dev", pkgver: "1.4.10-1ubuntu4.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcairo-directfb2-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcairo-directfb2-dev-1.4.10-1ubuntu4.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcairo2", pkgver: "1.4.10-1ubuntu4.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcairo2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcairo2-1.4.10-1ubuntu4.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcairo2-dev", pkgver: "1.4.10-1ubuntu4.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcairo2-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcairo2-dev-1.4.10-1ubuntu4.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcairo2-doc", pkgver: "1.4.10-1ubuntu4.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcairo2-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcairo2-doc-1.4.10-1ubuntu4.4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
