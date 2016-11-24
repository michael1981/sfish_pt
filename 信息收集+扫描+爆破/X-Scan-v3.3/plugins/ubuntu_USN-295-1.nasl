# This script was automatically generated from the 295-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27867);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "295-1");
script_summary(english:"xine-lib vulnerability");
script_name(english:"USN295-1 : xine-lib vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libxine-dev 
- libxine-main1 
- libxine1 
- libxine1c2 
');
script_set_attribute(attribute:'description', value: 'Federico L. Bossi Bonin discovered a buffer overflow in the HTTP input
module. By tricking an user into opening a malicious remote media
location, a remote attacker could exploit this to crash Xine library
frontends (like totem-xine, gxine, or xine-ui) and possibly even
execute arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxine-dev-1.1.1+ubuntu2-7.1 (Ubuntu 6.06)
- libxine-main1-1.1.1+ubuntu2-7.1 (Ubuntu 6.06)
- libxine1-1.0-1ubuntu3.7 (Ubuntu 5.04)
- libxine1c2-1.0.1-1ubuntu10.3 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2802");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libxine-dev", pkgver: "1.1.1+ubuntu2-7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libxine-dev-1.1.1+ubuntu2-7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libxine-main1", pkgver: "1.1.1+ubuntu2-7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-main1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libxine-main1-1.1.1+ubuntu2-7.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libxine1", pkgver: "1.0-1ubuntu3.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libxine1-1.0-1ubuntu3.7
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libxine1c2", pkgver: "1.0.1-1ubuntu10.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libxine1c2-1.0.1-1ubuntu10.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
