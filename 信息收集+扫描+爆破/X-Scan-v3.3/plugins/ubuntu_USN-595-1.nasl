# This script was automatically generated from the 595-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31703);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "595-1");
script_summary(english:"SDL_image vulnerabilities");
script_name(english:"USN595-1 : SDL_image vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libsdl-image1.2 
- libsdl-image1.2-dev 
');
script_set_attribute(attribute:'description', value: 'Michael Skladnikiewicz discovered that SDL_image did not correctly load
GIF images.  If a user or automated system were tricked into processing
a specially crafted GIF, a remote attacker could execute arbitrary code
or cause a crash, leading to a denial of service. (CVE-2007-6697)

David Raulo discovered that SDL_image did not correctly load ILBM images.
If a user or automated system were tricked into processing a specially
crafted ILBM, a remote attacker could execute arbitrary code or cause
a crash, leading to a denial of service. (CVE-2008-0544)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libsdl-image1.2-1.2.5-3ubuntu0.1 (Ubuntu 7.10)
- libsdl-image1.2-dev-1.2.5-3ubuntu0.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-6697","CVE-2008-0544");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libsdl-image1.2", pkgver: "1.2.5-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsdl-image1.2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsdl-image1.2-1.2.5-3ubuntu0.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libsdl-image1.2-dev", pkgver: "1.2.5-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsdl-image1.2-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsdl-image1.2-dev-1.2.5-3ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
