# This script was automatically generated from the 472-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28073);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "472-1");
script_summary(english:"libpng vulnerability");
script_name(english:"USN472-1 : libpng vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpng12-0 
- libpng12-dev 
- libpng3 
');
script_set_attribute(attribute:'description', value: 'It was discovered that libpng did not correctly handle corrupted CRC
in grayscale PNG images.  By tricking a user into opening a specially
crafted PNG, a remote attacker could cause the application using libpng
to crash, resulting in a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpng12-0-1.2.8rel-5.1ubuntu0.2 (Ubuntu 6.10)
- libpng12-dev-1.2.8rel-5.1ubuntu0.2 (Ubuntu 6.10)
- libpng3-1.2.8rel-5.1ubuntu0.2 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-2445");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libpng12-0", pkgver: "1.2.8rel-5.1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng12-0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpng12-0-1.2.8rel-5.1ubuntu0.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpng12-dev", pkgver: "1.2.8rel-5.1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng12-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpng12-dev-1.2.8rel-5.1ubuntu0.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libpng3", pkgver: "1.2.8rel-5.1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng3-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libpng3-1.2.8rel-5.1ubuntu0.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
