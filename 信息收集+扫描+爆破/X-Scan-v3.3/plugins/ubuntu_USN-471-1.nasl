# This script was automatically generated from the 471-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28072);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "471-1");
script_summary(english:"libexif vulnerability");
script_name(english:"USN471-1 : libexif vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libexif-dev 
- libexif12 
');
script_set_attribute(attribute:'description', value: 'Victor Stinner discovered that libexif did not correctly validate the
size of some EXIF header fields.  By tricking a user into opening an
image with specially crafted EXIF headers, a remote attacker could cause
the application using libexif to crash, resulting in a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libexif-dev-0.6.13-5ubuntu0.1 (Ubuntu 7.04)
- libexif12-0.6.13-5ubuntu0.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-2645");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libexif-dev", pkgver: "0.6.13-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexif-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libexif-dev-0.6.13-5ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libexif12", pkgver: "0.6.13-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexif12-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libexif12-0.6.13-5ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
