# This script was automatically generated from the 91-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20717);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "91-1");
script_summary(english:"libexif vulnerabilities");
script_name(english:"USN91-1 : libexif vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libexif-dev 
- libexif10 
');
script_set_attribute(attribute:'description', value: 'Sylvain Defresne discovered that the EXIF library did not properly
validate the structure of the EXIF tags. By tricking a user to load an
image with a malicious EXIF tag, an attacker could exploit this to
crash the process using the library, or even execute arbitrary code
with the privileges of the process.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libexif-dev-0.6.9-1ubuntu0.1 (Ubuntu 4.10)
- libexif10-0.6.9-1ubuntu0.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "libexif-dev", pkgver: "0.6.9-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexif-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libexif-dev-0.6.9-1ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libexif10", pkgver: "0.6.9-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexif10-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libexif10-0.6.9-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
