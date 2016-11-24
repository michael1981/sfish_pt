# This script was automatically generated from the 655-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37662);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "655-1");
script_summary(english:"exiv2 vulnerabilities");
script_name(english:"USN655-1 : exiv2 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- exiv2 
- libexiv2-0 
- libexiv2-0.12 
- libexiv2-2 
- libexiv2-dev 
- libexiv2-doc 
');
script_set_attribute(attribute:'description', value: 'Meder Kydyraliev discovered that exiv2 did not correctly handle certain
EXIF headers. If a user or automated system were tricked into processing
a specially crafted image, a remote attacker could cause the application
linked against libexiv2 to crash, leading to a denial of service, or
possibly executing arbitrary code with user privileges. (CVE-2007-6353)

Joakim Bildrulle discovered that exiv2 did not correctly handle Nikon
lens EXIF information.  If a user or automated system were tricked into
processing a specially crafted image, a remote attacker could cause the
application linked against libexiv2 to crash, leading to a denial of
service. (CVE-2008-2696)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- exiv2-0.16-3ubuntu1.1 (Ubuntu 8.04)
- libexiv2-0-0.15-1ubuntu2.1 (Ubuntu 7.10)
- libexiv2-0.12-0.12-0ubuntu2.1 (Ubuntu 7.04)
- libexiv2-2-0.16-3ubuntu1.1 (Ubuntu 8.04)
- libexiv2-dev-0.16-3ubuntu1.1 (Ubuntu 8.04)
- libexiv2-doc-0.16-3ubuntu1.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-6353","CVE-2008-2696");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "exiv2", pkgver: "0.16-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package exiv2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to exiv2-0.16-3ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libexiv2-0", pkgver: "0.15-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexiv2-0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libexiv2-0-0.15-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libexiv2-0.12", pkgver: "0.12-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexiv2-0.12-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libexiv2-0.12-0.12-0ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libexiv2-2", pkgver: "0.16-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexiv2-2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libexiv2-2-0.16-3ubuntu1.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libexiv2-dev", pkgver: "0.16-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexiv2-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libexiv2-dev-0.16-3ubuntu1.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libexiv2-doc", pkgver: "0.16-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexiv2-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libexiv2-doc-0.16-3ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
