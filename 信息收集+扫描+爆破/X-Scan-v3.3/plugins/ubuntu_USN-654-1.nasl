# This script was automatically generated from the 654-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38049);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "654-1");
script_summary(english:"libexif vulnerabilities");
script_name(english:"USN654-1 : libexif vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libexif-dev 
- libexif12 
');
script_set_attribute(attribute:'description', value: 'Meder Kydyraliev discovered that libexif did not correctly handle certain
EXIF headers.  If a user or automated system were tricked into processing
a specially crafted image, a remote attacker could cause the application
linked against libexif to crash, leading to a denial of service, or
possibly executing arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libexif-dev-0.6.16-1ubuntu0.1 (Ubuntu 7.10)
- libexif12-0.6.16-1ubuntu0.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-6351","CVE-2007-6352");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libexif-dev", pkgver: "0.6.16-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexif-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libexif-dev-0.6.16-1ubuntu0.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libexif12", pkgver: "0.6.16-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libexif12-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libexif12-0.6.16-1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
