# This script was automatically generated from the 501-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28104);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "501-1");
script_summary(english:"jasper vulnerability");
script_name(english:"USN501-1 : jasper vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libjasper-1.701-1 
- libjasper-1.701-dev 
- libjasper-runtime 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Jasper did not correctly handle corrupted JPEG2000
images.  By tricking a user into opening a specially crafted JPG, a
remote attacker could cause the application using libjasper to crash,
resulting in a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libjasper-1.701-1-1.701.0-2ubuntu0.7.04 (Ubuntu 7.04)
- libjasper-1.701-dev-1.701.0-2ubuntu0.7.04 (Ubuntu 7.04)
- libjasper-runtime-1.701.0-2ubuntu0.7.04 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-2721");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libjasper-1.701-1", pkgver: "1.701.0-2ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libjasper-1.701-1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libjasper-1.701-1-1.701.0-2ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libjasper-1.701-dev", pkgver: "1.701.0-2ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libjasper-1.701-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libjasper-1.701-dev-1.701.0-2ubuntu0.7.04
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libjasper-runtime", pkgver: "1.701.0-2ubuntu0.7.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libjasper-runtime-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libjasper-runtime-1.701.0-2ubuntu0.7.04
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
