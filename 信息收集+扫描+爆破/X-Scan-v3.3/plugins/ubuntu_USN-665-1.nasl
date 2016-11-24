# This script was automatically generated from the 665-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38074);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "665-1");
script_summary(english:"netpbm-free vulnerability");
script_name(english:"USN665-1 : netpbm-free vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libnetpbm10 
- libnetpbm10-dev 
- libnetpbm9 
- libnetpbm9-dev 
- netpbm 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Netpbm could be made to overrun a buffer when loading
certain images. If a user were tricked into opening a specially crafted
GIF image, remote attackers could cause a denial of service or execute
arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnetpbm10-10.0-11ubuntu0.1 (Ubuntu 7.10)
- libnetpbm10-dev-10.0-11ubuntu0.1 (Ubuntu 7.10)
- libnetpbm9-10.0-11ubuntu0.1 (Ubuntu 7.10)
- libnetpbm9-dev-10.0-11ubuntu0.1 (Ubuntu 7.10)
- netpbm-10.0-11ubuntu0.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-0554");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libnetpbm10", pkgver: "10.0-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm10-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libnetpbm10-10.0-11ubuntu0.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libnetpbm10-dev", pkgver: "10.0-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm10-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libnetpbm10-dev-10.0-11ubuntu0.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libnetpbm9", pkgver: "10.0-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm9-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libnetpbm9-10.0-11ubuntu0.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libnetpbm9-dev", pkgver: "10.0-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm9-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libnetpbm9-dev-10.0-11ubuntu0.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "netpbm", pkgver: "10.0-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package netpbm-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to netpbm-10.0-11ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
