# This script was automatically generated from the 136-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20528);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "136-2");
script_summary(english:"binutils regression");
script_name(english:"USN136-2 : binutils regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- binutils 
- binutils-dev 
- binutils-doc 
- binutils-multiarch 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the packages from USN-136-1 had a flawed patch
with regressions that caused the ld linker to fail. The updated
packages fix this.

We apologize for the inconvenience.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- binutils-2.15-5ubuntu2.2 (Ubuntu 5.04)
- binutils-dev-2.15-5ubuntu2.2 (Ubuntu 5.04)
- binutils-doc-2.15-5ubuntu2.2 (Ubuntu 5.04)
- binutils-multiarch-2.15-5ubuntu2.2 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "binutils", pkgver: "2.15-5ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to binutils-2.15-5ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "binutils-dev", pkgver: "2.15-5ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to binutils-dev-2.15-5ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "binutils-doc", pkgver: "2.15-5ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to binutils-doc-2.15-5ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "binutils-multiarch", pkgver: "2.15-5ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-multiarch-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to binutils-multiarch-2.15-5ubuntu2.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
