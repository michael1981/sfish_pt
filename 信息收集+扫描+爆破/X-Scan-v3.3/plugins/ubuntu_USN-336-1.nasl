# This script was automatically generated from the 336-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27915);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "336-1");
script_summary(english:"binutils vulnerability");
script_name(english:"USN336-1 : binutils vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- binutils 
- binutils-dev 
- binutils-doc 
- binutils-multiarch 
- binutils-static 
');
script_set_attribute(attribute:'description', value: 'A buffer overflow was discovered in gas (the GNU assembler). By
tricking an user or automated system (like a compile farm) into
assembling a specially crafted source file with gcc or gas, this could
be exploited to execute arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- binutils-2.16.1-2ubuntu6.2 (Ubuntu 5.10)
- binutils-dev-2.16.1-2ubuntu6.2 (Ubuntu 5.10)
- binutils-doc-2.16.1-2ubuntu6.2 (Ubuntu 5.10)
- binutils-multiarch-2.16.1-2ubuntu6.2 (Ubuntu 5.10)
- binutils-static-2.16.1-2ubuntu6.2 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "binutils", pkgver: "2.16.1-2ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to binutils-2.16.1-2ubuntu6.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "binutils-dev", pkgver: "2.16.1-2ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to binutils-dev-2.16.1-2ubuntu6.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "binutils-doc", pkgver: "2.16.1-2ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-doc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to binutils-doc-2.16.1-2ubuntu6.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "binutils-multiarch", pkgver: "2.16.1-2ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-multiarch-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to binutils-multiarch-2.16.1-2ubuntu6.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "binutils-static", pkgver: "2.16.1-2ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package binutils-static-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to binutils-static-2.16.1-2ubuntu6.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
