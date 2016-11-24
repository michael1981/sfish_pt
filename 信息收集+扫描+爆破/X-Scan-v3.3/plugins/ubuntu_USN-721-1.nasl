# This script was automatically generated from the 721-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37002);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "721-1");
script_summary(english:"fglrx-installer vulnerability");
script_name(english:"USN721-1 : fglrx-installer vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- fglrx-amdcccle 
- fglrx-kernel-source 
- fglrx-modaliases 
- libamdxvba1 
- xorg-driver-fglrx 
- xorg-driver-fglrx-dev 
');
script_set_attribute(attribute:'description', value: 'Marko Lindqvist discovered that the fglrx installer created an unsafe
LD_LIBRARY_PATH on 64bit systems.  If a user were tricked into downloading
specially crafted libraries and running commands in the same directory,
a remote attacker could execute arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- fglrx-amdcccle-8.543-0ubuntu4.1 (Ubuntu 8.10)
- fglrx-kernel-source-8.543-0ubuntu4.1 (Ubuntu 8.10)
- fglrx-modaliases-8.543-0ubuntu4.1 (Ubuntu 8.10)
- libamdxvba1-8.543-0ubuntu4.1 (Ubuntu 8.10)
- xorg-driver-fglrx-8.543-0ubuntu4.1 (Ubuntu 8.10)
- xorg-driver-fglrx-dev-8.543-0ubuntu4.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "fglrx-amdcccle", pkgver: "8.543-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-amdcccle-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to fglrx-amdcccle-8.543-0ubuntu4.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "fglrx-kernel-source", pkgver: "8.543-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-kernel-source-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to fglrx-kernel-source-8.543-0ubuntu4.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "fglrx-modaliases", pkgver: "8.543-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package fglrx-modaliases-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to fglrx-modaliases-8.543-0ubuntu4.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libamdxvba1", pkgver: "8.543-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libamdxvba1-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libamdxvba1-8.543-0ubuntu4.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xorg-driver-fglrx", pkgver: "8.543-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xorg-driver-fglrx-8.543-0ubuntu4.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xorg-driver-fglrx-dev", pkgver: "8.543-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-driver-fglrx-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xorg-driver-fglrx-dev-8.543-0ubuntu4.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
