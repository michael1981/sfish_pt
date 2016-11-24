# This script was automatically generated from the 708-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36714);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "708-1");
script_summary(english:"hplip vulnerability");
script_name(english:"USN708-1 : hplip vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- hpijs 
- hpijs-ppds 
- hplip 
- hplip-data 
- hplip-dbg 
- hplip-doc 
- hplip-gui 
');
script_set_attribute(attribute:'description', value: 'It was discovered that an installation script in the HPLIP package would
change permissions on the hplip config files located in user\'s home directories.
A local user could exploit this and change permissions on arbitrary files
upon an HPLIP installation or upgrade, which could lead to root privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- hpijs-2.7.7+2.7.7.dfsg.1-0ubuntu5.3 (Ubuntu 7.10)
- hpijs-ppds-2.7.7+2.7.7.dfsg.1-0ubuntu5.3 (Ubuntu 7.10)
- hplip-2.7.7.dfsg.1-0ubuntu5.3 (Ubuntu 7.10)
- hplip-data-2.7.7.dfsg.1-0ubuntu5.3 (Ubuntu 7.10)
- hplip-dbg-2.7.7.dfsg.1-0ubuntu5.3 (Ubuntu 7.10)
- hplip-doc-2.7.7.dfsg.1-0ubuntu5.3 (Ubuntu 7.10)
- hplip-gui-2.7.7.dfsg.1-0ubuntu5.3 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "hpijs", pkgver: "2.7.7+2.7.7.dfsg.1-0ubuntu5.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hpijs-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to hpijs-2.7.7+2.7.7.dfsg.1-0ubuntu5.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "hpijs-ppds", pkgver: "2.7.7+2.7.7.dfsg.1-0ubuntu5.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hpijs-ppds-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to hpijs-ppds-2.7.7+2.7.7.dfsg.1-0ubuntu5.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "hplip", pkgver: "2.7.7.dfsg.1-0ubuntu5.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to hplip-2.7.7.dfsg.1-0ubuntu5.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "hplip-data", pkgver: "2.7.7.dfsg.1-0ubuntu5.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-data-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to hplip-data-2.7.7.dfsg.1-0ubuntu5.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "hplip-dbg", pkgver: "2.7.7.dfsg.1-0ubuntu5.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to hplip-dbg-2.7.7.dfsg.1-0ubuntu5.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "hplip-doc", pkgver: "2.7.7.dfsg.1-0ubuntu5.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to hplip-doc-2.7.7.dfsg.1-0ubuntu5.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "hplip-gui", pkgver: "2.7.7.dfsg.1-0ubuntu5.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package hplip-gui-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to hplip-gui-2.7.7.dfsg.1-0ubuntu5.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
