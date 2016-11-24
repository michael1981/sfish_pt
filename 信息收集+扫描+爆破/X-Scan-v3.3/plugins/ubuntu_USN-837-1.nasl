# This script was automatically generated from the 837-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(41624);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "837-1");
script_summary(english:"newt vulnerability");
script_name(english:"USN837-1 : newt vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libnewt-dev 
- libnewt-pic 
- libnewt0.51 
- libnewt0.52 
- newt-tcl 
- python-newt 
- python-newt-dbg 
- whiptail 
');
script_set_attribute(attribute:'description', value: 'Miroslav Lichvar discovered that Newt incorrectly handled rendering in a
text box. An attacker could exploit this and cause a denial of service or
possibly execute arbitrary code with the privileges of the user invoking
the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnewt-dev-0.52.2-11.3ubuntu3.1 (Ubuntu 9.04)
- libnewt-pic-0.52.2-11.3ubuntu3.1 (Ubuntu 9.04)
- libnewt0.51-0.51.6-31ubuntu1.1 (Ubuntu 6.06)
- libnewt0.52-0.52.2-11.3ubuntu3.1 (Ubuntu 9.04)
- newt-tcl-0.52.2-11.3ubuntu3.1 (Ubuntu 9.04)
- python-newt-0.52.2-11.3ubuntu3.1 (Ubuntu 9.04)
- python-newt-dbg-0.52.2-11.3ubuntu3.1 (Ubuntu 9.04)
- whiptail-0.52.2-11.3ubuntu3.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

script_cve_id("CVE-2009-2905");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libnewt-dev", pkgver: "0.52.2-11.3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnewt-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libnewt-dev-0.52.2-11.3ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libnewt-pic", pkgver: "0.52.2-11.3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnewt-pic-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libnewt-pic-0.52.2-11.3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnewt0.51", pkgver: "0.51.6-31ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnewt0.51-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnewt0.51-0.51.6-31ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libnewt0.52", pkgver: "0.52.2-11.3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnewt0.52-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libnewt0.52-0.52.2-11.3ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "newt-tcl", pkgver: "0.52.2-11.3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package newt-tcl-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to newt-tcl-0.52.2-11.3ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "python-newt", pkgver: "0.52.2-11.3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-newt-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to python-newt-0.52.2-11.3ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "python-newt-dbg", pkgver: "0.52.2-11.3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-newt-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to python-newt-dbg-0.52.2-11.3ubuntu3.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "whiptail", pkgver: "0.52.2-11.3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package whiptail-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to whiptail-0.52.2-11.3ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
