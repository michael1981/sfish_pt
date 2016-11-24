# This script was automatically generated from the 616-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33199);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "616-1");
script_summary(english:"X.org vulnerabilities");
script_name(english:"USN616-1 : X.org vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- xdmx 
- xdmx-tools 
- xnest 
- xprint 
- xprint-common 
- xserver-xephyr 
- xserver-xorg-core 
- xserver-xorg-core-dbg 
- xserver-xorg-dev 
- xvfb 
');
script_set_attribute(attribute:'description', value: 'Multiple flaws were found in the RENDER, RECORD, and Security
extensions of X.org which did not correctly validate function arguments.
An authenticated attacker could send specially crafted requests and gain
root privileges or crash X. (CVE-2008-1377, CVE-2008-2360, CVE-2008-2361,
CVE-2008-2362)

It was discovered that the MIT-SHM extension of X.org did not correctly
validate the location of memory during an image copy.  An authenticated
attacker could exploit this to read arbitrary memory locations within X,
exposing sensitive information. (CVE-2008-1379)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- xdmx-1.3.0.0.dfsg-12ubuntu8.4 (Ubuntu 7.10)
- xdmx-tools-1.3.0.0.dfsg-12ubuntu8.4 (Ubuntu 7.10)
- xnest-1.3.0.0.dfsg-12ubuntu8.4 (Ubuntu 7.10)
- xprint-1.3.0.0.dfsg-12ubuntu8.4 (Ubuntu 7.10)
- xprint-common-1.3.0.0.dfsg-12ubuntu8.4 (Ubuntu 7.10)
- xserver-xephyr-1.3.0.0.dfsg-12ubuntu8.4 (Ubuntu 7.10)
- xserver-xorg-core-1.3.0.0.dfsg-12ubuntu8.4 (Ubuntu 7.10)
- xserver-xorg-core-dbg-1.3.0.0.dfsg-12ubuntu8.4 (Ubuntu 7.10)
- xserver-xorg-dev-1.3.0.0.dfsg-12ubuntu8.4 (Ubuntu 7.10)
- xvfb-1.3.0.
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1377","CVE-2008-1379","CVE-2008-2360","CVE-2008-2361","CVE-2008-2362");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "xdmx", pkgver: "1.3.0.0.dfsg-12ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xdmx-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xdmx-1.3.0.0.dfsg-12ubuntu8.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xdmx-tools", pkgver: "1.3.0.0.dfsg-12ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xdmx-tools-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xdmx-tools-1.3.0.0.dfsg-12ubuntu8.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xnest", pkgver: "1.3.0.0.dfsg-12ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xnest-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xnest-1.3.0.0.dfsg-12ubuntu8.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xprint", pkgver: "1.3.0.0.dfsg-12ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xprint-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xprint-1.3.0.0.dfsg-12ubuntu8.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xprint-common", pkgver: "1.3.0.0.dfsg-12ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xprint-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xprint-common-1.3.0.0.dfsg-12ubuntu8.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xserver-xephyr", pkgver: "1.3.0.0.dfsg-12ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xephyr-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xserver-xephyr-1.3.0.0.dfsg-12ubuntu8.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xserver-xorg-core", pkgver: "1.3.0.0.dfsg-12ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-core-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xserver-xorg-core-1.3.0.0.dfsg-12ubuntu8.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xserver-xorg-core-dbg", pkgver: "1.3.0.0.dfsg-12ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-core-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xserver-xorg-core-dbg-1.3.0.0.dfsg-12ubuntu8.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xserver-xorg-dev", pkgver: "1.3.0.0.dfsg-12ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xserver-xorg-dev-1.3.0.0.dfsg-12ubuntu8.4
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xvfb", pkgver: "1.3.0.0.dfsg-12ubuntu8.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xvfb-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xvfb-1.3.0.0.dfsg-12ubuntu8.4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
