# This script was automatically generated from the 571-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(30042);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "571-2");
script_summary(english:"X.org regression");
script_name(english:"USN571-2 : X.org regression");
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
script_set_attribute(attribute:'description', value: 'USN-571-1 fixed vulnerabilities in X.org.  The upstream fixes were
incomplete, and under certain situations, applications using the MIT-SHM
extension (e.g. Java, wxWidgets) would crash with BadAlloc X errors.
This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Multiple overflows were discovered in the XFree86-Misc, XInput-Misc,
 TOG-CUP, EVI, and MIT-SHM extensions which did not correctly validate
 function arguments.  An authenticated attacker could send specially
 crafted requests and gain root privileges. (CVE-2007-5760, CVE-2007-6427,
 CVE-2007-6428, CVE-2007-6429)
 
 It was discovered that the X.org server did not use user privileges when
 attempting to open security policy files.  Local attackers could exploit
 this to probe for files in directories they would not normally be able
 to access.  (CVE-2007-5958)
 
 It was discovered that the PCF font handling code did not correctly
 validate the size of fonts.  An authenticated attacker could load a
 specially
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- xdmx-1.3.0.0.dfsg-12ubuntu8.3 (Ubuntu 7.10)
- xdmx-tools-1.3.0.0.dfsg-12ubuntu8.3 (Ubuntu 7.10)
- xnest-1.3.0.0.dfsg-12ubuntu8.3 (Ubuntu 7.10)
- xprint-1.3.0.0.dfsg-12ubuntu8.3 (Ubuntu 7.10)
- xprint-common-1.3.0.0.dfsg-12ubuntu8.3 (Ubuntu 7.10)
- xserver-xephyr-1.3.0.0.dfsg-12ubuntu8.3 (Ubuntu 7.10)
- xserver-xorg-core-1.3.0.0.dfsg-12ubuntu8.3 (Ubuntu 7.10)
- xserver-xorg-core-dbg-1.3.0.0.dfsg-12ubuntu8.3 (Ubuntu 7.10)
- xserver-xorg-dev-1.3.0.0.dfsg-12ubuntu8.3 (Ubuntu 7.10)
- xvfb-1.3.0.
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-5760","CVE-2007-5958","CVE-2007-6427","CVE-2007-6428","CVE-2007-6429","CVE-2008-0006");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "xdmx", pkgver: "1.3.0.0.dfsg-12ubuntu8.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xdmx-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xdmx-1.3.0.0.dfsg-12ubuntu8.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xdmx-tools", pkgver: "1.3.0.0.dfsg-12ubuntu8.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xdmx-tools-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xdmx-tools-1.3.0.0.dfsg-12ubuntu8.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xnest", pkgver: "1.3.0.0.dfsg-12ubuntu8.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xnest-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xnest-1.3.0.0.dfsg-12ubuntu8.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xprint", pkgver: "1.3.0.0.dfsg-12ubuntu8.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xprint-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xprint-1.3.0.0.dfsg-12ubuntu8.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xprint-common", pkgver: "1.3.0.0.dfsg-12ubuntu8.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xprint-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xprint-common-1.3.0.0.dfsg-12ubuntu8.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xserver-xephyr", pkgver: "1.3.0.0.dfsg-12ubuntu8.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xephyr-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xserver-xephyr-1.3.0.0.dfsg-12ubuntu8.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xserver-xorg-core", pkgver: "1.3.0.0.dfsg-12ubuntu8.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-core-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xserver-xorg-core-1.3.0.0.dfsg-12ubuntu8.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xserver-xorg-core-dbg", pkgver: "1.3.0.0.dfsg-12ubuntu8.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-core-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xserver-xorg-core-dbg-1.3.0.0.dfsg-12ubuntu8.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xserver-xorg-dev", pkgver: "1.3.0.0.dfsg-12ubuntu8.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xserver-xorg-dev-1.3.0.0.dfsg-12ubuntu8.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "xvfb", pkgver: "1.3.0.0.dfsg-12ubuntu8.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xvfb-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to xvfb-1.3.0.0.dfsg-12ubuntu8.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
