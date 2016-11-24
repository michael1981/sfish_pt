# This script was automatically generated from the 514-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28119);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "514-1");
script_summary(english:"X.org vulnerability");
script_name(english:"USN514-1 : X.org vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- xdmx 
- xdmx-tools 
- xnest 
- xserver-xorg-core 
- xserver-xorg-dev 
- xvfb 
');
script_set_attribute(attribute:'description', value: 'Aaron Plattner discovered that the Composite extension did not correctly
calculate the size of buffers when copying between different bit depths.
An authenticated user could exploit this to execute arbitrary code with
root privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- xdmx-1.0.2-0ubuntu10.7 (Ubuntu 6.06)
- xdmx-tools-1.0.2-0ubuntu10.7 (Ubuntu 6.06)
- xnest-1.0.2-0ubuntu10.7 (Ubuntu 6.06)
- xserver-xorg-core-1.0.2-0ubuntu10.7 (Ubuntu 6.06)
- xserver-xorg-dev-1.0.2-0ubuntu10.7 (Ubuntu 6.06)
- xvfb-1.0.2-0ubuntu10.7 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:S/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-4730");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "xdmx", pkgver: "1.0.2-0ubuntu10.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xdmx-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xdmx-1.0.2-0ubuntu10.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "xdmx-tools", pkgver: "1.0.2-0ubuntu10.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xdmx-tools-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xdmx-tools-1.0.2-0ubuntu10.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "xnest", pkgver: "1.0.2-0ubuntu10.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xnest-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xnest-1.0.2-0ubuntu10.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "xserver-xorg-core", pkgver: "1.0.2-0ubuntu10.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-core-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xserver-xorg-core-1.0.2-0ubuntu10.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "xserver-xorg-dev", pkgver: "1.0.2-0ubuntu10.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xserver-xorg-dev-1.0.2-0ubuntu10.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "xvfb", pkgver: "1.0.2-0ubuntu10.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xvfb-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to xvfb-1.0.2-0ubuntu10.7
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
