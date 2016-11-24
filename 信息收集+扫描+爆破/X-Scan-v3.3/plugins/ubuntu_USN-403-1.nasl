# This script was automatically generated from the 403-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27991);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "403-1");
script_summary(english:"X.org vulnerabilities");
script_name(english:"USN403-1 : X.org vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- x-window-system-core 
- x-window-system-dev 
- xbase-clients 
- xdmx 
- xdmx-tools 
- xlibs 
- xlibs-data 
- xlibs-dev 
- xlibs-static-dev 
- xlibs-static-pic 
- xnest 
- xorg-common 
- xserver-common 
- xserver-xephyr 
- xserver-xorg 
- xserver-xorg-core 
- xserver-xorg-dbg 
- xserver-xorg-dev 
- xserver-xorg-driver-apm 
- xserver-xorg-driver-ark 
- xserver-xorg-driver-ati 
- xserver-xorg-driver-chips 
- xserver-xorg-driver-cirrus 
- xserver-xorg-driv
[...]');
script_set_attribute(attribute:'description', value: 'The DBE and Render extensions in X.org were vulnerable to integer 
overflows, which could lead to memory overwrites.  An authenticated user 
could make a specially crafted request and execute arbitrary code with 
root privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- x-window-system-core-6.8.2-77.2 (Ubuntu 5.10)
- x-window-system-dev-6.8.2-77.2 (Ubuntu 5.10)
- xbase-clients-6.8.2-77.2 (Ubuntu 5.10)
- xdmx-1.1.1-0ubuntu12.1 (Ubuntu 6.10)
- xdmx-tools-1.1.1-0ubuntu12.1 (Ubuntu 6.10)
- xlibs-6.8.2-77.2 (Ubuntu 5.10)
- xlibs-data-6.8.2-77.2 (Ubuntu 5.10)
- xlibs-dev-6.8.2-77.2 (Ubuntu 5.10)
- xlibs-static-dev-6.8.2-77.2 (Ubuntu 5.10)
- xlibs-static-pic-6.8.2-77.2 (Ubuntu 5.10)
- xnest-1.1.1-0ubuntu12.1 (Ubuntu 6.10)
- xorg-common-6.8.2-77.2 (Ubuntu 5.10)
- 
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-6101","CVE-2006-6102","CVE-2006-6103");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "x-window-system-core", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package x-window-system-core-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to x-window-system-core-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "x-window-system-dev", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package x-window-system-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to x-window-system-dev-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xbase-clients", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xbase-clients-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xbase-clients-6.8.2-77.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xdmx", pkgver: "1.1.1-0ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xdmx-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xdmx-1.1.1-0ubuntu12.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xdmx-tools", pkgver: "1.1.1-0ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xdmx-tools-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xdmx-tools-1.1.1-0ubuntu12.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xlibs", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xlibs-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xlibs-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xlibs-data", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xlibs-data-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xlibs-data-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xlibs-dev", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xlibs-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xlibs-dev-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xlibs-static-dev", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xlibs-static-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xlibs-static-dev-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xlibs-static-pic", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xlibs-static-pic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xlibs-static-pic-6.8.2-77.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xnest", pkgver: "1.1.1-0ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xnest-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xnest-1.1.1-0ubuntu12.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xorg-common", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xorg-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xorg-common-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-common", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-common-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-common-6.8.2-77.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xserver-xephyr", pkgver: "1.1.1-0ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xephyr-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xserver-xephyr-1.1.1-0ubuntu12.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-6.8.2-77.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xserver-xorg-core", pkgver: "1.1.1-0ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-core-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xserver-xorg-core-1.1.1-0ubuntu12.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-dbg", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-dbg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-dbg-6.8.2-77.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xserver-xorg-dev", pkgver: "1.1.1-0ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xserver-xorg-dev-1.1.1-0ubuntu12.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-apm", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-apm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-apm-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-ark", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-ark-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-ark-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-ati", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-ati-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-ati-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-chips", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-chips-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-chips-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-cirrus", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-cirrus-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-cirrus-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-cyrix", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-cyrix-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-cyrix-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-dummy", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-dummy-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-dummy-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-fbdev", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-fbdev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-fbdev-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-glide", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-glide-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-glide-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-glint", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-glint-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-glint-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-i128", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-i128-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-i128-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-i740", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-i740-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-i740-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-i810", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-i810-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-i810-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-imstt", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-imstt-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-imstt-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-mga", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-mga-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-mga-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-neomagic", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-neomagic-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-neomagic-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-newport", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-newport-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-newport-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-nsc", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-nsc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-nsc-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-nv", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-nv-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-nv-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-rendition", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-rendition-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-rendition-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-s3", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-s3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-s3-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-s3virge", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-s3virge-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-s3virge-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-savage", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-savage-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-savage-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-siliconmotion", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-siliconmotion-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-siliconmotion-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-sis", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-sis-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-sis-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-sunbw2", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-sunbw2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-sunbw2-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-suncg14", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-suncg14-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-suncg14-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-suncg3", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-suncg3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-suncg3-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-suncg6", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-suncg6-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-suncg6-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-sunffb", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-sunffb-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-sunffb-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-sunleo", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-sunleo-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-sunleo-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-suntcx", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-suntcx-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-suntcx-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-tdfx", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-tdfx-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-tdfx-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-tga", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-tga-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-tga-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-trident", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-trident-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-trident-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-tseng", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-tseng-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-tseng-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-v4l", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-v4l-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-v4l-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-vesa", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-vesa-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-vesa-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-vga", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-vga-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-vga-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-via", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-via-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-via-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-driver-vmware", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-driver-vmware-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-driver-vmware-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-acecad", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-acecad-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-acecad-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-aiptek", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-aiptek-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-aiptek-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-calcomp", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-calcomp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-calcomp-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-citron", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-citron-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-citron-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-digitaledge", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-digitaledge-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-digitaledge-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-dmc", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-dmc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-dmc-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-dynapro", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-dynapro-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-dynapro-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-elographics", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-elographics-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-elographics-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-fpit", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-fpit-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-fpit-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-hyperpen", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-hyperpen-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-hyperpen-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-kbd", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-kbd-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-kbd-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-magellan", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-magellan-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-magellan-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-microtouch", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-microtouch-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-microtouch-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-mouse", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-mouse-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-mouse-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-mutouch", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-mutouch-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-mutouch-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-palmax", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-palmax-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-palmax-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-penmount", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-penmount-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-penmount-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-spaceorb", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-spaceorb-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-spaceorb-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-summa", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-summa-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-summa-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-tek4957", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-tek4957-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-tek4957-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-void", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-void-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-void-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xserver-xorg-input-wacom", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xserver-xorg-input-wacom-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xserver-xorg-input-wacom-6.8.2-77.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "xutils", pkgver: "6.8.2-77.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xutils-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to xutils-6.8.2-77.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xvfb", pkgver: "1.1.1-0ubuntu12.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xvfb-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xvfb-1.1.1-0ubuntu12.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
