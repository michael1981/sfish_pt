# This script was automatically generated from the 853-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42474);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "853-2");
script_summary(english:"firefox-3.5, xulrunner-1.9.1 regression");
script_name(english:"USN853-2 : firefox-3.5, xulrunner-1.9.1 regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- abrowser 
- abrowser-3.0 
- abrowser-3.0-branding 
- abrowser-3.1 
- abrowser-3.1-branding 
- abrowser-3.5 
- abrowser-3.5-branding 
- firefox 
- firefox-3.0 
- firefox-3.0-branding 
- firefox-3.0-dev 
- firefox-3.0-dom-inspector 
- firefox-3.0-gnome-support 
- firefox-3.0-venkman 
- firefox-3.1 
- firefox-3.1-branding 
- firefox-3.1-dbg 
- firefox-3.1-dev 
- firefox-3.1-gnome-support 
- firefox-3.5 
- firefox-3.5-branding 
- firefox-3.5-dbg 
- firefox
[...]');
script_set_attribute(attribute:'description', value: 'USN-853-1 fixed vulnerabilities in Firefox and Xulrunner. The upstream
changes introduced regressions that could lead to crashes when processing
certain malformed GIF images, fonts and web pages. This update fixes the
problem.

We apologize for the inconvenience.

Original advisory details:

 Alin Rad Pop discovered a heap-based buffer overflow in Firefox when it
 converted strings to floating point numbers. If a user were tricked into
 viewing a malicious website, a remote attacker could cause a denial of service
 or possibly execute arbitrary code with the privileges of the user invoking the
 program. (CVE-2009-1563)
 
 Jeremy Brown discovered that the Firefox Download Manager was vulnerable to
 symlink attacks. A local attacker could exploit this to create or overwrite
 files with the privileges of the user invoking the program. (CVE-2009-3274)
 
 Paul Stone discovered a flaw in the Firefox form history. If a user were
 tricked into viewing a malicious website, a remote attacker could access this
 data to
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- abrowser-3.5.5+nobinonly-0ubuntu0.9.10.1 (Ubuntu 9.10)
- abrowser-3.0-3.5.5+nobinonly-0ubuntu0.9.10.1 (Ubuntu 9.10)
- abrowser-3.0-branding-3.5.5+nobinonly-0ubuntu0.9.10.1 (Ubuntu 9.10)
- abrowser-3.1-3.5.5+nobinonly-0ubuntu0.9.10.1 (Ubuntu 9.10)
- abrowser-3.1-branding-3.5.5+nobinonly-0ubuntu0.9.10.1 (Ubuntu 9.10)
- abrowser-3.5-3.5.5+nobinonly-0ubuntu0.9.10.1 (Ubuntu 9.10)
- abrowser-3.5-branding-3.5.5+nobinonly-0ubuntu0.9.10.1 (Ubuntu 9.10)
- firefox-3.5.5+nobinonly-0ubuntu0.9.10.1 (Ubun
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1563","CVE-2009-3274","CVE-2009-3370","CVE-2009-3371","CVE-2009-3372","CVE-2009-3373","CVE-2009-3374","CVE-2009-3375","CVE-2009-3376","CVE-2009-3377","CVE-2009-3380","CVE-2009-3381","CVE-2009-3382","CVE-2009-3383");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.10", pkgname: "abrowser", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to abrowser-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "abrowser-3.0", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-3.0-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to abrowser-3.0-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "abrowser-3.0-branding", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-3.0-branding-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to abrowser-3.0-branding-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "abrowser-3.1", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-3.1-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to abrowser-3.1-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "abrowser-3.1-branding", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-3.1-branding-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to abrowser-3.1-branding-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "abrowser-3.5", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-3.5-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to abrowser-3.5-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "abrowser-3.5-branding", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-3.5-branding-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to abrowser-3.5-branding-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.0", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.0-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.0-branding", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-branding-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.0-branding-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.0-dev", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.0-dev-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.0-dom-inspector", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-dom-inspector-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.0-dom-inspector-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.0-gnome-support", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-gnome-support-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.0-gnome-support-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.0-venkman", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-venkman-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.0-venkman-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.1", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.1-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.1-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.1-branding", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.1-branding-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.1-branding-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.1-dbg", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.1-dbg-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.1-dbg-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.1-dev", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.1-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.1-dev-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.1-gnome-support", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.1-gnome-support-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.1-gnome-support-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.5", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.5-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.5-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.5-branding", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.5-branding-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.5-branding-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.5-dbg", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.5-dbg-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.5-dbg-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.5-dev", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.5-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.5-dev-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-3.5-gnome-support", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.5-gnome-support-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-3.5-gnome-support-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-dom-inspector", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-dom-inspector-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "firefox-gnome-support", pkgver: "3.5.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to firefox-gnome-support-3.5.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "xulrunner-1.9.1", pkgver: "1.9.1.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9.1-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to xulrunner-1.9.1-1.9.1.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "xulrunner-1.9.1-dbg", pkgver: "1.9.1.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9.1-dbg-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to xulrunner-1.9.1-dbg-1.9.1.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "xulrunner-1.9.1-dev", pkgver: "1.9.1.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9.1-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to xulrunner-1.9.1-dev-1.9.1.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "xulrunner-1.9.1-gnome-support", pkgver: "1.9.1.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9.1-gnome-support-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to xulrunner-1.9.1-gnome-support-1.9.1.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "xulrunner-1.9.1-testsuite", pkgver: "1.9.1.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9.1-testsuite-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to xulrunner-1.9.1-testsuite-1.9.1.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "xulrunner-1.9.1-testsuite-dev", pkgver: "1.9.1.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9.1-testsuite-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to xulrunner-1.9.1-testsuite-dev-1.9.1.5+nobinonly-0ubuntu0.9.10.1
');
}
found = ubuntu_check(osver: "9.10", pkgname: "xulrunner-dev", pkgver: "1.9.1.5+nobinonly-0ubuntu0.9.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-dev-',found,' is vulnerable in Ubuntu 9.10
Upgrade it to xulrunner-dev-1.9.1.5+nobinonly-0ubuntu0.9.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
