# This script was automatically generated from the 728-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38036);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "728-1");
script_summary(english:"firefox-3.0, xulrunner-1.9 vulnerabilities");
script_name(english:"USN728-1 : firefox-3.0, xulrunner-1.9 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- abrowser 
- abrowser-3.0-branding 
- firefox 
- firefox-3.0 
- firefox-3.0-branding 
- firefox-3.0-dev 
- firefox-3.0-dom-inspector 
- firefox-3.0-gnome-support 
- firefox-3.0-venkman 
- firefox-dev 
- firefox-dom-inspector 
- firefox-gnome-support 
- firefox-granparadiso 
- firefox-granparadiso-dev 
- firefox-granparadiso-dom-inspector 
- firefox-granparadiso-gnome-support 
- firefox-libthai 
- firefox-trunk 
- firefox-trunk-dev 
- firefox-trunk-dom-i
[...]');
script_set_attribute(attribute:'description', value: 'Glenn Randers-Pehrson discovered that the embedded libpng in Firefox
did not properly initialize pointers. If a user were tricked into
viewing a malicious website with a crafted PNG file, a remote attacker
could cause a denial of service or possibly execute arbitrary code
with the privileges of the user invoking the program. (CVE-2009-0040)

Martijn Wargers, Jesse Ruderman, Josh Soref, Gary Kwong, and Timothee
Groleau discovered flaws in the browser engine. If a user were tricked
into viewing a malicious website, a remote attacker could cause a
denial of service or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-0771,
CVE-2009-0772, CVE-2009-0773, CVE-2009-0774)

A flaw was discovered in Firefox\'s garbage collection process. Under
certain circumstances a remote attacker could exploit this to cause a
denial of service or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-0775)

Georgi Guninski discovered a flaw when 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- abrowser-3.0.7+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- abrowser-3.0-branding-3.0.7+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0.7+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0-3.0.7+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0-branding-3.0.7+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0-dev-3.0.7+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0-dom-inspector-3.0.7+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0-gnome-support-3.0.7+nobinonly-0ub
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0040","CVE-2009-0771","CVE-2009-0772","CVE-2009-0773","CVE-2009-0774","CVE-2009-0775","CVE-2009-0776","CVE-2009-0777");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "abrowser", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to abrowser-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "abrowser-3.0-branding", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-3.0-branding-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to abrowser-3.0-branding-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-branding", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-branding-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-branding-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-dev", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-dev-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-dom-inspector", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-dom-inspector-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-gnome-support", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-gnome-support-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-venkman", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-venkman-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-venkman-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-dev", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-dev-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-dom-inspector", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-dom-inspector-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-gnome-support", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-gnome-support-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso-dev", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-dev-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso-dom-inspector", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-dom-inspector-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso-gnome-support", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-gnome-support-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-libthai", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-libthai-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-libthai-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-dev", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-dev-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-dom-inspector", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-dom-inspector-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-gnome-support", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-gnome-support-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-venkman", pkgver: "3.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-venkman-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-venkman-3.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9", pkgver: "1.9.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-1.9.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-dev", pkgver: "1.9.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-dev-1.9.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-dom-inspector", pkgver: "1.9.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-dom-inspector-1.9.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-gnome-support", pkgver: "1.9.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-gnome-support-1.9.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-venkman", pkgver: "1.9.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-venkman-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-venkman-1.9.0.7+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-dev", pkgver: "1.9.0.7+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-dev-1.9.0.7+nobinonly-0ubuntu0.8.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
