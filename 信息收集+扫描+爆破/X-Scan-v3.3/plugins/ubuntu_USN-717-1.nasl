# This script was automatically generated from the 717-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37217);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "717-1");
script_summary(english:"firefox-3.0, xulrunner-1.9 vulnerabilities");
script_name(english:"USN717-1 : firefox-3.0, xulrunner-1.9 vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'Several flaws were discovered in the browser engine. These problems could allow
an attacker to crash the browser and possibly execute arbitrary code with user
privileges. (CVE-2009-0352, CVE-2009-0353)

A flaw was discovered in the JavaScript engine. An attacker could bypass the
same-origin policy in Firefox by utilizing a chrome XBL method and execute
arbitrary JavaScript within the context of another website. (CVE-2009-0354)

A flaw was discovered in the browser engine when restoring closed tabs. If a
user were tricked into restoring a tab to a malicious website with form input
controls, an attacker could steal local files on the user\'s system.
(CVE-2009-0355)

Wladimir Palant discovered that Firefox did not restrict access to cookies in
HTTP response headers. If a user were tricked into opening a malicious web
page, a remote attacker could view sensitive information. (CVE-2009-0357)

Paul Nel discovered that Firefox did not honor certain Cache-Control HTTP
directives. A local attacker could exploit this 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- abrowser-3.0.6+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- abrowser-3.0-branding-3.0.6+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0.6+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0-3.0.6+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0-branding-3.0.6+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0-dev-3.0.6+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0-dom-inspector-3.0.6+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0-gnome-support-3.0.6+nobinonly-0ub
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0352","CVE-2009-0353","CVE-2009-0354","CVE-2009-0355","CVE-2009-0357","CVE-2009-0358");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "abrowser", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to abrowser-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "abrowser-3.0-branding", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-3.0-branding-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to abrowser-3.0-branding-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-branding", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-branding-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-branding-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-dev", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-dev-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-dom-inspector", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-dom-inspector-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-gnome-support", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-gnome-support-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-venkman", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-venkman-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-venkman-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-dev", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-dev-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-dom-inspector", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-dom-inspector-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-gnome-support", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-gnome-support-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso-dev", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-dev-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso-dom-inspector", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-dom-inspector-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso-gnome-support", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-gnome-support-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-libthai", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-libthai-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-libthai-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-dev", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-dev-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-dom-inspector", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-dom-inspector-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-gnome-support", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-gnome-support-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-venkman", pkgver: "3.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-venkman-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-venkman-3.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9", pkgver: "1.9.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-1.9.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-dev", pkgver: "1.9.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-dev-1.9.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-dom-inspector", pkgver: "1.9.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-dom-inspector-1.9.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-gnome-support", pkgver: "1.9.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-gnome-support-1.9.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-venkman", pkgver: "1.9.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-venkman-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-venkman-1.9.0.6+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-dev", pkgver: "1.9.0.6+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-dev-1.9.0.6+nobinonly-0ubuntu0.8.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
