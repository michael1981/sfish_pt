# This script was automatically generated from the 645-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36243);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "645-1");
script_summary(english:"Firefox and xulrunner vulnerabilities");
script_name(english:"USN645-1 : Firefox and xulrunner vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- firefox 
- firefox-3.0 
- firefox-3.0-dev 
- firefox-3.0-dom-inspector 
- firefox-3.0-gnome-support 
- firefox-3.0-venkman 
- firefox-dbg 
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
- firefox-trunk-dom-inspector 
- firefox-trunk-gnome-support 
- fir
[...]');
script_set_attribute(attribute:'description', value: 'Justin Schuh, Tom Cross and Peter Williams discovered errors in the
Firefox URL parsing routines. If a user were tricked into opening a
crafted hyperlink, an attacker could overflow a stack buffer and
execute arbitrary code. (CVE-2008-0016)

It was discovered that the same-origin check in Firefox could be
bypassed. If a user were tricked into opening a malicious website,
an attacker may be able to execute JavaScript in the context of a
different website. (CVE-2008-3835)

Several problems were discovered in the JavaScript engine. This
could allow an attacker to execute scripts from page content with
chrome privileges. (CVE-2008-3836)

Paul Nickerson discovered Firefox did not properly process mouse
click events. If a user were tricked into opening a malicious web
page, an attacker could move the content window, which could
potentially be used to force a user to perform unintended drag and
drop operations. (CVE-2008-3837)

Several problems were discovered in the browser engine. This could
allow an attacker to 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- firefox-3.0.2+build6+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- firefox-3.0-3.0.2+build6+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- firefox-3.0-dev-3.0.2+build6+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- firefox-3.0-dom-inspector-3.0.2+build6+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- firefox-3.0-gnome-support-3.0.2+build6+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- firefox-3.0-venkman-3.0.2+build6+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- firefox-dbg-2.0.0.17+1nobinonly-0ubuntu0.7.10 (Ubuntu 7.1
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-0016","CVE-2008-3835","CVE-2008-3836","CVE-2008-3837","CVE-2008-4058","CVE-2008-4059","CVE-2008-4060","CVE-2008-4061","CVE-2008-4062","CVE-2008-4063","CVE-2008-4064","CVE-2008-4065","CVE-2008-4066","CVE-2008-4067","CVE-2008-4068","CVE-2008-4069");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "firefox", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-3.0", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-3.0-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-3.0-dev", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-3.0-dev-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-3.0-dom-inspector", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-dom-inspector-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-3.0-dom-inspector-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-3.0-gnome-support", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-gnome-support-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-3.0-gnome-support-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-3.0-venkman", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-venkman-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-3.0-venkman-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dbg", pkgver: "2.0.0.17+1nobinonly-0ubuntu0.7.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dbg-2.0.0.17+1nobinonly-0ubuntu0.7.10
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-dev", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-dev-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-dom-inspector", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-dom-inspector-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-gnome-support", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-gnome-support-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-granparadiso", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-granparadiso-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-granparadiso-dev", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-granparadiso-dev-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-granparadiso-dom-inspector", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-dom-inspector-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-granparadiso-dom-inspector-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-granparadiso-gnome-support", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-gnome-support-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-granparadiso-gnome-support-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-libthai", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-libthai-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-libthai-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-trunk", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-trunk-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-trunk-dev", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-trunk-dev-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-trunk-dom-inspector", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-dom-inspector-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-trunk-dom-inspector-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-trunk-gnome-support", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-gnome-support-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-trunk-gnome-support-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-trunk-venkman", pkgver: "3.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-venkman-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-trunk-venkman-3.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnspr-dev", pkgver: "1.firefox2.0.0.17+0nobinonly-0ubuntu0.7.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnspr-dev-1.firefox2.0.0.17+0nobinonly-0ubuntu0.7.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnspr4", pkgver: "1.firefox2.0.0.17+0nobinonly-0ubuntu0.7.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr4-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnspr4-1.firefox2.0.0.17+0nobinonly-0ubuntu0.7.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnss-dev", pkgver: "1.firefox2.0.0.17+0nobinonly-0ubuntu0.7.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnss-dev-1.firefox2.0.0.17+0nobinonly-0ubuntu0.7.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnss3", pkgver: "1.firefox2.0.0.17+0nobinonly-0ubuntu0.7.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnss3-1.firefox2.0.0.17+0nobinonly-0ubuntu0.7.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox", pkgver: "2.0.0.17+0nobinonly-0ubuntu0.7.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-2.0.0.17+0nobinonly-0ubuntu0.7.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox-dev", pkgver: "2.0.0.17+0nobinonly-0ubuntu0.7.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-dev-2.0.0.17+0nobinonly-0ubuntu0.7.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox-dom-inspector", pkgver: "2.0.0.17+0nobinonly-0ubuntu0.7.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-dom-inspector-2.0.0.17+0nobinonly-0ubuntu0.7.4
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox-gnome-support", pkgver: "2.0.0.17+0nobinonly-0ubuntu0.7.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-gnome-support-2.0.0.17+0nobinonly-0ubuntu0.7.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "xulrunner-1.9", pkgver: "1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to xulrunner-1.9-1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "xulrunner-1.9-dev", pkgver: "1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to xulrunner-1.9-dev-1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "xulrunner-1.9-dom-inspector", pkgver: "1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-dom-inspector-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to xulrunner-1.9-dom-inspector-1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "xulrunner-1.9-gnome-support", pkgver: "1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-gnome-support-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to xulrunner-1.9-gnome-support-1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "xulrunner-1.9-venkman", pkgver: "1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-venkman-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to xulrunner-1.9-venkman-1.9.0.2+build6+nobinonly-0ubuntu0.8.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
