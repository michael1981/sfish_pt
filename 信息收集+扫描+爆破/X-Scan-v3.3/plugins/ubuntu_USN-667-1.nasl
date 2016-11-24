# This script was automatically generated from the 667-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36711);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "667-1");
script_summary(english:"firefox, firefox-3.0, xulrunner-1.9 vulnerabilities");
script_name(english:"USN667-1 : firefox, firefox-3.0, xulrunner-1.9 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- abrowser 
- abrowser-3.0-branding 
- firefox 
- firefox-2 
- firefox-2-dbg 
- firefox-2-dev 
- firefox-2-dom-inspector 
- firefox-2-gnome-support 
- firefox-2-libthai 
- firefox-3.0 
- firefox-3.0-branding 
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
- firefox-granpar
[...]');
script_set_attribute(attribute:'description', value: 'Liu Die Yu discovered an information disclosure vulnerability in Firefox
when using saved .url shortcut files. If a user were tricked into
downloading a crafted .url file and a crafted HTML file, an attacker
could steal information from the user\'s cache. (CVE-2008-4582)

Georgi Guninski, Michal Zalewsk and Chris Evans discovered that the
same-origin check in Firefox could be bypassed. If a user were tricked
into opening a malicious website, an attacker could obtain private
information from data stored in the images, or discover information
about software on the user\'s computer. This issue only affects Firefox 2.
(CVE-2008-5012)

It was discovered that Firefox did not properly check if the Flash
module was properly unloaded. By tricking a user into opening a crafted
SWF file, an attacker could cause Firefox to crash and possibly execute
arbitrary code with user privileges. This issue only affects Firefox 2.
(CVE-2008-5013)

Jesse Ruderman discovered that Firefox did not properly guard locks on
non-native ob
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- abrowser-3.0.4+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- abrowser-3.0-branding-3.0.4+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-3.0.4+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- firefox-2-2.0.0.18+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- firefox-2-dbg-2.0.0.18+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- firefox-2-dev-2.0.0.18+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- firefox-2-dom-inspector-2.0.0.18+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- firefox-2-gnome-support-2.0.0.18+nobinonly-0ub
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-0017","CVE-2008-4582","CVE-2008-5012","CVE-2008-5013","CVE-2008-5014","CVE-2008-5015","CVE-2008-5016","CVE-2008-5017","CVE-2008-5018","CVE-2008-5019","CVE-2008-5021","CVE-2008-5022","CVE-2008-5023","CVE-2008-5024");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "abrowser", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to abrowser-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "abrowser-3.0-branding", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abrowser-3.0-branding-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to abrowser-3.0-branding-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-2", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-2-2.0.0.18+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-2-dbg", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-2-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-2-dbg-2.0.0.18+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-2-dev", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-2-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-2-dev-2.0.0.18+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-2-dom-inspector", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-2-dom-inspector-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-2-dom-inspector-2.0.0.18+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-2-gnome-support", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-2-gnome-support-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-2-gnome-support-2.0.0.18+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "firefox-2-libthai", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-2-libthai-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to firefox-2-libthai-2.0.0.18+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-branding", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-branding-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-branding-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-dev", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-dev-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-dom-inspector", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-dom-inspector-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-gnome-support", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-gnome-support-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-3.0-venkman", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-3.0-venkman-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-3.0-venkman-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dbg", pkgver: "2.0.0.18+nobinonly-0ubuntu0.7.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dbg-2.0.0.18+nobinonly-0ubuntu0.7.10
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-dev", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-dev-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-dom-inspector", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-dom-inspector-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-gnome-support", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-gnome-support-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso-dev", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-dev-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso-dom-inspector", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-dom-inspector-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-granparadiso-gnome-support", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-granparadiso-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-granparadiso-gnome-support-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-libthai", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-libthai-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-libthai-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-dev", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-dev-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-dom-inspector", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-dom-inspector-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-gnome-support", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-gnome-support-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "firefox-trunk-venkman", pkgver: "3.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-trunk-venkman-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to firefox-trunk-venkman-3.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9", pkgver: "1.9.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-1.9.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-dev", pkgver: "1.9.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-dev-1.9.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-dom-inspector", pkgver: "1.9.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-dom-inspector-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-dom-inspector-1.9.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-gnome-support", pkgver: "1.9.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-gnome-support-1.9.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-1.9-venkman", pkgver: "1.9.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-1.9-venkman-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-1.9-venkman-1.9.0.4+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "xulrunner-dev", pkgver: "1.9.0.4+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xulrunner-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xulrunner-dev-1.9.0.4+nobinonly-0ubuntu0.8.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
