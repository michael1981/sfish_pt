# This script was automatically generated from the 546-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28358);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "546-1");
script_summary(english:"Firefox vulnerabilities");
script_name(english:"USN546-1 : Firefox vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- firefox 
- firefox-dbg 
- firefox-dev 
- firefox-dom-inspector 
- firefox-gnome-support 
- firefox-libthai 
- libnspr-dev 
- libnspr4 
- libnss-dev 
- libnss3 
- mozilla-firefox 
- mozilla-firefox-dev 
- mozilla-firefox-dom-inspector 
- mozilla-firefox-gnome-support 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Firefox incorrectly associated redirected sites
as the origin of "jar:" contents. A malicious web site could exploit this
to modify or steal confidential data (such as passwords) from other web
sites. (CVE-2007-5947)

Various flaws were discovered in the layout and JavaScript engines. By
tricking a user into opening a malicious web page, an attacker could
execute arbitrary code with the user\'s privileges. (CVE-2007-5959)

Gregory Fleischer discovered that it was possible to use JavaScript to
manipulate Firefox\'s Referer header.  A malicious web site could exploit
this to conduct cross-site request forgeries against sites that relied
only on Referer headers for protection from such attacks. (CVE-2007-5960)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- firefox-2.0.0.10+2nobinonly-0ubuntu1.7.10.1 (Ubuntu 7.10)
- firefox-dbg-2.0.0.10+2nobinonly-0ubuntu1.7.10.1 (Ubuntu 7.10)
- firefox-dev-2.0.0.10+2nobinonly-0ubuntu1.7.10.1 (Ubuntu 7.10)
- firefox-dom-inspector-2.0.0.10+2nobinonly-0ubuntu1.7.10.1 (Ubuntu 7.10)
- firefox-gnome-support-2.0.0.10+2nobinonly-0ubuntu1.7.10.1 (Ubuntu 7.10)
- firefox-libthai-2.0.0.10+2nobinonly-0ubuntu1.7.10.1 (Ubuntu 7.10)
- libnspr-dev-1.firefox2.0.0.10+1nobinonly-0ubuntu1 (Ubuntu 7.04)
- libnspr4-1.firefox2.0.0.1
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-5947","CVE-2007-5959","CVE-2007-5960");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "firefox", pkgver: "2.0.0.10+2nobinonly-0ubuntu1.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-2.0.0.10+2nobinonly-0ubuntu1.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dbg", pkgver: "2.0.0.10+2nobinonly-0ubuntu1.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dbg-2.0.0.10+2nobinonly-0ubuntu1.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dev", pkgver: "2.0.0.10+2nobinonly-0ubuntu1.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dev-2.0.0.10+2nobinonly-0ubuntu1.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dom-inspector", pkgver: "2.0.0.10+2nobinonly-0ubuntu1.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dom-inspector-2.0.0.10+2nobinonly-0ubuntu1.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-gnome-support", pkgver: "2.0.0.10+2nobinonly-0ubuntu1.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-gnome-support-2.0.0.10+2nobinonly-0ubuntu1.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-libthai", pkgver: "2.0.0.10+2nobinonly-0ubuntu1.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-libthai-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-libthai-2.0.0.10+2nobinonly-0ubuntu1.7.10.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnspr-dev", pkgver: "1.firefox2.0.0.10+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnspr-dev-1.firefox2.0.0.10+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnspr4", pkgver: "1.firefox2.0.0.10+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr4-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnspr4-1.firefox2.0.0.10+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnss-dev", pkgver: "1.firefox2.0.0.10+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnss-dev-1.firefox2.0.0.10+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnss3", pkgver: "1.firefox2.0.0.10+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnss3-1.firefox2.0.0.10+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox", pkgver: "2.0.0.10+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-2.0.0.10+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox-dev", pkgver: "2.0.0.10+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-dev-2.0.0.10+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox-dom-inspector", pkgver: "2.0.0.10+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-dom-inspector-2.0.0.10+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox-gnome-support", pkgver: "2.0.0.10+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-gnome-support-2.0.0.10+1nobinonly-0ubuntu1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
