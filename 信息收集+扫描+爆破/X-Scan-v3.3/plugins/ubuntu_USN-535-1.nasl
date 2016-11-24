# This script was automatically generated from the 535-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28141);
script_version("$Revision: 1.9 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "535-1");
 script_cve_id("CVE-2007-5339");
script_summary(english:"Firefox vulnerabilities");
script_name(english:"USN535-1 : Firefox vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'Various flaws were discovered in the layout and JavaScript engines.
By tricking a user into opening a malicious web page, an attacker could
execute arbitrary code with the user\'s privileges. (CVE-2007-5336,
CVE-2007-5339, CVE-2007-5340)

Michal Zalewski discovered that the onUnload event handlers were
incorrectly able to access information outside the old page content.
A malicious web site could exploit this to modify the contents, or steal
confidential data (such as passwords), of the next loaded web page.
(CVE-2007-1095)

Stefano Di Paola discovered that Firefox did not correctly request
Digest Authentications.  A malicious web site could exploit this to
inject arbitrary HTTP headers or perform session splitting attacks
against proxies. (CVE-2007-2292)

Flaws were discovered in the file upload form control.  By tricking
a user into opening a malicious web page, an attacker could force
arbitrary files from the user\'s computer to be uploaded without their
consent. (CVE-2006-2894, CVE-2007-3511)

Eli Friedm
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- firefox-2.0.0.8+2nobinonly-0ubuntu1 (Ubuntu 7.10)
- firefox-dbg-2.0.0.8+2nobinonly-0ubuntu1 (Ubuntu 7.10)
- firefox-dev-2.0.0.8+2nobinonly-0ubuntu1 (Ubuntu 7.10)
- firefox-dom-inspector-2.0.0.8+2nobinonly-0ubuntu1 (Ubuntu 7.10)
- firefox-gnome-support-2.0.0.8+2nobinonly-0ubuntu1 (Ubuntu 7.10)
- firefox-libthai-2.0.0.8+2nobinonly-0ubuntu1 (Ubuntu 7.10)
- libnspr-dev-1.firefox2.0.0.8+1nobinonly-0ubuntu1 (Ubuntu 7.04)
- libnspr4-1.firefox2.0.0.8+1nobinonly-0ubuntu1 (Ubuntu 7.04)
- libnss-dev-1
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "firefox", pkgver: "2.0.0.8+2nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-2.0.0.8+2nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dbg", pkgver: "2.0.0.8+2nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dbg-2.0.0.8+2nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dev", pkgver: "2.0.0.8+2nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dev-2.0.0.8+2nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dom-inspector", pkgver: "2.0.0.8+2nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dom-inspector-2.0.0.8+2nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-gnome-support", pkgver: "2.0.0.8+2nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-gnome-support-2.0.0.8+2nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-libthai", pkgver: "2.0.0.8+2nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-libthai-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-libthai-2.0.0.8+2nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnspr-dev", pkgver: "1.firefox2.0.0.8+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnspr-dev-1.firefox2.0.0.8+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnspr4", pkgver: "1.firefox2.0.0.8+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr4-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnspr4-1.firefox2.0.0.8+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnss-dev", pkgver: "1.firefox2.0.0.8+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnss-dev-1.firefox2.0.0.8+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libnss3", pkgver: "1.firefox2.0.0.8+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libnss3-1.firefox2.0.0.8+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox", pkgver: "2.0.0.8+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-2.0.0.8+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox-dev", pkgver: "2.0.0.8+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-dev-2.0.0.8+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox-dom-inspector", pkgver: "2.0.0.8+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-dom-inspector-2.0.0.8+1nobinonly-0ubuntu1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "mozilla-firefox-gnome-support", pkgver: "2.0.0.8+1nobinonly-0ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to mozilla-firefox-gnome-support-2.0.0.8+1nobinonly-0ubuntu1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
