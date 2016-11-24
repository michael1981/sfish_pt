# This script was automatically generated from the 428-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28021);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "428-1");
script_summary(english:"Firefox vulnerabilities");
script_name(english:"USN428-1 : Firefox vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- firefox 
- firefox-dbg 
- firefox-dev 
- firefox-dom-inspector 
- firefox-gnome-support 
- libnspr-dev 
- libnspr4 
- libnss-dev 
- libnss3 
- mozilla-firefox 
- mozilla-firefox-dev 
- mozilla-firefox-dom-inspector 
- mozilla-firefox-gnome-support 
');
script_set_attribute(attribute:'description', value: 'Several flaws have been found that could be used to perform Cross-site
scripting attacks. A malicious web site could exploit these to modify
the contents or steal confidential data (such as passwords) from other
opened web pages. (CVE-2006-6077, CVE-2007-0780, CVE-2007-0800,
CVE-2007-0981, CVE-2007-0995, CVE-2007-0996)

The SSLv2 protocol support in the NSS library did not sufficiently
check the validity of public keys presented with a SSL certificate. A
malicious SSL web site using SSLv2 could potentially exploit this to
execute arbitrary code with the user\'s privileges.  (CVE-2007-0008)

The SSLv2 protocol support in the NSS library did not sufficiently
verify the validity of client master keys presented in an SSL client
certificate. A remote attacker could exploit this to execute arbitrary
code in a server application that uses the NSS library.
(CVE-2007-0009)

Various flaws have been reported that could allow an attacker to
execute arbitrary code with user privileges by tricking the user into
opening a 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- firefox-2.0.0.2+0dfsg-0ubuntu0.6.10 (Ubuntu 6.10)
- firefox-dbg-2.0.0.2+0dfsg-0ubuntu0.6.10 (Ubuntu 6.10)
- firefox-dev-2.0.0.2+0dfsg-0ubuntu0.6.10 (Ubuntu 6.10)
- firefox-dom-inspector-2.0.0.2+0dfsg-0ubuntu0.6.10 (Ubuntu 6.10)
- firefox-gnome-support-2.0.0.2+0dfsg-0ubuntu0.6.10 (Ubuntu 6.10)
- libnspr-dev-1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10 (Ubuntu 6.10)
- libnspr4-1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10 (Ubuntu 6.10)
- libnss-dev-1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10 (Ubuntu 6.10)
- libnss3-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-6077","CVE-2007-0008","CVE-2007-0009","CVE-2007-0775","CVE-2007-0776","CVE-2007-0777","CVE-2007-0778","CVE-2007-0779","CVE-2007-0780","CVE-2007-0800","CVE-2007-0981","CVE-2007-0995","CVE-2007-0996","CVE-2007-1092");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "firefox", pkgver: "2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to firefox-2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "firefox-dbg", pkgver: "2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to firefox-dbg-2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "firefox-dev", pkgver: "2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to firefox-dev-2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "firefox-dom-inspector", pkgver: "2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to firefox-dom-inspector-2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "firefox-gnome-support", pkgver: "2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to firefox-gnome-support-2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libnspr-dev", pkgver: "1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libnspr-dev-1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libnspr4", pkgver: "1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr4-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libnspr4-1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libnss-dev", pkgver: "1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libnss-dev-1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libnss3", pkgver: "1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libnss3-1.firefox2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mozilla-firefox", pkgver: "2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-firefox-2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mozilla-firefox-dev", pkgver: "2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-firefox-dev-2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mozilla-firefox-dom-inspector", pkgver: "2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-firefox-dom-inspector-2.0.0.2+0dfsg-0ubuntu0.6.10
');
}
found = ubuntu_check(osver: "6.10", pkgname: "mozilla-firefox-gnome-support", pkgver: "2.0.0.2+0dfsg-0ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to mozilla-firefox-gnome-support-2.0.0.2+0dfsg-0ubuntu0.6.10
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
