# This script was automatically generated from the 351-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27931);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "351-1");
script_summary(english:"firefox vulnerabilities");
script_name(english:"USN351-1 : firefox vulnerabilities");
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
');
script_set_attribute(attribute:'description', value: 'Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious web page containing JavaScript. (CVE-2006-4253,
CVE-2006-4565, CVE-2006-4566, CVE-2006-4568, CVE-2006-4569
CVE-2006-4571)

The NSS library did not sufficiently check the padding of PKCS #1 v1.5
signatures if the exponent of the public key is 3 (which is widely
used for CAs). This could be exploited to forge valid signatures
without the need of the secret key. (CVE-2006-4340)

Jon Oberheide reported a way how a remote attacker could trick users
into downloading arbitrary extensions with circumventing the normal
SSL certificate check. The attacker would have to be in a position to
spoof the victim\'s DNS, causing them to connect to sites of the
attacker\'s choosing rather than the sites intended by the victim. If
they gained that control and the victim accepted the attacker\'s cert
for the Mozilla update site, then the next update check could be
hijacked and redir
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- firefox-1.5.dfsg+1.5.0.7-ubuntu0.6.06 (Ubuntu 6.06)
- firefox-dbg-1.5.dfsg+1.5.0.7-ubuntu0.6.06 (Ubuntu 6.06)
- firefox-dev-1.5.dfsg+1.5.0.7-ubuntu0.6.06 (Ubuntu 6.06)
- firefox-dom-inspector-1.5.dfsg+1.5.0.7-ubuntu0.6.06 (Ubuntu 6.06)
- firefox-gnome-support-1.5.dfsg+1.5.0.7-ubuntu0.6.06 (Ubuntu 6.06)
- libnspr-dev-1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06 (Ubuntu 6.06)
- libnspr4-1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06 (Ubuntu 6.06)
- libnss-dev-1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06 (Ubuntu 
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-4253","CVE-2006-4340","CVE-2006-4565","CVE-2006-4566","CVE-2006-4567","CVE-2006-4568","CVE-2006-4569","CVE-2006-4571");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "firefox", pkgver: "1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-dbg", pkgver: "1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-dbg-1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-dev", pkgver: "1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-dev-1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-dom-inspector", pkgver: "1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-dom-inspector-1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-gnome-support", pkgver: "1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-gnome-support-1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnspr-dev", pkgver: "1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnspr-dev-1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnspr4", pkgver: "1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnspr4-1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnss-dev", pkgver: "1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnss-dev-1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnss3", pkgver: "1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnss3-1.firefox1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-firefox", pkgver: "1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-firefox-1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-firefox-dev", pkgver: "1.5.dfsg+1.5.0.7-ubuntu0.6.06");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-firefox-dev-1.5.dfsg+1.5.0.7-ubuntu0.6.06
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
