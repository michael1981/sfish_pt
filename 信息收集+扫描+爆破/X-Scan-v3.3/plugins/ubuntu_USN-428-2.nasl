# This script was automatically generated from the 428-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28022);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "428-2");
script_summary(english:"Firefox regression");
script_name(english:"USN428-2 : Firefox regression");
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
script_set_attribute(attribute:'description', value: 'USN-428-1 fixed vulnerabilities in Firefox 1.5.  However, changes to 
library paths caused applications depending on libnss3 to fail to start 
up.  This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Several flaws have been found that could be used to perform Cross-site
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
 certificate. A remote attacker
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- firefox-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2 (Ubuntu 6.06)
- firefox-dbg-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2 (Ubuntu 6.06)
- firefox-dev-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2 (Ubuntu 6.06)
- firefox-dom-inspector-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2 (Ubuntu 6.06)
- firefox-gnome-support-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2 (Ubuntu 6.06)
- libnspr-dev-1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2 (Ubuntu 6.06)
- libnspr4-1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2 (Ubuntu 6.06)
- libnss-dev-1.firefox1.5.dfsg+1
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-6077","CVE-2007-0008","CVE-2007-0009","CVE-2007-0775","CVE-2007-0776","CVE-2007-0777","CVE-2007-0778","CVE-2007-0779","CVE-2007-0780","CVE-2007-0800","CVE-2007-0981","CVE-2007-0995","CVE-2007-0996","CVE-2007-1092");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "firefox", pkgver: "1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-dbg", pkgver: "1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-dbg-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-dev", pkgver: "1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-dev-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-dom-inspector", pkgver: "1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-dom-inspector-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "firefox-gnome-support", pkgver: "1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to firefox-gnome-support-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnspr-dev", pkgver: "1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnspr-dev-1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnspr4", pkgver: "1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnspr4-1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnss-dev", pkgver: "1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnss-dev-1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libnss3", pkgver: "1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libnss3-1.firefox1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-firefox", pkgver: "1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-firefox-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "mozilla-firefox-dev", pkgver: "1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to mozilla-firefox-dev-1.5.dfsg+1.5.0.10-0ubuntu0.6.06.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
