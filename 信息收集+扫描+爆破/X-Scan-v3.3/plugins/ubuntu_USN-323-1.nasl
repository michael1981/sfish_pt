# This script was automatically generated from the 323-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27901);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "323-1");
script_summary(english:"mozilla vulnerabilities");
script_name(english:"USN323-1 : mozilla vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libnspr-dev 
- libnspr4 
- libnss-dev 
- libnss3 
- mozilla 
- mozilla-browser 
- mozilla-calendar 
- mozilla-chatzilla 
- mozilla-dev 
- mozilla-dom-inspector 
- mozilla-js-debugger 
- mozilla-mailnews 
- mozilla-psm 
');
script_set_attribute(attribute:'description', value: 'Jonas Sicking discovered that under some circumstances persisted XUL
attributes are associated with the wrong URL. A malicious web site
could exploit this to execute arbitrary code with the privileges of
the user. (MFSA 2006-35, CVE-2006-2775)

Paul Nickerson discovered that content-defined setters on an object
prototype were getting called by privileged UI code. It was
demonstrated that this could be exploited to run arbitrary web script
with full user privileges (MFSA 2006-37, CVE-2006-2776). A similar
attack was discovered by moz_bug_r_a4 that leveraged SelectionObject
notifications that were called in privileged context. (MFSA 2006-43,
CVE-2006-2777)

Mikolaj Habryn discovered a buffer overflow in the crypto.signText()
function. By tricking a user to visit a site with an SSL certificate
with specially crafted optional Certificate Authority name
arguments, this could potentially be exploited to execute arbitrary
code with the user\'s privileges. (MFSA 2006-38, CVE-2006-2778)

The Mozilla developer team di
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnspr-dev-1.7.13-0ubuntu5.10.1 (Ubuntu 5.10)
- libnspr4-1.7.13-0ubuntu5.10.1 (Ubuntu 5.10)
- libnss-dev-1.7.13-0ubuntu5.10.1 (Ubuntu 5.10)
- libnss3-1.7.13-0ubuntu5.10.1 (Ubuntu 5.10)
- mozilla-1.7.13-0ubuntu5.10.1 (Ubuntu 5.10)
- mozilla-browser-1.7.13-0ubuntu5.10.1 (Ubuntu 5.10)
- mozilla-calendar-1.7.13-0ubuntu5.10.1 (Ubuntu 5.10)
- mozilla-chatzilla-1.7.13-0ubuntu5.10.1 (Ubuntu 5.10)
- mozilla-dev-1.7.13-0ubuntu5.10.1 (Ubuntu 5.10)
- mozilla-dom-inspector-1.7.13-0ubuntu5.10.1 (Ubuntu 
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2005-0752","CVE-2006-1729","CVE-2006-2775","CVE-2006-2776","CVE-2006-2777","CVE-2006-2778","CVE-2006-2779","CVE-2006-2780","CVE-2006-2781","CVE-2006-2782","CVE-2006-2783","CVE-2006-2784","CVE-2006-2785","CVE-2006-2786","CVE-2006-2787");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libnspr-dev", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnspr-dev-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnspr4", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnspr4-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnss-dev", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnss-dev-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnss3", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnss3-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-browser", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-browser-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-browser-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-calendar", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-calendar-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-calendar-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-chatzilla", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-chatzilla-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-chatzilla-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-dev", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-dev-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-dom-inspector", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-dom-inspector-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-dom-inspector-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-js-debugger", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-js-debugger-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-js-debugger-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-mailnews", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-mailnews-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-mailnews-1.7.13-0ubuntu5.10.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-psm", pkgver: "1.7.13-0ubuntu5.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-psm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-psm-1.7.13-0ubuntu5.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
