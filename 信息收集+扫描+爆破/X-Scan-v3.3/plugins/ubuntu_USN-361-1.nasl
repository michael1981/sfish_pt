# This script was automatically generated from the 361-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27941);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "361-1");
script_summary(english:"Mozilla vulnerabilities");
script_name(english:"USN361-1 : Mozilla vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'Various flaws have been reported that allow an attacker to execute
arbitrary code with user privileges by tricking the user into opening
a malicious URL. (CVE-2006-2788, CVE-2006-3805, CVE-2006-3806,
CVE-2006-3807, CVE-2006-3809, CVE-2006-3811, CVE-2006-4565,
CVE-2006-4568, CVE-2006-4571)

A bug was found in the script handler for automatic proxy
configuration. A malicious proxy could send scripts which could
execute arbitrary code with the user\'s privileges. (CVE-2006-3808)

The NSS library did not sufficiently check the padding of PKCS #1 v1.5
signatures if the exponent of the public key is 3 (which is widely
used for CAs). This could be exploited to forge valid signatures
without the need of the secret key. (CVE-2006-4340)

Georgi Guninski discovered that even with JavaScript disabled, a
malicous email could still execute JavaScript when the message is
viewed, replied to, or forwarded by putting the script in a remote XBL
file loaded by the message. (CVE-2006-4570)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnspr-dev-1.7.13-0ubuntu5.10.2 (Ubuntu 5.10)
- libnspr4-1.7.13-0ubuntu5.10.2 (Ubuntu 5.10)
- libnss-dev-1.7.13-0ubuntu5.10.2 (Ubuntu 5.10)
- libnss3-1.7.13-0ubuntu5.10.2 (Ubuntu 5.10)
- mozilla-1.7.13-0ubuntu5.10.2 (Ubuntu 5.10)
- mozilla-browser-1.7.13-0ubuntu5.10.2 (Ubuntu 5.10)
- mozilla-calendar-1.7.13-0ubuntu5.10.2 (Ubuntu 5.10)
- mozilla-chatzilla-1.7.13-0ubuntu5.10.2 (Ubuntu 5.10)
- mozilla-dev-1.7.13-0ubuntu5.10.2 (Ubuntu 5.10)
- mozilla-dom-inspector-1.7.13-0ubuntu5.10.2 (Ubuntu 
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2788","CVE-2006-3805","CVE-2006-3806","CVE-2006-3807","CVE-2006-3808","CVE-2006-3809","CVE-2006-3811","CVE-2006-4340","CVE-2006-4565","CVE-2006-4568","CVE-2006-4570","CVE-2006-4571");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libnspr-dev", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnspr-dev-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnspr4", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnspr4-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnspr4-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnss-dev", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnss-dev-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnss3", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnss3-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnss3-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-browser", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-browser-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-browser-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-calendar", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-calendar-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-calendar-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-chatzilla", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-chatzilla-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-chatzilla-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-dev", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-dev-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-dom-inspector", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-dom-inspector-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-dom-inspector-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-js-debugger", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-js-debugger-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-js-debugger-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-mailnews", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-mailnews-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-mailnews-1.7.13-0ubuntu5.10.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-psm", pkgver: "1.7.13-0ubuntu5.10.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-psm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-psm-1.7.13-0ubuntu5.10.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
