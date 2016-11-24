# This script was automatically generated from the 149-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20546);
script_version("$Revision: 1.6 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "149-3");
script_summary(english:"mozilla-firefox vulnerabilities");
script_name(english:"USN149-3 : mozilla-firefox vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-firefox 
- mozilla-firefox-dom-inspector 
- mozilla-firefox-locale-ca 
- mozilla-firefox-locale-de 
- mozilla-firefox-locale-es 
- mozilla-firefox-locale-fr 
- mozilla-firefox-locale-it 
- mozilla-firefox-locale-ja 
- mozilla-firefox-locale-nb 
- mozilla-firefox-locale-pl 
- mozilla-firefox-locale-tr 
- mozilla-firefox-locale-uk 
');
script_set_attribute(attribute:'description', value: 'USN-149-1 fixed some vulnerabilities in the Ubuntu 5.04 (Hoary
Hedgehog) version of Firefox. The version shipped with Ubuntu 4.10
(Warty Warthog) is also vulnerable to these flaws, so it needs to be
upgraded as well. Please see

  http://www.ubuntulinux.org/support/documentation/usn/usn-149-1

for the original advisory.

This update also fixes several older vulnerabilities; Some of them
could be exploited to execute arbitrary code with full user privileges
if the user visited a malicious web site. (MFSA-2005-01 to
MFSA-2005-44; please see the following web site for details:
http://www.mozilla.org/projects/security/known-vulnerabilities.html)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-firefox-1.0.6-0ubuntu0.0.1 (Ubuntu 4.10)
- mozilla-firefox-dom-inspector-1.0.6-0ubuntu0.0.1 (Ubuntu 4.10)
- mozilla-firefox-locale-ca-1.0-0ubuntu0.1 (Ubuntu 4.10)
- mozilla-firefox-locale-de-1.0-0ubuntu0.1 (Ubuntu 4.10)
- mozilla-firefox-locale-es-1.0-0ubuntu0.1 (Ubuntu 4.10)
- mozilla-firefox-locale-fr-1.0-0ubuntu0.2 (Ubuntu 4.10)
- mozilla-firefox-locale-it-1.0-0ubuntu0.1 (Ubuntu 4.10)
- mozilla-firefox-locale-ja-1.0-0ubuntu0.1 (Ubuntu 4.10)
- mozilla-firefox-locale-nb-1.0-0ubuntu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2004-1156","CVE-2004-1381","CVE-2005-0141","CVE-2005-0142","CVE-2005-0143","CVE-2005-0144","CVE-2005-0145","CVE-2005-0146","CVE-2005-0147","CVE-2005-0150","CVE-2005-0230","CVE-2005-0231","CVE-2005-0232","CVE-2005-0233","CVE-2005-0255","CVE-2005-0399","CVE-2005-0401","CVE-2005-0402","CVE-2005-0578","CVE-2005-0584","CVE-2005-0585","CVE-2005-0586","CVE-2005-0587","CVE-2005-0588","CVE-2005-0589","CVE-2005-0590","CVE-2005-0591","CVE-2005-0592","CVE-2005-0593","CVE-2005-0752","CVE-2005-0989","CVE-2005-1153","CVE-2005-1154","CVE-2005-1155","CVE-2005-1156","CVE-2005-1157","CVE-2005-1158","CVE-2005-1159","CVE-2005-1160","CVE-2005-1531","CVE-2005-1532","CVE-2005-1937","CVE-2005-2260","CVE-2005-2261","CVE-2005-2262","CVE-2005-2263","CVE-2005-2264","CVE-2005-2265","CVE-2005-2266","CVE-2005-2267","CVE-2005-2268","CVE-2005-2269","CVE-2005-2270");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox", pkgver: "1.0.6-0ubuntu0.0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-1.0.6-0ubuntu0.0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-dom-inspector", pkgver: "1.0.6-0ubuntu0.0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-dom-inspector-1.0.6-0ubuntu0.0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-locale-ca", pkgver: "1.0-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-locale-ca-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-locale-ca-1.0-0ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-locale-de", pkgver: "1.0-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-locale-de-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-locale-de-1.0-0ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-locale-es", pkgver: "1.0-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-locale-es-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-locale-es-1.0-0ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-locale-fr", pkgver: "1.0-0ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-locale-fr-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-locale-fr-1.0-0ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-locale-it", pkgver: "1.0-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-locale-it-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-locale-it-1.0-0ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-locale-ja", pkgver: "1.0-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-locale-ja-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-locale-ja-1.0-0ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-locale-nb", pkgver: "1.0-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-locale-nb-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-locale-nb-1.0-0ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-locale-pl", pkgver: "1.0-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-locale-pl-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-locale-pl-1.0-0ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-locale-tr", pkgver: "1.0-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-locale-tr-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-locale-tr-1.0-0ubuntu0.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "mozilla-firefox-locale-uk", pkgver: "1.0-0ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-locale-uk-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to mozilla-firefox-locale-uk-1.0-0ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
