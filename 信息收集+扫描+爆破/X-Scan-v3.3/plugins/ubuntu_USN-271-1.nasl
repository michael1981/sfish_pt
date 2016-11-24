# This script was automatically generated from the 271-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21270);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "271-1");
script_summary(english:"mozilla-firefox, firefox vulnerabilities");
script_name(english:"USN271-1 : mozilla-firefox, firefox vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- firefox 
- firefox-dev 
- firefox-dom-inspector 
- firefox-gnome-support 
- mozilla-firefox 
- mozilla-firefox-dev 
- mozilla-firefox-dom-inspector 
- mozilla-firefox-gnome-support 
');
script_set_attribute(attribute:'description', value: 'Web pages with extremely long titles caused subsequent launches of
Firefox browser to hang for up to a few minutes, or caused Firefox to
crash on computers with	insufficient memory. (CVE-2005-4134)

Igor Bukanov discovered that the JavaScript engine did not properly
declare some temporary variables. Under some rare circumstances, a
malicious website could exploit this to execute arbitrary code with
the privileges of the user. (CVE-2006-0292, CVE-2006-1742)

The function XULDocument.persist() did not sufficiently validate the
names of attributes. An attacker could exploit this to inject
arbitrary XML code into the file \'localstore.rdf\', which is read and
evaluated at startup. This could include JavaScript commands that
would be run with the user\'s privileges. (CVE-2006-0296)

Due to a flaw in the HTML tag parser a specific sequence of HTML tags
caused memory corruption. A malicious web site could exploit this to
crash the browser or even execute arbitrary code with the user\'s
privileges. (CVE-2006-0749)


[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- firefox-1.0.8-0ubuntu5.10 (Ubuntu 5.10)
- firefox-dev-1.0.8-0ubuntu5.10 (Ubuntu 5.10)
- firefox-dom-inspector-1.0.8-0ubuntu5.10 (Ubuntu 5.10)
- firefox-gnome-support-1.0.8-0ubuntu5.10 (Ubuntu 5.10)
- mozilla-firefox-1.0.8-0ubuntu5.10 (Ubuntu 5.10)
- mozilla-firefox-dev-1.0.8-0ubuntu5.10 (Ubuntu 5.10)
- mozilla-firefox-dom-inspector-1.0.8-0ubuntu5.04 (Ubuntu 5.04)
- mozilla-firefox-gnome-support-1.0.8-0ubuntu5.04 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2005-4134","CVE-2006-0292","CVE-2006-0296","CVE-2006-0749","CVE-2006-1727","CVE-2006-1728","CVE-2006-1729","CVE-2006-1730","CVE-2006-1731","CVE-2006-1732","CVE-2006-1733","CVE-2006-1734","CVE-2006-1735","CVE-2006-1736","CVE-2006-1737","CVE-2006-1738","CVE-2006-1739","CVE-2006-1740","CVE-2006-1741","CVE-2006-1742","CVE-2006-1790");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "firefox", pkgver: "1.0.8-0ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to firefox-1.0.8-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "firefox-dev", pkgver: "1.0.8-0ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to firefox-dev-1.0.8-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "firefox-dom-inspector", pkgver: "1.0.8-0ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to firefox-dom-inspector-1.0.8-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "firefox-gnome-support", pkgver: "1.0.8-0ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to firefox-gnome-support-1.0.8-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-firefox", pkgver: "1.0.8-0ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-firefox-1.0.8-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.10", pkgname: "mozilla-firefox-dev", pkgver: "1.0.8-0ubuntu5.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to mozilla-firefox-dev-1.0.8-0ubuntu5.10
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-dom-inspector", pkgver: "1.0.8-0ubuntu5.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-dom-inspector-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-dom-inspector-1.0.8-0ubuntu5.04
');
}
found = ubuntu_check(osver: "5.04", pkgname: "mozilla-firefox-gnome-support", pkgver: "1.0.8-0ubuntu5.04");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-firefox-gnome-support-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to mozilla-firefox-gnome-support-1.0.8-0ubuntu5.04
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
