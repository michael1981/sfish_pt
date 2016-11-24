# This script was automatically generated from the 690-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36225);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "690-2");
script_summary(english:"firefox vulnerabilities");
script_name(english:"USN690-2 : firefox vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- firefox 
- firefox-dbg 
- firefox-dev 
- firefox-dom-inspector 
- firefox-gnome-support 
- firefox-libthai 
');
script_set_attribute(attribute:'description', value: 'Several flaws were discovered in the browser engine. These problems could allow
an attacker to crash the browser and possibly execute arbitrary code with user
privileges. (CVE-2008-5500)

Boris Zbarsky discovered that the same-origin check in Firefox could be
bypassed by utilizing XBL-bindings. An attacker could exploit this to read data
from other domains. (CVE-2008-5503)

Several problems were discovered in the JavaScript engine. An attacker could
exploit feed preview vulnerabilities to execute scripts from page content with
chrome privileges. (CVE-2008-5504)

Marius Schilder discovered that Firefox did not properly handle redirects to
an outside domain when an XMLHttpRequest was made to a same-origin resource.
It\'s possible that sensitive information could be revealed in the
XMLHttpRequest response. (CVE-2008-5506)

Chris Evans discovered that Firefox did not properly protect a user\'s data when
accessing a same-domain Javascript URL that is redirected to an unparsable
Javascript off-site resource. If a 
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- firefox-2.0.0.19+nobinonly1-0ubuntu0.7.10.1 (Ubuntu 7.10)
- firefox-dbg-2.0.0.19+nobinonly1-0ubuntu0.7.10.1 (Ubuntu 7.10)
- firefox-dev-2.0.0.19+nobinonly1-0ubuntu0.7.10.1 (Ubuntu 7.10)
- firefox-dom-inspector-2.0.0.19+nobinonly1-0ubuntu0.7.10.1 (Ubuntu 7.10)
- firefox-gnome-support-2.0.0.19+nobinonly1-0ubuntu0.7.10.1 (Ubuntu 7.10)
- firefox-libthai-2.0.0.19+nobinonly1-0ubuntu0.7.10.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-5500","CVE-2008-5503","CVE-2008-5504","CVE-2008-5506","CVE-2008-5507","CVE-2008-5508","CVE-2008-5510","CVE-2008-5511","CVE-2008-5512","CVE-2008-5513");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "firefox", pkgver: "2.0.0.19+nobinonly1-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-2.0.0.19+nobinonly1-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dbg", pkgver: "2.0.0.19+nobinonly1-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dbg-2.0.0.19+nobinonly1-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dev", pkgver: "2.0.0.19+nobinonly1-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dev-2.0.0.19+nobinonly1-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-dom-inspector", pkgver: "2.0.0.19+nobinonly1-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-dom-inspector-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-dom-inspector-2.0.0.19+nobinonly1-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-gnome-support", pkgver: "2.0.0.19+nobinonly1-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-gnome-support-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-gnome-support-2.0.0.19+nobinonly1-0ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "firefox-libthai", pkgver: "2.0.0.19+nobinonly1-0ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package firefox-libthai-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to firefox-libthai-2.0.0.19+nobinonly1-0ubuntu0.7.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
