# This script was automatically generated from the 701-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37974);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "701-1");
script_summary(english:"thunderbird vulnerabilities");
script_name(english:"USN701-1 : thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- thunderbird 
- thunderbird-dev 
- thunderbird-gnome-support 
');
script_set_attribute(attribute:'description', value: 'Several flaws were discovered in the browser engine. If a user had Javascript
enabled, these problems could allow an attacker to crash Thunderbird and
possibly execute arbitrary code with user privileges. (CVE-2008-5500)

Boris Zbarsky discovered that the same-origin check in Thunderbird could be
bypassed by utilizing XBL-bindings. If a user had Javascript enabled, an
attacker could exploit this to read data from other domains. (CVE-2008-5503)

Marius Schilder discovered that Thunderbird did not properly handle redirects
to an outside domain when an XMLHttpRequest was made to a same-origin resource.
When Javascript is enabled, it\'s possible that sensitive information could be
revealed in the XMLHttpRequest response. (CVE-2008-5506)

Chris Evans discovered that Thunderbird did not properly protect a user\'s data
when accessing a same-domain Javascript URL that is redirected to an unparsable
Javascript off-site resource. If a user were tricked into opening a malicious
website and had Javascript enabled, an at
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-2.0.0.19+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- mozilla-thunderbird-dev-2.0.0.19+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- thunderbird-2.0.0.19+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- thunderbird-dev-2.0.0.19+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- thunderbird-gnome-support-2.0.0.19+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-5500","CVE-2008-5503","CVE-2008-5506","CVE-2008-5507","CVE-2008-5508","CVE-2008-5510","CVE-2008-5511","CVE-2008-5512");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "mozilla-thunderbird", pkgver: "2.0.0.19+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to mozilla-thunderbird-2.0.0.19+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "mozilla-thunderbird-dev", pkgver: "2.0.0.19+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to mozilla-thunderbird-dev-2.0.0.19+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "thunderbird", pkgver: "2.0.0.19+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to thunderbird-2.0.0.19+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "thunderbird-dev", pkgver: "2.0.0.19+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to thunderbird-dev-2.0.0.19+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "thunderbird-gnome-support", pkgver: "2.0.0.19+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to thunderbird-gnome-support-2.0.0.19+nobinonly-0ubuntu0.8.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
