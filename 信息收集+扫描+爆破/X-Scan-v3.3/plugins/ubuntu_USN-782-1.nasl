# This script was automatically generated from the 782-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39533);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "782-1");
script_summary(english:"thunderbird vulnerabilities");
script_name(english:"USN782-1 : thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- thunderbird 
- thunderbird-dev 
- thunderbird-gnome-support 
');
script_set_attribute(attribute:'description', value: 'Several flaws were discovered in the JavaScript engine of Thunderbird. If a
user had JavaScript enabled and were tricked into viewing malicious web
content, a remote attacker could cause a denial of service or possibly
execute arbitrary code with the privileges of the user invoking the
program. (CVE-2009-1303, CVE-2009-1305, CVE-2009-1392, CVE-2009-1833,
CVE-2009-1838)

Several flaws were discovered in the way Thunderbird processed malformed
URI schemes. If a user were tricked into viewing a malicious website and
had JavaScript and plugins enabled, a remote attacker could execute
arbitrary JavaScript or steal private data. (CVE-2009-1306, CVE-2009-1307,
CVE-2009-1309)

Cefn Hoile discovered Thunderbird did not adequately protect against
embedded third-party stylesheets. If JavaScript were enabled, an attacker
could exploit this to perform script injection attacks using XBL bindings.
(CVE-2009-1308)

Shuo Chen, Ziqing Mao, Yi-Min Wang, and Ming Zhang discovered that
Thunderbird did not properly handle error r
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1 (Ubuntu 9.04)
- mozilla-thunderbird-dev-2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1 (Ubuntu 9.04)
- thunderbird-2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1 (Ubuntu 9.04)
- thunderbird-dev-2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1 (Ubuntu 9.04)
- thunderbird-gnome-support-2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1303","CVE-2009-1305","CVE-2009-1306","CVE-2009-1307","CVE-2009-1308","CVE-2009-1309","CVE-2009-1392","CVE-2009-1833","CVE-2009-1836","CVE-2009-1838","CVE-2009-1841");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "mozilla-thunderbird", pkgver: "2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mozilla-thunderbird-2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "mozilla-thunderbird-dev", pkgver: "2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to mozilla-thunderbird-dev-2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "thunderbird", pkgver: "2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to thunderbird-2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "thunderbird-dev", pkgver: "2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to thunderbird-dev-2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "thunderbird-gnome-support", pkgver: "2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-gnome-support-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to thunderbird-gnome-support-2.0.0.22+build1+nobinonly-0ubuntu0.9.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
