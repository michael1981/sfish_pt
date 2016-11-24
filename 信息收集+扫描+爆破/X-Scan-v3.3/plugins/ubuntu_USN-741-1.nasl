# This script was automatically generated from the 741-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37220);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "741-1");
script_summary(english:"mozilla-thunderbird, thunderbird vulnerabilities");
script_name(english:"USN741-1 : mozilla-thunderbird, thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- thunderbird 
- thunderbird-dev 
- thunderbird-gnome-support 
');
script_set_attribute(attribute:'description', value: 'Several flaws were discovered in the browser engine. If Javascript were
enabled, an attacker could exploit these flaws to crash Thunderbird and
possibly execute arbitrary code with user privileges. (CVE-2009-0352)

Jesse Ruderman and Gary Kwong discovered flaws in the browser engine. If a
user had Javascript enabled, these problems could allow a remote attacker to
cause a denial of service or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-0772, CVE-2009-0774)

Georgi Guninski discovered a flaw when Thunderbird performed a cross-domain
redirect. If a user had Javascript enabled, an attacker could bypass the
same-origin policy in Thunderbird by utilizing nsIRDFService and steal
private data from users authenticated to the redirected website.
(CVE-2009-0776)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-2.0.0.21+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- mozilla-thunderbird-dev-2.0.0.21+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- thunderbird-2.0.0.21+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- thunderbird-dev-2.0.0.21+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- thunderbird-gnome-support-2.0.0.21+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0352","CVE-2009-0772","CVE-2009-0774","CVE-2009-0776");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "mozilla-thunderbird", pkgver: "2.0.0.21+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to mozilla-thunderbird-2.0.0.21+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "mozilla-thunderbird-dev", pkgver: "2.0.0.21+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to mozilla-thunderbird-dev-2.0.0.21+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "thunderbird", pkgver: "2.0.0.21+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to thunderbird-2.0.0.21+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "thunderbird-dev", pkgver: "2.0.0.21+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to thunderbird-dev-2.0.0.21+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "thunderbird-gnome-support", pkgver: "2.0.0.21+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to thunderbird-gnome-support-2.0.0.21+nobinonly-0ubuntu0.8.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
