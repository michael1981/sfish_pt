# This script was automatically generated from the 668-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37649);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "668-1");
script_summary(english:"mozilla-thunderbird, thunderbird vulnerabilities");
script_name(english:"USN668-1 : mozilla-thunderbird, thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- thunderbird 
- thunderbird-dev 
- thunderbird-gnome-support 
');
script_set_attribute(attribute:'description', value: 'Georgi Guninski, Michal Zalewsk and Chris Evans discovered that the same-origin
check in Thunderbird could be bypassed. If a user were tricked into opening a
malicious website, an attacker could obtain private information from data
stored in the images, or discover information about software on the user\'s
computer. (CVE-2008-5012)

Jesse Ruderman discovered that Thunderbird did not properly guard locks on
non-native objects. If a user had JavaScript enabled and were tricked into
opening malicious web content, an attacker could cause a browser crash and
possibly execute arbitrary code with user privileges. (CVE-2008-5014)

Several problems were discovered in the browser, layout and JavaScript engines.
If a user had JavaScript enabled, these problems could allow an attacker to
crash Thunderbird and possibly execute arbitrary code with user privileges.
(CVE-2008-5016, CVE-2008-5017, CVE-2008-5018)

A flaw was discovered in Thunderbird\'s DOM constructing code. If a user were
tricked into opening a malicious we
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-2.0.0.18+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- mozilla-thunderbird-dev-2.0.0.18+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- thunderbird-2.0.0.18+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- thunderbird-dev-2.0.0.18+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
- thunderbird-gnome-support-2.0.0.18+nobinonly-0ubuntu0.8.10.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-5012","CVE-2008-5014","CVE-2008-5016","CVE-2008-5017","CVE-2008-5018","CVE-2008-5021","CVE-2008-5022","CVE-2008-5024");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "mozilla-thunderbird", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to mozilla-thunderbird-2.0.0.18+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "mozilla-thunderbird-dev", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to mozilla-thunderbird-dev-2.0.0.18+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "thunderbird", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to thunderbird-2.0.0.18+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "thunderbird-dev", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to thunderbird-dev-2.0.0.18+nobinonly-0ubuntu0.8.10.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "thunderbird-gnome-support", pkgver: "2.0.0.18+nobinonly-0ubuntu0.8.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-gnome-support-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to thunderbird-gnome-support-2.0.0.18+nobinonly-0ubuntu0.8.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
