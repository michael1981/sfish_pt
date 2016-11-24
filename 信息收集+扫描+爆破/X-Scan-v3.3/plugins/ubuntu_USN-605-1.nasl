# This script was automatically generated from the 605-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32185);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "605-1");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN605-1 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- thunderbird 
- thunderbird-dev 
- thunderbird-gnome-support 
');
script_set_attribute(attribute:'description', value: 'Various flaws were discovered in the JavaScript engine. If a user had
JavaScript enabled and were tricked into opening a malicious email,
an attacker could escalate privileges within Thunderbird, perform
cross-site scripting attacks and/or execute arbitrary code with the
user\'s privileges. (CVE-2008-1233, CVE-2008-1234, CVE-2008-1235)

Several problems were discovered in Thunderbird which could lead to
crashes and memory corruption. If a user had JavaScript enabled and
were tricked into opening a malicious email, an attacker may be able
to execute arbitrary code with the user\'s privileges. (CVE-2008-1236,
CVE-2008-1237)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-2.0.0.14+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- mozilla-thunderbird-dev-2.0.0.14+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- thunderbird-2.0.0.14+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- thunderbird-dev-2.0.0.14+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- thunderbird-gnome-support-2.0.0.14+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1233","CVE-2008-1234","CVE-2008-1235","CVE-2008-1236","CVE-2008-1237");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "mozilla-thunderbird", pkgver: "2.0.0.14+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to mozilla-thunderbird-2.0.0.14+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "mozilla-thunderbird-dev", pkgver: "2.0.0.14+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to mozilla-thunderbird-dev-2.0.0.14+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "thunderbird", pkgver: "2.0.0.14+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to thunderbird-2.0.0.14+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "thunderbird-dev", pkgver: "2.0.0.14+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to thunderbird-dev-2.0.0.14+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "thunderbird-gnome-support", pkgver: "2.0.0.14+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-gnome-support-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to thunderbird-gnome-support-2.0.0.14+nobinonly-0ubuntu0.8.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
