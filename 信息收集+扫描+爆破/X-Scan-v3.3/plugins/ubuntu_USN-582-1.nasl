# This script was automatically generated from the 582-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31341);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "582-1");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN582-1 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- thunderbird 
- thunderbird-dev 
- thunderbird-gnome-support 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Thunderbird did not properly set the size of a
buffer when parsing an external-body MIME-type. If a user were to open
a specially crafted email, an attacker could cause a denial of service
via application crash or possibly execute arbitrary code as the user.
(CVE-2008-0304)

Various flaws were discovered in Thunderbird and its JavaScript
engine. By tricking a user into opening a malicious message, an
attacker could execute arbitrary code with the user\'s privileges.
(CVE-2008-0412, CVE-2008-0413)

Various flaws were discovered in the JavaScript engine. By tricking
a user into opening a malicious message, an attacker could escalate
privileges within Thunderbird, perform cross-site scripting attacks
and/or execute arbitrary code with the user\'s privileges. (CVE-2008-0415)

Gerry Eisenhaur discovered that the chrome URI scheme did not properly
guard against directory traversal. Under certain circumstances, an
attacker may be able to load files or steal session data. Ubuntu is not
vulnera
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-2.0.0.12+nobinonly-0ubuntu0.7.10.0 (Ubuntu 7.10)
- mozilla-thunderbird-dev-2.0.0.12+nobinonly-0ubuntu0.7.10.0 (Ubuntu 7.10)
- thunderbird-2.0.0.12+nobinonly-0ubuntu0.7.10.0 (Ubuntu 7.10)
- thunderbird-dev-2.0.0.12+nobinonly-0ubuntu0.7.10.0 (Ubuntu 7.10)
- thunderbird-gnome-support-2.0.0.12+nobinonly-0ubuntu0.7.10.0 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-0304","CVE-2008-0412","CVE-2008-0413","CVE-2008-0415","CVE-2008-0418","CVE-2008-0420");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "mozilla-thunderbird", pkgver: "2.0.0.12+nobinonly-0ubuntu0.7.10.0");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mozilla-thunderbird-2.0.0.12+nobinonly-0ubuntu0.7.10.0
');
}
found = ubuntu_check(osver: "7.10", pkgname: "mozilla-thunderbird-dev", pkgver: "2.0.0.12+nobinonly-0ubuntu0.7.10.0");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to mozilla-thunderbird-dev-2.0.0.12+nobinonly-0ubuntu0.7.10.0
');
}
found = ubuntu_check(osver: "7.10", pkgname: "thunderbird", pkgver: "2.0.0.12+nobinonly-0ubuntu0.7.10.0");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to thunderbird-2.0.0.12+nobinonly-0ubuntu0.7.10.0
');
}
found = ubuntu_check(osver: "7.10", pkgname: "thunderbird-dev", pkgver: "2.0.0.12+nobinonly-0ubuntu0.7.10.0");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to thunderbird-dev-2.0.0.12+nobinonly-0ubuntu0.7.10.0
');
}
found = ubuntu_check(osver: "7.10", pkgname: "thunderbird-gnome-support", pkgver: "2.0.0.12+nobinonly-0ubuntu0.7.10.0");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-gnome-support-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to thunderbird-gnome-support-2.0.0.12+nobinonly-0ubuntu0.7.10.0
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
