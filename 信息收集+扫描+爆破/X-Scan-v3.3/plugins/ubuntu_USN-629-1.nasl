# This script was automatically generated from the 629-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33587);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "629-1");
script_summary(english:"Thunderbird vulnerabilities");
script_name(english:"USN629-1 : Thunderbird vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- mozilla-thunderbird 
- mozilla-thunderbird-dev 
- thunderbird 
- thunderbird-dev 
- thunderbird-gnome-support 
');
script_set_attribute(attribute:'description', value: 'Various flaws were discovered in the browser engine. If a user had
Javascript enabled and were tricked into opening a malicious web
page, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the
user invoking the program. (CVE-2008-2798, CVE-2008-2799)

It was discovered that Thunderbird would allow non-privileged XUL
documents to load chrome scripts from the fastload file if Javascript
was enabled. This could allow an attacker to execute arbitrary
Javascript code with chrome privileges. (CVE-2008-2802)

A flaw was discovered in Thunderbird that allowed overwriting trusted
objects via mozIJSSubScriptLoader.loadSubScript(). If a user had
Javascript enabled and was tricked into opening a malicious web page,
an attacker could execute arbitrary code with the privileges of the
user invoking the program. (CVE-2008-2803)

Daniel Glazman found that an improperly encoded .properties file in
an add-on can result in uninitialized memory being used.
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- mozilla-thunderbird-2.0.0.16+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- mozilla-thunderbird-dev-2.0.0.16+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- thunderbird-2.0.0.16+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- thunderbird-dev-2.0.0.16+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
- thunderbird-gnome-support-2.0.0.16+nobinonly-0ubuntu0.8.04.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-0304","CVE-2008-2785","CVE-2008-2798","CVE-2008-2799","CVE-2008-2802","CVE-2008-2803","CVE-2008-2807","CVE-2008-2809","CVE-2008-2811");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "mozilla-thunderbird", pkgver: "2.0.0.16+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to mozilla-thunderbird-2.0.0.16+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "mozilla-thunderbird-dev", pkgver: "2.0.0.16+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package mozilla-thunderbird-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to mozilla-thunderbird-dev-2.0.0.16+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "thunderbird", pkgver: "2.0.0.16+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to thunderbird-2.0.0.16+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "thunderbird-dev", pkgver: "2.0.0.16+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to thunderbird-dev-2.0.0.16+nobinonly-0ubuntu0.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "thunderbird-gnome-support", pkgver: "2.0.0.16+nobinonly-0ubuntu0.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package thunderbird-gnome-support-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to thunderbird-gnome-support-2.0.0.16+nobinonly-0ubuntu0.8.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
