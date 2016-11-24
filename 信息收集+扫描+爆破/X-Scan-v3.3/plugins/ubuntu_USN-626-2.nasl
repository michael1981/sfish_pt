# This script was automatically generated from the 626-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33827);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "626-2");
script_summary(english:"Devhelp, Epiphany, Midbrowser and Yelp update");
script_name(english:"USN626-2 : Devhelp, Epiphany, Midbrowser and Yelp update");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- devhelp 
- devhelp-common 
- epiphany-browser 
- epiphany-browser-data 
- epiphany-browser-dbg 
- epiphany-browser-dev 
- epiphany-gecko 
- libdevhelp-1-0 
- libdevhelp-1-dev 
- yelp 
');
script_set_attribute(attribute:'description', value: 'USN-626-1 fixed vulnerabilities in xulrunner-1.9. The changes required
that Devhelp, Epiphany, Midbrowser and Yelp also be updated to use the
new xulrunner-1.9.

Original advisory details:

 A flaw was discovered in the browser engine. A variable could be made to
 overflow causing the browser to crash. If a user were tricked into opening
 a malicious web page, an attacker could cause a denial of service or
 possibly execute arbitrary code with the privileges of the user invoking
 the program. (CVE-2008-2785)
 
 Billy Rios discovered that Firefox and xulrunner, as used by browsers
 such as Epiphany, did not properly perform URI splitting with pipe
 symbols when passed a command-line URI. If Firefox or xulrunner were
 passed a malicious URL, an attacker may be able to execute local
 content with chrome privileges. (CVE-2008-2933)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- devhelp-0.19-1ubuntu1.8.04.3 (Ubuntu 8.04)
- devhelp-common-0.19-1ubuntu1.8.04.3 (Ubuntu 8.04)
- epiphany-browser-2.22.2-0ubuntu0.8.04.5 (Ubuntu 8.04)
- epiphany-browser-data-2.22.2-0ubuntu0.8.04.5 (Ubuntu 8.04)
- epiphany-browser-dbg-2.22.2-0ubuntu0.8.04.5 (Ubuntu 8.04)
- epiphany-browser-dev-2.22.2-0ubuntu0.8.04.5 (Ubuntu 8.04)
- epiphany-gecko-2.22.2-0ubuntu0.8.04.5 (Ubuntu 8.04)
- libdevhelp-1-0-0.19-1ubuntu1.8.04.3 (Ubuntu 8.04)
- libdevhelp-1-dev-0.19-1ubuntu1.8.04.3 (Ubuntu 8.04)
- y
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-2785","CVE-2008-2933");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "devhelp", pkgver: "0.19-1ubuntu1.8.04.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package devhelp-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to devhelp-0.19-1ubuntu1.8.04.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "devhelp-common", pkgver: "0.19-1ubuntu1.8.04.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package devhelp-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to devhelp-common-0.19-1ubuntu1.8.04.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "epiphany-browser", pkgver: "2.22.2-0ubuntu0.8.04.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package epiphany-browser-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to epiphany-browser-2.22.2-0ubuntu0.8.04.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "epiphany-browser-data", pkgver: "2.22.2-0ubuntu0.8.04.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package epiphany-browser-data-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to epiphany-browser-data-2.22.2-0ubuntu0.8.04.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "epiphany-browser-dbg", pkgver: "2.22.2-0ubuntu0.8.04.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package epiphany-browser-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to epiphany-browser-dbg-2.22.2-0ubuntu0.8.04.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "epiphany-browser-dev", pkgver: "2.22.2-0ubuntu0.8.04.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package epiphany-browser-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to epiphany-browser-dev-2.22.2-0ubuntu0.8.04.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "epiphany-gecko", pkgver: "2.22.2-0ubuntu0.8.04.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package epiphany-gecko-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to epiphany-gecko-2.22.2-0ubuntu0.8.04.5
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libdevhelp-1-0", pkgver: "0.19-1ubuntu1.8.04.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdevhelp-1-0-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libdevhelp-1-0-0.19-1ubuntu1.8.04.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libdevhelp-1-dev", pkgver: "0.19-1ubuntu1.8.04.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdevhelp-1-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libdevhelp-1-dev-0.19-1ubuntu1.8.04.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "yelp", pkgver: "2.22.1-0ubuntu2.8.04.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package yelp-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to yelp-2.22.1-0ubuntu2.8.04.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
