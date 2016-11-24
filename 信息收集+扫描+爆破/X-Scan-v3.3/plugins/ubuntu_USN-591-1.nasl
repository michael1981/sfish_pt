# This script was automatically generated from the 591-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31678);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "591-1");
script_summary(english:"libicu vulnerabilities");
script_name(english:"USN591-1 : libicu vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- icu-doc 
- libicu34 
- libicu34-dev 
- libicu36 
- libicu36-dev 
');
script_set_attribute(attribute:'description', value: 'Will Drewry discovered that libicu did not properly handle \'\\0\' when
processing regular expressions. If an application linked against libicu
processed a crafted regular expression, an attacker could execute
arbitrary code with privileges of the user invoking the program.
(CVE-2007-4770)

Will Drewry discovered that libicu did not properly limit its
backtracking stack size. If an application linked against libicu
processed a crafted regular expression, an attacker could cause a denial
of service via resource exhaustion. (CVE-2007-4771)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- icu-doc-3.6-3ubuntu0.1 (Ubuntu 7.10)
- libicu34-3.4.1a-1ubuntu1.6.10.1 (Ubuntu 6.10)
- libicu34-dev-3.4.1a-1ubuntu1.6.10.1 (Ubuntu 6.10)
- libicu36-3.6-3ubuntu0.1 (Ubuntu 7.10)
- libicu36-dev-3.6-3ubuntu0.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-4770","CVE-2007-4771");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "icu-doc", pkgver: "3.6-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package icu-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to icu-doc-3.6-3ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libicu34", pkgver: "3.4.1a-1ubuntu1.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu34-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libicu34-3.4.1a-1ubuntu1.6.10.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libicu34-dev", pkgver: "3.4.1a-1ubuntu1.6.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu34-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libicu34-dev-3.4.1a-1ubuntu1.6.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libicu36", pkgver: "3.6-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu36-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libicu36-3.6-3ubuntu0.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libicu36-dev", pkgver: "3.6-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu36-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libicu36-dev-3.6-3ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
