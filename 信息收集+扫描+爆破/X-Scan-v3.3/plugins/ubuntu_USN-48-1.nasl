# This script was automatically generated from the 48-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20665);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "48-1");
script_summary(english:"xpdf, tetex-bin vulnerabilities");
script_name(english:"USN48-1 : xpdf, tetex-bin vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libkpathsea-dev 
- libkpathsea3 
- tetex-bin 
- xpdf 
- xpdf-common 
- xpdf-reader 
- xpdf-utils 
');
script_set_attribute(attribute:'description', value: 'A potential buffer overflow has been found in the xpdf viewer. An
insufficient input validation could be exploited by an attacker
providing a specially crafted PDF file which, when processed by xpdf,
could result in abnormal program termination or the execution of
attacker supplied program code with the user\'s privileges.

The tetex-bin package contains the affected xpdf code to generate PDF
output and process included PDF files, thus is vulnerable as well.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libkpathsea-dev-2.0.2-21ubuntu0.3 (Ubuntu 4.10)
- libkpathsea3-2.0.2-21ubuntu0.3 (Ubuntu 4.10)
- tetex-bin-2.0.2-21ubuntu0.3 (Ubuntu 4.10)
- xpdf-3.00-8ubuntu1.3 (Ubuntu 4.10)
- xpdf-common-3.00-8ubuntu1.3 (Ubuntu 4.10)
- xpdf-reader-3.00-8ubuntu1.3 (Ubuntu 4.10)
- xpdf-utils-3.00-8ubuntu1.3 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2004-1125");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "libkpathsea-dev", pkgver: "2.0.2-21ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkpathsea-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libkpathsea-dev-2.0.2-21ubuntu0.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libkpathsea3", pkgver: "2.0.2-21ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libkpathsea3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libkpathsea3-2.0.2-21ubuntu0.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "tetex-bin", pkgver: "2.0.2-21ubuntu0.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tetex-bin-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to tetex-bin-2.0.2-21ubuntu0.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf", pkgver: "3.00-8ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xpdf-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-3.00-8ubuntu1.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf-common", pkgver: "3.00-8ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xpdf-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-common-3.00-8ubuntu1.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf-reader", pkgver: "3.00-8ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xpdf-reader-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-reader-3.00-8ubuntu1.3
');
}
found = ubuntu_check(osver: "4.10", pkgname: "xpdf-utils", pkgver: "3.00-8ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xpdf-utils-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to xpdf-utils-3.00-8ubuntu1.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
