# This script was automatically generated from the 747-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36537);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "747-1");
script_summary(english:"icu vulnerability");
script_name(english:"USN747-1 : icu vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- icu-doc 
- lib32icu-dev 
- lib32icu38 
- libicu-dev 
- libicu34 
- libicu34-dev 
- libicu36 
- libicu36-dev 
- libicu38 
- libicu38-dbg 
');
script_set_attribute(attribute:'description', value: 'It was discovered that libicu did not correctly handle certain invalid
encoded data. If a user or automated system were tricked into processing
specially crafted data with applications linked against libicu, certain
content filters could be bypassed.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- icu-doc-3.8.1-2ubuntu0.1 (Ubuntu 8.10)
- lib32icu-dev-3.8.1-2ubuntu0.1 (Ubuntu 8.10)
- lib32icu38-3.8.1-2ubuntu0.1 (Ubuntu 8.10)
- libicu-dev-3.8.1-2ubuntu0.1 (Ubuntu 8.10)
- libicu34-3.4.1a-1ubuntu1.6.06.2 (Ubuntu 6.06)
- libicu34-dev-3.4.1a-1ubuntu1.6.06.2 (Ubuntu 6.06)
- libicu36-3.6-3ubuntu0.2 (Ubuntu 7.10)
- libicu36-dev-3.6-3ubuntu0.2 (Ubuntu 7.10)
- libicu38-3.8.1-2ubuntu0.1 (Ubuntu 8.10)
- libicu38-dbg-3.8.1-2ubuntu0.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2008-1036");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "icu-doc", pkgver: "3.8.1-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package icu-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to icu-doc-3.8.1-2ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "lib32icu-dev", pkgver: "3.8.1-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lib32icu-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to lib32icu-dev-3.8.1-2ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "lib32icu38", pkgver: "3.8.1-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lib32icu38-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to lib32icu38-3.8.1-2ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libicu-dev", pkgver: "3.8.1-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libicu-dev-3.8.1-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libicu34", pkgver: "3.4.1a-1ubuntu1.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu34-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libicu34-3.4.1a-1ubuntu1.6.06.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libicu34-dev", pkgver: "3.4.1a-1ubuntu1.6.06.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu34-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libicu34-dev-3.4.1a-1ubuntu1.6.06.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libicu36", pkgver: "3.6-3ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu36-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libicu36-3.6-3ubuntu0.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libicu36-dev", pkgver: "3.6-3ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu36-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libicu36-dev-3.6-3ubuntu0.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libicu38", pkgver: "3.8.1-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu38-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libicu38-3.8.1-2ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libicu38-dbg", pkgver: "3.8.1-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu38-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libicu38-dbg-3.8.1-2ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
