# This script was automatically generated from the 846-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(42081);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "846-1");
script_summary(english:"icu vulnerability");
script_name(english:"USN846-1 : icu vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- icu-doc 
- lib32icu-dev 
- lib32icu38 
- libicu-dev 
- libicu38 
- libicu38-dbg 
');
script_set_attribute(attribute:'description', value: 'It was discovered that ICU did not properly handle invalid byte sequences
during Unicode conversion. If an application using ICU processed crafted
data, content security mechanisms could be bypassed, potentially leading to
cross-site scripting (XSS) attacks.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- icu-doc-3.8.1-3ubuntu1.1 (Ubuntu 9.04)
- lib32icu-dev-3.8.1-3ubuntu1.1 (Ubuntu 9.04)
- lib32icu38-3.8.1-3ubuntu1.1 (Ubuntu 9.04)
- libicu-dev-3.8.1-3ubuntu1.1 (Ubuntu 9.04)
- libicu38-3.8.1-3ubuntu1.1 (Ubuntu 9.04)
- libicu38-dbg-3.8.1-3ubuntu1.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2009-0153");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "icu-doc", pkgver: "3.8.1-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package icu-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to icu-doc-3.8.1-3ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "lib32icu-dev", pkgver: "3.8.1-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lib32icu-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to lib32icu-dev-3.8.1-3ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "lib32icu38", pkgver: "3.8.1-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lib32icu38-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to lib32icu38-3.8.1-3ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libicu-dev", pkgver: "3.8.1-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libicu-dev-3.8.1-3ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libicu38", pkgver: "3.8.1-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu38-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libicu38-3.8.1-3ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libicu38-dbg", pkgver: "3.8.1-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libicu38-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libicu38-dbg-3.8.1-3ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
