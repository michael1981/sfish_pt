# This script was automatically generated from the 743-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36471);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "743-1");
script_summary(english:"ghostscript, gs-gpl vulnerabilities");
script_name(english:"USN743-1 : ghostscript, gs-gpl vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ghostscript 
- ghostscript-doc 
- ghostscript-x 
- gs 
- gs-aladdin 
- gs-common 
- gs-esp 
- gs-esp-x 
- gs-gpl 
- libgs-dev 
- libgs-esp-dev 
- libgs8 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Ghostscript contained multiple integer overflows in
its ICC color management library. If a user or automated system were
tricked into opening a crafted Postscript file, an attacker could cause a
denial of service or execute arbitrary code with privileges of the user
invoking the program. (CVE-2009-0583)

It was discovered that Ghostscript did not properly perform bounds checking
in its ICC color management library. If a user or automated system were
tricked into opening a crafted Postscript file, an attacker could cause a
denial of service or execute arbitrary code with privileges of the user
invoking the program. (CVE-2009-0584)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ghostscript-8.63.dfsg.1-0ubuntu6.3 (Ubuntu 8.10)
- ghostscript-doc-8.63.dfsg.1-0ubuntu6.3 (Ubuntu 8.10)
- ghostscript-x-8.63.dfsg.1-0ubuntu6.3 (Ubuntu 8.10)
- gs-8.63.dfsg.1-0ubuntu6.3 (Ubuntu 8.10)
- gs-aladdin-8.63.dfsg.1-0ubuntu6.3 (Ubuntu 8.10)
- gs-common-8.63.dfsg.1-0ubuntu6.3 (Ubuntu 8.10)
- gs-esp-8.63.dfsg.1-0ubuntu6.3 (Ubuntu 8.10)
- gs-esp-x-8.63.dfsg.1-0ubuntu6.3 (Ubuntu 8.10)
- gs-gpl-8.63.dfsg.1-0ubuntu6.3 (Ubuntu 8.10)
- libgs-dev-8.63.dfsg.1-0ubuntu6.3 (Ubuntu 8.10)
- libgs-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0583","CVE-2009-0584");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "ghostscript", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ghostscript-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ghostscript-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ghostscript-doc", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ghostscript-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ghostscript-doc-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ghostscript-x", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ghostscript-x-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ghostscript-x-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gs", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gs-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gs-aladdin", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-aladdin-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gs-aladdin-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gs-common", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-common-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gs-common-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gs-esp", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-esp-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gs-esp-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gs-esp-x", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-esp-x-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gs-esp-x-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gs-gpl", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gs-gpl-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gs-gpl-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgs-dev", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgs-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgs-dev-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgs-esp-dev", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgs-esp-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgs-esp-dev-8.63.dfsg.1-0ubuntu6.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgs8", pkgver: "8.63.dfsg.1-0ubuntu6.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgs8-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgs8-8.63.dfsg.1-0ubuntu6.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
