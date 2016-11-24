# This script was automatically generated from the 822-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40767);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "822-1");
script_summary(english:"kde4libs, kdelibs vulnerabilities");
script_name(english:"USN822-1 : kde4libs, kdelibs vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- kdelibs 
- kdelibs-bin 
- kdelibs-data 
- kdelibs-dbg 
- kdelibs4-dev 
- kdelibs4-doc 
- kdelibs4c2a 
- kdelibs5 
- kdelibs5-data 
- kdelibs5-dbg 
- kdelibs5-dev 
- libplasma-dev 
- libplasma3 
');
script_set_attribute(attribute:'description', value: 'It was discovered that KDE-Libs did not properly handle certain malformed
SVG images. If a user were tricked into opening a specially crafted SVG
image, an attacker could cause a denial of service or possibly execute
arbitrary code with the privileges of the user invoking the program. This
issue only affected Ubuntu 9.04. (CVE-2009-0945)

It was discovered that the KDE JavaScript garbage collector did not
properly handle memory allocation failures. If a user were tricked into
viewing a malicious website, an attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2009-1687)

It was discovered that KDE-Libs did not properly handle HTML content in the
head element. If a user were tricked into viewing a malicious website, an
attacker could cause a denial of service or possibly execute arbitrary code
with the privileges of the user invoking the program. (CVE-2009-1690)

It was discovered that KDE-Libs did not properly handle the Cascad
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- kdelibs-3.5.10.dfsg.1-1ubuntu8.1 (Ubuntu 9.04)
- kdelibs-bin-4.2.2-0ubuntu5.1 (Ubuntu 9.04)
- kdelibs-data-3.5.10.dfsg.1-1ubuntu8.1 (Ubuntu 9.04)
- kdelibs-dbg-3.5.10.dfsg.1-1ubuntu8.1 (Ubuntu 9.04)
- kdelibs4-dev-3.5.10.dfsg.1-1ubuntu8.1 (Ubuntu 9.04)
- kdelibs4-doc-3.5.10-0ubuntu6.1 (Ubuntu 8.10)
- kdelibs4c2a-3.5.10.dfsg.1-1ubuntu8.1 (Ubuntu 9.04)
- kdelibs5-4.2.2-0ubuntu5.1 (Ubuntu 9.04)
- kdelibs5-data-4.2.2-0ubuntu5.1 (Ubuntu 9.04)
- kdelibs5-dbg-4.2.2-0ubuntu5.1 (Ubuntu 9.04)
- kdeli
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0945","CVE-2009-1687","CVE-2009-1690","CVE-2009-1698");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "kdelibs", pkgver: "3.5.10.dfsg.1-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to kdelibs-3.5.10.dfsg.1-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "kdelibs-bin", pkgver: "4.2.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-bin-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to kdelibs-bin-4.2.2-0ubuntu5.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "kdelibs-data", pkgver: "3.5.10.dfsg.1-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-data-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to kdelibs-data-3.5.10.dfsg.1-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "kdelibs-dbg", pkgver: "3.5.10.dfsg.1-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to kdelibs-dbg-3.5.10.dfsg.1-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "kdelibs4-dev", pkgver: "3.5.10.dfsg.1-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to kdelibs4-dev-3.5.10.dfsg.1-1ubuntu8.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "kdelibs4-doc", pkgver: "3.5.10-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to kdelibs4-doc-3.5.10-0ubuntu6.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "kdelibs4c2a", pkgver: "3.5.10.dfsg.1-1ubuntu8.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4c2a-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to kdelibs4c2a-3.5.10.dfsg.1-1ubuntu8.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "kdelibs5", pkgver: "4.2.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs5-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to kdelibs5-4.2.2-0ubuntu5.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "kdelibs5-data", pkgver: "4.2.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs5-data-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to kdelibs5-data-4.2.2-0ubuntu5.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "kdelibs5-dbg", pkgver: "4.2.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs5-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to kdelibs5-dbg-4.2.2-0ubuntu5.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "kdelibs5-dev", pkgver: "4.2.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs5-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to kdelibs5-dev-4.2.2-0ubuntu5.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libplasma-dev", pkgver: "4.2.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libplasma-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libplasma-dev-4.2.2-0ubuntu5.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libplasma3", pkgver: "4.2.2-0ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libplasma3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libplasma3-4.2.2-0ubuntu5.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
