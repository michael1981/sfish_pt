# This script was automatically generated from the 742-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37359);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "742-1");
script_summary(english:"jasper vulnerabilities");
script_name(english:"USN742-1 : jasper vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libjasper-1.701-1 
- libjasper-1.701-dev 
- libjasper-dev 
- libjasper-runtime 
- libjasper1 
');
script_set_attribute(attribute:'description', value: 'It was discovered that JasPer did not correctly handle memory allocation
when parsing certain malformed JPEG2000 images. If a user were tricked into
opening a specially crafted image with an application that uses libjasper,
an attacker could cause a denial of service and possibly execute arbitrary
code with the user\'s privileges. (CVE-2008-3520)

It was discovered that JasPer created temporary files in an insecure way.
Local users could exploit a race condition and cause a denial of service in
libjasper applications.
(CVE-2008-3521)

It was discovered that JasPer did not correctly handle certain formatting
operations. If a user were tricked into opening a specially crafted image
with an application that uses libjasper, an attacker could cause a denial
of service and possibly execute arbitrary code with the user\'s privileges.
(CVE-2008-3522)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libjasper-1.701-1-1.701.0-2ubuntu0.6.06.1 (Ubuntu 6.06)
- libjasper-1.701-dev-1.701.0-2ubuntu0.6.06.1 (Ubuntu 6.06)
- libjasper-dev-1.900.1-5ubuntu0.1 (Ubuntu 8.10)
- libjasper-runtime-1.900.1-5ubuntu0.1 (Ubuntu 8.10)
- libjasper1-1.900.1-5ubuntu0.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-3520","CVE-2008-3521","CVE-2008-3522");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libjasper-1.701-1", pkgver: "1.701.0-2ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libjasper-1.701-1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libjasper-1.701-1-1.701.0-2ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libjasper-1.701-dev", pkgver: "1.701.0-2ubuntu0.6.06.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libjasper-1.701-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libjasper-1.701-dev-1.701.0-2ubuntu0.6.06.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libjasper-dev", pkgver: "1.900.1-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libjasper-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libjasper-dev-1.900.1-5ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libjasper-runtime", pkgver: "1.900.1-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libjasper-runtime-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libjasper-runtime-1.900.1-5ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libjasper1", pkgver: "1.900.1-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libjasper1-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libjasper1-1.900.1-5ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
