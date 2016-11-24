# This script was automatically generated from the 590-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31677);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "590-1");
script_summary(english:"bzip2 vulnerability");
script_name(english:"USN590-1 : bzip2 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- bzip2 
- bzip2-doc 
- lib32bz2-1.0 
- lib32bz2-dev 
- lib64bz2-1.0 
- lib64bz2-dev 
- libbz2-1.0 
- libbz2-dev 
');
script_set_attribute(attribute:'description', value: 'It was discovered that bzip2 did not correctly handle certain malformed
archives.  If a user or automated system were tricked into processing
a specially crafted bzip2 archive, applications linked against libbz2
could be made to crash, possibly leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- bzip2-1.0.4-0ubuntu2.1 (Ubuntu 7.10)
- bzip2-doc-1.0.4-0ubuntu2.1 (Ubuntu 7.10)
- lib32bz2-1.0-1.0.4-0ubuntu2.1 (Ubuntu 7.10)
- lib32bz2-dev-1.0.4-0ubuntu2.1 (Ubuntu 7.10)
- lib64bz2-1.0-1.0.4-0ubuntu2.1 (Ubuntu 7.10)
- lib64bz2-dev-1.0.4-0ubuntu2.1 (Ubuntu 7.10)
- libbz2-1.0-1.0.4-0ubuntu2.1 (Ubuntu 7.10)
- libbz2-dev-1.0.4-0ubuntu2.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2008-1372");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "bzip2", pkgver: "1.0.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bzip2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to bzip2-1.0.4-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "bzip2-doc", pkgver: "1.0.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bzip2-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to bzip2-doc-1.0.4-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "lib32bz2-1.0", pkgver: "1.0.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lib32bz2-1.0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to lib32bz2-1.0-1.0.4-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "lib32bz2-dev", pkgver: "1.0.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lib32bz2-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to lib32bz2-dev-1.0.4-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "lib64bz2-1.0", pkgver: "1.0.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lib64bz2-1.0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to lib64bz2-1.0-1.0.4-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "lib64bz2-dev", pkgver: "1.0.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lib64bz2-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to lib64bz2-dev-1.0.4-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libbz2-1.0", pkgver: "1.0.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbz2-1.0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libbz2-1.0-1.0.4-0ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libbz2-dev", pkgver: "1.0.4-0ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbz2-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libbz2-dev-1.0.4-0ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
