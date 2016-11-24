# This script was automatically generated from the 540-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28208);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "540-1");
script_summary(english:"flac vulnerability");
script_name(english:"USN540-1 : flac vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- flac 
- libflac++-dev 
- libflac++5c2 
- libflac++6 
- libflac-dev 
- libflac-doc 
- libflac7 
- libflac8 
- liboggflac++-dev 
- liboggflac++2c2 
- liboggflac-dev 
- liboggflac3 
- xmms-flac 
');
script_set_attribute(attribute:'description', value: 'Sean de Regge discovered that flac did not properly perform bounds
checking in many situations. An attacker could send a specially crafted
FLAC audio file and execute arbitrary code as the user or cause a denial
of service in flac or applications that link against flac.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- flac-1.1.4-3ubuntu1.1 (Ubuntu 7.10)
- libflac++-dev-1.1.4-3ubuntu1.1 (Ubuntu 7.10)
- libflac++5c2-1.1.2-5ubuntu2.1 (Ubuntu 7.04)
- libflac++6-1.1.4-3ubuntu1.1 (Ubuntu 7.10)
- libflac-dev-1.1.4-3ubuntu1.1 (Ubuntu 7.10)
- libflac-doc-1.1.4-3ubuntu1.1 (Ubuntu 7.10)
- libflac7-1.1.2-5ubuntu2.1 (Ubuntu 7.04)
- libflac8-1.1.4-3ubuntu1.1 (Ubuntu 7.10)
- liboggflac++-dev-1.1.2-5ubuntu2.1 (Ubuntu 7.04)
- liboggflac++2c2-1.1.2-5ubuntu2.1 (Ubuntu 7.04)
- liboggflac-dev-1.1.2-5ubuntu2.1 (Ubuntu 7.04)
-
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-4619");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "flac", pkgver: "1.1.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package flac-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to flac-1.1.4-3ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libflac++-dev", pkgver: "1.1.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libflac++-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libflac++-dev-1.1.4-3ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libflac++5c2", pkgver: "1.1.2-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libflac++5c2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libflac++5c2-1.1.2-5ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libflac++6", pkgver: "1.1.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libflac++6-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libflac++6-1.1.4-3ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libflac-dev", pkgver: "1.1.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libflac-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libflac-dev-1.1.4-3ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libflac-doc", pkgver: "1.1.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libflac-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libflac-doc-1.1.4-3ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libflac7", pkgver: "1.1.2-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libflac7-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libflac7-1.1.2-5ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libflac8", pkgver: "1.1.4-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libflac8-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libflac8-1.1.4-3ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "liboggflac++-dev", pkgver: "1.1.2-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liboggflac++-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to liboggflac++-dev-1.1.2-5ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "liboggflac++2c2", pkgver: "1.1.2-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liboggflac++2c2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to liboggflac++2c2-1.1.2-5ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "liboggflac-dev", pkgver: "1.1.2-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liboggflac-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to liboggflac-dev-1.1.2-5ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "liboggflac3", pkgver: "1.1.2-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liboggflac3-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to liboggflac3-1.1.2-5ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xmms-flac", pkgver: "1.1.2-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xmms-flac-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xmms-flac-1.1.2-5ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
