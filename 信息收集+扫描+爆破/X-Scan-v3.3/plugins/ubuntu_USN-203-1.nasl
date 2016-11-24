# This script was automatically generated from the 203-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20619);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "203-1");
script_summary(english:"abiword vulnerabilities");
script_name(english:"USN203-1 : abiword vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- abiword 
- abiword-common 
- abiword-doc 
- abiword-gnome 
- abiword-help 
- abiword-plugins 
- abiword-plugins-gnome 
- xfonts-abi 
');
script_set_attribute(attribute:'description', value: 'Chris Evans discovered several buffer overflows in the RTF import
module of AbiWord. By tricking a user into opening an RTF file with
specially crafted long identifiers, an attacker could exploit this to
execute arbitrary code with the privileges of the AbiWord user.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- abiword-2.2.2-1ubuntu2.2 (Ubuntu 5.04)
- abiword-common-2.2.2-1ubuntu2.2 (Ubuntu 5.04)
- abiword-doc-2.2.2-1ubuntu2.2 (Ubuntu 5.04)
- abiword-gnome-2.2.2-1ubuntu2.2 (Ubuntu 5.04)
- abiword-help-2.2.2-1ubuntu2.2 (Ubuntu 5.04)
- abiword-plugins-2.2.2-1ubuntu2.2 (Ubuntu 5.04)
- abiword-plugins-gnome-2.2.2-1ubuntu2.2 (Ubuntu 5.04)
- xfonts-abi-2.2.2-1ubuntu2.2 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-2972");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "abiword", pkgver: "2.2.2-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abiword-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to abiword-2.2.2-1ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "abiword-common", pkgver: "2.2.2-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abiword-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to abiword-common-2.2.2-1ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "abiword-doc", pkgver: "2.2.2-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abiword-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to abiword-doc-2.2.2-1ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "abiword-gnome", pkgver: "2.2.2-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abiword-gnome-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to abiword-gnome-2.2.2-1ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "abiword-help", pkgver: "2.2.2-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abiword-help-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to abiword-help-2.2.2-1ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "abiword-plugins", pkgver: "2.2.2-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abiword-plugins-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to abiword-plugins-2.2.2-1ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "abiword-plugins-gnome", pkgver: "2.2.2-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package abiword-plugins-gnome-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to abiword-plugins-gnome-2.2.2-1ubuntu2.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "xfonts-abi", pkgver: "2.2.2-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xfonts-abi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to xfonts-abi-2.2.2-1ubuntu2.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
