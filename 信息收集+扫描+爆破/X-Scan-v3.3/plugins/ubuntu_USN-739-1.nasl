# This script was automatically generated from the 739-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37607);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "739-1");
script_summary(english:"amarok vulnerabilities");
script_name(english:"USN739-1 : amarok vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- amarok 
- amarok-common 
- amarok-dbg 
- amarok-engine-xine 
- amarok-engine-yauap 
- amarok-engines 
- amarok-xine 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Amarok did not correctly handle certain malformed
tags in Audible Audio (.aa) files. If a user were tricked into opening a
crafted Audible Audio file, an attacker could execute arbitrary code with
the privileges of the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- amarok-1.4.10-0ubuntu3.1 (Ubuntu 8.10)
- amarok-common-1.4.10-0ubuntu3.1 (Ubuntu 8.10)
- amarok-dbg-1.4.10-0ubuntu3.1 (Ubuntu 8.10)
- amarok-engine-xine-1.4.10-0ubuntu3.1 (Ubuntu 8.10)
- amarok-engine-yauap-1.4.10-0ubuntu3.1 (Ubuntu 8.10)
- amarok-engines-1.4.10-0ubuntu3.1 (Ubuntu 8.10)
- amarok-xine-1.4.9.1-0ubuntu3.2 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0135","CVE-2009-0136");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "amarok", pkgver: "1.4.10-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package amarok-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to amarok-1.4.10-0ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "amarok-common", pkgver: "1.4.10-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package amarok-common-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to amarok-common-1.4.10-0ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "amarok-dbg", pkgver: "1.4.10-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package amarok-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to amarok-dbg-1.4.10-0ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "amarok-engine-xine", pkgver: "1.4.10-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package amarok-engine-xine-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to amarok-engine-xine-1.4.10-0ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "amarok-engine-yauap", pkgver: "1.4.10-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package amarok-engine-yauap-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to amarok-engine-yauap-1.4.10-0ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "amarok-engines", pkgver: "1.4.10-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package amarok-engines-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to amarok-engines-1.4.10-0ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "amarok-xine", pkgver: "1.4.9.1-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package amarok-xine-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to amarok-xine-1.4.9.1-0ubuntu3.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
