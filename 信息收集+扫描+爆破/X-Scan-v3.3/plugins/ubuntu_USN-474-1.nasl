# This script was automatically generated from the 474-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28075);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "474-1");
script_summary(english:"xscreensaver vulnerability");
script_name(english:"USN474-1 : xscreensaver vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- xscreensaver 
- xscreensaver-data 
- xscreensaver-data-extra 
- xscreensaver-gl 
- xscreensaver-gl-extra 
');
script_set_attribute(attribute:'description', value: 'It was discovered that xscreensaver did not correctly validate the
return values from network authentication systems such as LDAP or NIS.
A local attacker could bypass a locked screen if they were able to
interrupt network connectivity.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- xscreensaver-4.24-5ubuntu2.1 (Ubuntu 7.04)
- xscreensaver-data-4.24-5ubuntu2.1 (Ubuntu 7.04)
- xscreensaver-data-extra-4.24-5ubuntu2.1 (Ubuntu 7.04)
- xscreensaver-gl-4.24-5ubuntu2.1 (Ubuntu 7.04)
- xscreensaver-gl-extra-4.24-5ubuntu2.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-1859");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "xscreensaver", pkgver: "4.24-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xscreensaver-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xscreensaver-4.24-5ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xscreensaver-data", pkgver: "4.24-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xscreensaver-data-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xscreensaver-data-4.24-5ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xscreensaver-data-extra", pkgver: "4.24-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xscreensaver-data-extra-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xscreensaver-data-extra-4.24-5ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xscreensaver-gl", pkgver: "4.24-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xscreensaver-gl-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xscreensaver-gl-4.24-5ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "xscreensaver-gl-extra", pkgver: "4.24-5ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xscreensaver-gl-extra-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xscreensaver-gl-extra-4.24-5ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
