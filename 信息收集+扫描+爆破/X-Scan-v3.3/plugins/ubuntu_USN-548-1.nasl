# This script was automatically generated from the 548-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28360);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "548-1");
script_summary(english:"Pidgin vulnerability");
script_name(english:"USN548-1 : Pidgin vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- finch 
- finch-dev 
- gaim 
- libpurple-bin 
- libpurple-dev 
- libpurple0 
- pidgin 
- pidgin-data 
- pidgin-dbg 
- pidgin-dev 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Pidgin did not correctly handle certain logging
events.  A remote attacker could send specially crafted messages and cause
the application to crash, leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- finch-2.2.1-1ubuntu4.1 (Ubuntu 7.10)
- finch-dev-2.2.1-1ubuntu4.1 (Ubuntu 7.10)
- gaim-2.2.1-1ubuntu4.1 (Ubuntu 7.10)
- libpurple-bin-2.2.1-1ubuntu4.1 (Ubuntu 7.10)
- libpurple-dev-2.2.1-1ubuntu4.1 (Ubuntu 7.10)
- libpurple0-2.2.1-1ubuntu4.1 (Ubuntu 7.10)
- pidgin-2.2.1-1ubuntu4.1 (Ubuntu 7.10)
- pidgin-data-2.2.1-1ubuntu4.1 (Ubuntu 7.10)
- pidgin-dbg-2.2.1-1ubuntu4.1 (Ubuntu 7.10)
- pidgin-dev-2.2.1-1ubuntu4.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-4999");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "finch", pkgver: "2.2.1-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package finch-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to finch-2.2.1-1ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "finch-dev", pkgver: "2.2.1-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package finch-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to finch-dev-2.2.1-1ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "gaim", pkgver: "2.2.1-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gaim-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to gaim-2.2.1-1ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpurple-bin", pkgver: "2.2.1-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpurple-bin-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpurple-bin-2.2.1-1ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpurple-dev", pkgver: "2.2.1-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpurple-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpurple-dev-2.2.1-1ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpurple0", pkgver: "2.2.1-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpurple0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpurple0-2.2.1-1ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pidgin", pkgver: "2.2.1-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pidgin-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pidgin-2.2.1-1ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pidgin-data", pkgver: "2.2.1-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pidgin-data-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pidgin-data-2.2.1-1ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pidgin-dbg", pkgver: "2.2.1-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pidgin-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pidgin-dbg-2.2.1-1ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pidgin-dev", pkgver: "2.2.1-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pidgin-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pidgin-dev-2.2.1-1ubuntu4.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
