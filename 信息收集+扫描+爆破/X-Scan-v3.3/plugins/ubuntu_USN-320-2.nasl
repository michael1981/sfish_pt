# This script was automatically generated from the 320-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27898);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "320-2");
script_summary(english:"php4 regression");
script_name(english:"USN320-2 : php4 regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libapache2-mod-php4 
- php4 
- php4-cgi 
- php4-cli 
- php4-common 
- php4-dev 
');
script_set_attribute(attribute:'description', value: 'USN-320-2 fixed several vulnerabilities in PHP. James Manning
discovered that the Ubuntu 5.04 update introduced a regression, the
function tempnam() caused a crash of the PHP interpreter in some
circumstances. The updated packages fix this.

We apologize for the inconvenience.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libapache2-mod-php4-4.3.10-10ubuntu4.6 (Ubuntu 5.04)
- php4-4.3.10-10ubuntu4.6 (Ubuntu 5.04)
- php4-cgi-4.3.10-10ubuntu4.6 (Ubuntu 5.04)
- php4-cli-4.3.10-10ubuntu4.6 (Ubuntu 5.04)
- php4-common-4.3.10-10ubuntu4.6 (Ubuntu 5.04)
- php4-dev-4.3.10-10ubuntu4.6 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "libapache2-mod-php4", pkgver: "4.3.10-10ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-mod-php4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libapache2-mod-php4-4.3.10-10ubuntu4.6
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4", pkgver: "4.3.10-10ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-4.3.10-10ubuntu4.6
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-cgi", pkgver: "4.3.10-10ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-cgi-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-cgi-4.3.10-10ubuntu4.6
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-cli", pkgver: "4.3.10-10ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-cli-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-cli-4.3.10-10ubuntu4.6
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-common", pkgver: "4.3.10-10ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-common-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-common-4.3.10-10ubuntu4.6
');
}
found = ubuntu_check(osver: "5.04", pkgname: "php4-dev", pkgver: "4.3.10-10ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package php4-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to php4-dev-4.3.10-10ubuntu4.6
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
