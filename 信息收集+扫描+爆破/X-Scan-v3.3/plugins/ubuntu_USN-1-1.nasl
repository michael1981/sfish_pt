# This script was automatically generated from the 1-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20484);
script_version("$Revision: 1.12 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "1-1");
 script_cve_id("CVE-2004-0599");
script_summary(english:"PNG library vulnerabilities");
script_name(english:"USN1-1 : PNG library vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpng10-0 
- libpng10-dev 
- libpng12-0 
- libpng12-dev 
- libpng2 
- libpng2-dev 
- libpng3 
- libpng3-dev 
');
script_set_attribute(attribute:'description', value: 'Several integer overflow vulnerabilities were discovered in the PNG library.
These vulnerabilities could be exploited by an attacker by providing a
specially crafted PNG image which, when processed by the PNG library, could
result in the execution of program code provided by the attacker.

The PNG library is used by a variety of software packages for different
purposes, so the exact nature of the exposure will vary depending on the
software involved.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpng10-0-1.0.15-6ubuntu1 (Ubuntu 4.10)
- libpng10-dev-1.0.15-6ubuntu1 (Ubuntu 4.10)
- libpng12-0-1.2.5.0-7ubuntu1 (Ubuntu 4.10)
- libpng12-dev-1.2.5.0-7ubuntu1 (Ubuntu 4.10)
- libpng2-1.0.15-6ubuntu1 (Ubuntu 4.10)
- libpng2-dev-1.0.15-6ubuntu1 (Ubuntu 4.10)
- libpng3-1.2.5.0-7ubuntu1 (Ubuntu 4.10)
- libpng3-dev-1.2.5.0-7ubuntu1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "libpng10-0", pkgver: "1.0.15-6ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng10-0-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpng10-0-1.0.15-6ubuntu1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libpng10-dev", pkgver: "1.0.15-6ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng10-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpng10-dev-1.0.15-6ubuntu1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libpng12-0", pkgver: "1.2.5.0-7ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng12-0-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpng12-0-1.2.5.0-7ubuntu1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libpng12-dev", pkgver: "1.2.5.0-7ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng12-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpng12-dev-1.2.5.0-7ubuntu1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libpng2", pkgver: "1.0.15-6ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpng2-1.0.15-6ubuntu1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libpng2-dev", pkgver: "1.0.15-6ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng2-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpng2-dev-1.0.15-6ubuntu1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libpng3", pkgver: "1.2.5.0-7ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng3-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpng3-1.2.5.0-7ubuntu1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libpng3-dev", pkgver: "1.2.5.0-7ubuntu1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng3-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libpng3-dev-1.2.5.0-7ubuntu1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
