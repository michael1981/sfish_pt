# This script was automatically generated from the 770-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38686);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "770-1");
script_summary(english:"clamav vulnerability");
script_name(english:"USN770-1 : clamav vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- clamav 
- clamav-base 
- clamav-daemon 
- clamav-dbg 
- clamav-docs 
- clamav-freshclam 
- clamav-milter 
- clamav-testfiles 
- libclamav-dev 
- libclamav6 
');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in the clamav-milter initscript which caused the
ownership of the current working directory to be changed to the \'clamav\'
user. This update attempts to repair the incorrect ownership for standard
system directories, but it is recommended that the following command be
performed to report any other directories that may be affected:

  $ sudo find -H / -type d -user clamav \\! -group clamav 2>/dev/null

Systems configured to run clamav as a user other than the default \'clamav\'
user will need to adjust the above command accordingly.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- clamav-0.95.1+dfsg-1ubuntu1.2 (Ubuntu 9.04)
- clamav-base-0.95.1+dfsg-1ubuntu1.2 (Ubuntu 9.04)
- clamav-daemon-0.95.1+dfsg-1ubuntu1.2 (Ubuntu 9.04)
- clamav-dbg-0.95.1+dfsg-1ubuntu1.2 (Ubuntu 9.04)
- clamav-docs-0.95.1+dfsg-1ubuntu1.2 (Ubuntu 9.04)
- clamav-freshclam-0.95.1+dfsg-1ubuntu1.2 (Ubuntu 9.04)
- clamav-milter-0.95.1+dfsg-1ubuntu1.2 (Ubuntu 9.04)
- clamav-testfiles-0.95.1+dfsg-1ubuntu1.2 (Ubuntu 9.04)
- libclamav-dev-0.95.1+dfsg-1ubuntu1.2 (Ubuntu 9.04)
- libclamav6-0.95.1+dfsg-1ub
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "clamav", pkgver: "0.95.1+dfsg-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to clamav-0.95.1+dfsg-1ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "clamav-base", pkgver: "0.95.1+dfsg-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-base-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to clamav-base-0.95.1+dfsg-1ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "clamav-daemon", pkgver: "0.95.1+dfsg-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-daemon-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to clamav-daemon-0.95.1+dfsg-1ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "clamav-dbg", pkgver: "0.95.1+dfsg-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to clamav-dbg-0.95.1+dfsg-1ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "clamav-docs", pkgver: "0.95.1+dfsg-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-docs-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to clamav-docs-0.95.1+dfsg-1ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "clamav-freshclam", pkgver: "0.95.1+dfsg-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-freshclam-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to clamav-freshclam-0.95.1+dfsg-1ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "clamav-milter", pkgver: "0.95.1+dfsg-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-milter-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to clamav-milter-0.95.1+dfsg-1ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "clamav-testfiles", pkgver: "0.95.1+dfsg-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package clamav-testfiles-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to clamav-testfiles-0.95.1+dfsg-1ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libclamav-dev", pkgver: "0.95.1+dfsg-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libclamav-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libclamav-dev-0.95.1+dfsg-1ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libclamav6", pkgver: "0.95.1+dfsg-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libclamav6-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libclamav6-0.95.1+dfsg-1ubuntu1.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
