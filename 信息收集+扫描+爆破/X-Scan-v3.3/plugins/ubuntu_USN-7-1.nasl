# This script was automatically generated from the 7-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20690);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "7-1");
script_summary(english:"imagemagick vulnerability");
script_name(english:"USN7-1 : imagemagick vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- imagemagick 
- libmagick++6 
- libmagick++6-dev 
- libmagick6 
- libmagick6-dev 
- perlmagick 
');
script_set_attribute(attribute:'description', value: 'A buffer overflow in imagemagick\'s EXIF parsing routine has been
discovered in imagemagick versions prior to 6.1.0. Trying to query
EXIF information of a malicious image file might result in execution
of arbitrary code with the user\'s privileges.

Since imagemagick can be used in custom printing systems, this also
might lead to privilege escalation (execute code with the printer
spooler\'s privileges). However, Ubuntu\'s standard printing system does
not use imagemagick, thus there is no risk of privilege escalation in
a standard installation.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- imagemagick-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
- libmagick++6-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
- libmagick++6-dev-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
- libmagick6-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
- libmagick6-dev-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
- perlmagick-6.0.2.5-1ubuntu1.1 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2004-0981");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "imagemagick", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package imagemagick-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to imagemagick-6.0.2.5-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick++6", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick++6-6.0.2.5-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick++6-dev", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick++6-dev-6.0.2.5-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick6", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick6-6.0.2.5-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick6-dev", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick6-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick6-dev-6.0.2.5-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "perlmagick", pkgver: "6.0.2.5-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perlmagick-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to perlmagick-6.0.2.5-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
