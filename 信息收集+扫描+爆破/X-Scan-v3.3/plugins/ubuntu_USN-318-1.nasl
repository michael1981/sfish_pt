# This script was automatically generated from the 318-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27894);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "318-1");
script_summary(english:"libtunepimp vulnerability");
script_name(english:"USN318-1 : libtunepimp vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libtunepimp-bin 
- libtunepimp-perl 
- libtunepimp2 
- libtunepimp2-dev 
- libtunepimp2c2 
- libtunepimp2c2a 
- python-tunepimp 
- python2.3-tunepimp 
- python2.4-tunepimp 
');
script_set_attribute(attribute:'description', value: 'Kevin Kofler discovered several buffer overflows in the tag parser. By
tricking a user into opening a specially crafted tagged multimedia
file (such as .ogg or .mp3 music) with an application that uses
libtunepimp, this could be exploited to execute arbitrary code with
the user\'s privileges. 

This particularly affects the KDE applications \'Amarok\' and \'Juk\'.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libtunepimp-bin-0.3.0-9.1ubuntu3.1 (Ubuntu 6.06)
- libtunepimp-perl-0.3.0-9.1ubuntu3.1 (Ubuntu 6.06)
- libtunepimp2-0.3.0-2ubuntu5.1 (Ubuntu 5.04)
- libtunepimp2-dev-0.3.0-9.1ubuntu3.1 (Ubuntu 6.06)
- libtunepimp2c2-0.3.0-2ubuntu7.1 (Ubuntu 5.10)
- libtunepimp2c2a-0.3.0-9.1ubuntu3.1 (Ubuntu 6.06)
- python-tunepimp-0.3.0-9.1ubuntu3.1 (Ubuntu 6.06)
- python2.3-tunepimp-0.3.0-2ubuntu7.1 (Ubuntu 5.10)
- python2.4-tunepimp-0.3.0-9.1ubuntu3.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libtunepimp-bin", pkgver: "0.3.0-9.1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtunepimp-bin-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libtunepimp-bin-0.3.0-9.1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libtunepimp-perl", pkgver: "0.3.0-9.1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtunepimp-perl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libtunepimp-perl-0.3.0-9.1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libtunepimp2", pkgver: "0.3.0-2ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtunepimp2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libtunepimp2-0.3.0-2ubuntu5.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libtunepimp2-dev", pkgver: "0.3.0-9.1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtunepimp2-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libtunepimp2-dev-0.3.0-9.1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libtunepimp2c2", pkgver: "0.3.0-2ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtunepimp2c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libtunepimp2c2-0.3.0-2ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libtunepimp2c2a", pkgver: "0.3.0-9.1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtunepimp2c2a-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libtunepimp2c2a-0.3.0-9.1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python-tunepimp", pkgver: "0.3.0-9.1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-tunepimp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python-tunepimp-0.3.0-9.1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python2.3-tunepimp", pkgver: "0.3.0-2ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-tunepimp-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python2.3-tunepimp-0.3.0-2ubuntu7.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-tunepimp", pkgver: "0.3.0-9.1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-tunepimp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-tunepimp-0.3.0-9.1ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
