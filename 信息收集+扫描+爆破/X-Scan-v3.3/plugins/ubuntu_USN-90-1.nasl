# This script was automatically generated from the 90-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20716);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "90-1");
script_summary(english:"imagemagick vulnerability");
script_name(english:"USN90-1 : imagemagick vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- imagemagick 
- libmagick++6 
- libmagick++6-dev 
- libmagick6 
- libmagick6-dev 
- perlmagick 
');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy discovered a format string vulnerability in ImageMagick\'s file
name handling. Specially crafted file names could cause a program using
ImageMagick to crash, or possibly even cause execution of arbitrary code.

Since ImageMagick can be used in custom printing systems, this also might lead
to privilege escalation (execute code with the printer spooler\'s privileges).
However, Ubuntu\'s standard printing system does not use ImageMagick, thus there
is no risk of privilege escalation in a standard installation.

ImageMagick is also commonly used by web frontends; if these accept image
uploads with arbitrary file names, this could also lead to remote privilege
escalation.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- imagemagick-6.0.2.5-1ubuntu1.4 (Ubuntu 4.10)
- libmagick++6-6.0.2.5-1ubuntu1.4 (Ubuntu 4.10)
- libmagick++6-dev-6.0.2.5-1ubuntu1.4 (Ubuntu 4.10)
- libmagick6-6.0.2.5-1ubuntu1.4 (Ubuntu 4.10)
- libmagick6-dev-6.0.2.5-1ubuntu1.4 (Ubuntu 4.10)
- perlmagick-6.0.2.5-1ubuntu1.4 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0397");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "imagemagick", pkgver: "6.0.2.5-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package imagemagick-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to imagemagick-6.0.2.5-1ubuntu1.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick++6", pkgver: "6.0.2.5-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick++6-6.0.2.5-1ubuntu1.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick++6-dev", pkgver: "6.0.2.5-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick++6-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick++6-dev-6.0.2.5-1ubuntu1.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick6", pkgver: "6.0.2.5-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick6-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick6-6.0.2.5-1ubuntu1.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libmagick6-dev", pkgver: "6.0.2.5-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmagick6-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libmagick6-dev-6.0.2.5-1ubuntu1.4
');
}
found = ubuntu_check(osver: "4.10", pkgname: "perlmagick", pkgver: "6.0.2.5-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perlmagick-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to perlmagick-6.0.2.5-1ubuntu1.4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
