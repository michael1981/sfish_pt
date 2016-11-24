# This script was automatically generated from the 289-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27861);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "289-1");
script_summary(english:"tiff vulnerabilities");
script_name(english:"USN289-1 : tiff vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libtiff-opengl 
- libtiff-tools 
- libtiff4 
- libtiff4-dev 
- libtiffxx0c2 
');
script_set_attribute(attribute:'description', value: 'A buffer overflow has been found in the tiff2pdf utility. By tricking
an user into processing a specially crafted TIF file with tiff2pdf,
this could potentially be exploited to execute arbitrary code with the
privileges of the user. (CVE-2006-2193)

A. Alejandro Hernández discovered a buffer overflow in the tiffsplit
utility. By calling tiffsplit with specially crafted long arguments,
an user can execute arbitrary code.  If tiffsplit is used in e. g.  a
web-based frontend or similar automated system, this could lead to
remote arbitary code execution with the privileges of that system. (In
normal interactive command line usage this is not a vulnerability.)
(CVE-2006-2656)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libtiff-opengl-3.7.4-1ubuntu3.1 (Ubuntu 6.06)
- libtiff-tools-3.7.4-1ubuntu3.1 (Ubuntu 6.06)
- libtiff4-3.7.4-1ubuntu3.1 (Ubuntu 6.06)
- libtiff4-dev-3.7.4-1ubuntu3.1 (Ubuntu 6.06)
- libtiffxx0c2-3.7.4-1ubuntu3.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2193","CVE-2006-2656");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libtiff-opengl", pkgver: "3.7.4-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff-opengl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libtiff-opengl-3.7.4-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libtiff-tools", pkgver: "3.7.4-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff-tools-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libtiff-tools-3.7.4-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libtiff4", pkgver: "3.7.4-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libtiff4-3.7.4-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libtiff4-dev", pkgver: "3.7.4-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff4-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libtiff4-dev-3.7.4-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libtiffxx0c2", pkgver: "3.7.4-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiffxx0c2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libtiffxx0c2-3.7.4-1ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
