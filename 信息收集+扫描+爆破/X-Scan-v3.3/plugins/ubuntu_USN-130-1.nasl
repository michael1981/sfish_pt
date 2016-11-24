# This script was automatically generated from the 130-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20521);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "130-1");
script_summary(english:"tiff vulnerability");
script_name(english:"USN130-1 : tiff vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libtiff-tools 
- libtiff4 
- libtiff4-dev 
');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy discovered a buffer overflow in the TIFF library.  A
malicious image with an invalid "bits per sample" number could be
constructed which, when decoded, would have resulted in execution of
arbitrary code with the privileges of the process using the library.

Since this library is used in many applications like "ghostscript" and
the "CUPS" printing system, this vulnerability may lead to remotely
induced privilege escalation.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libtiff-tools-3.6.1-5ubuntu0.1 (Ubuntu 5.04)
- libtiff4-3.6.1-5ubuntu0.1 (Ubuntu 5.04)
- libtiff4-dev-3.6.1-5ubuntu0.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-1544");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "libtiff-tools", pkgver: "3.6.1-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff-tools-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libtiff-tools-3.6.1-5ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libtiff4", pkgver: "3.6.1-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libtiff4-3.6.1-5ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libtiff4-dev", pkgver: "3.6.1-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtiff4-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libtiff4-dev-3.6.1-5ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
