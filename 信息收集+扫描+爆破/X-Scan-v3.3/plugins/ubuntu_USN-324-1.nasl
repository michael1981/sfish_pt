# This script was automatically generated from the 324-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27902);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "324-1");
script_summary(english:"freetype vulnerability");
script_name(english:"USN324-1 : freetype vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- freetype2-demos 
- libfreetype6 
- libfreetype6-dev 
');
script_set_attribute(attribute:'description', value: 'An integer overflow has been discovered in the FreeType library. By
tricking a user into installing and/or opening a specially crafted
font file, these could be exploited to execute arbitrary code with the
privileges of that user.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- freetype2-demos-2.1.10-1ubuntu2.2 (Ubuntu 6.06)
- libfreetype6-2.1.10-1ubuntu2.2 (Ubuntu 6.06)
- libfreetype6-dev-2.1.10-1ubuntu2.2 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-3467");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "freetype2-demos", pkgver: "2.1.10-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freetype2-demos-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to freetype2-demos-2.1.10-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libfreetype6", pkgver: "2.1.10-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libfreetype6-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libfreetype6-2.1.10-1ubuntu2.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libfreetype6-dev", pkgver: "2.1.10-1ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libfreetype6-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libfreetype6-dev-2.1.10-1ubuntu2.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
