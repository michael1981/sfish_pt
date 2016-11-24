# This script was automatically generated from the 466-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28066);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "466-1");
script_summary(english:"freetype vulnerability");
script_name(english:"USN466-1 : freetype vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- freetype2-demos 
- libfreetype6 
- libfreetype6-dev 
');
script_set_attribute(attribute:'description', value: 'Victor Stinner discovered that freetype did not correctly verify the
number of points in a TrueType font.  If a user were tricked into using
a specially crafted font, a remote attacker could execute arbitrary code
with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- freetype2-demos-2.2.1-5ubuntu1.1 (Ubuntu 7.04)
- libfreetype6-2.2.1-5ubuntu1.1 (Ubuntu 7.04)
- libfreetype6-dev-2.2.1-5ubuntu1.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-2754");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "freetype2-demos", pkgver: "2.2.1-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freetype2-demos-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to freetype2-demos-2.2.1-5ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libfreetype6", pkgver: "2.2.1-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libfreetype6-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libfreetype6-2.2.1-5ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libfreetype6-dev", pkgver: "2.2.1-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libfreetype6-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libfreetype6-dev-2.2.1-5ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
