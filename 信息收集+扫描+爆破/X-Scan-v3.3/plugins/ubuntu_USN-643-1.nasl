# This script was automatically generated from the 643-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37738);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "643-1");
script_summary(english:"FreeType vulnerabilities");
script_name(english:"USN643-1 : FreeType vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- freetype2-demos 
- libfreetype6 
- libfreetype6-dev 
');
script_set_attribute(attribute:'description', value: 'Multiple flaws were discovered in the PFB and TTF font handling code
in freetype.  If a user were tricked into using a specially crafted
font file, a remote attacker could execute arbitrary code with user
privileges or cause the application linked against freetype to crash,
leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- freetype2-demos-2.3.5-1ubuntu4.8.04.1 (Ubuntu 8.04)
- libfreetype6-2.3.5-1ubuntu4.8.04.1 (Ubuntu 8.04)
- libfreetype6-dev-2.3.5-1ubuntu4.8.04.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-1806","CVE-2008-1807","CVE-2008-1808");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "freetype2-demos", pkgver: "2.3.5-1ubuntu4.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package freetype2-demos-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to freetype2-demos-2.3.5-1ubuntu4.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libfreetype6", pkgver: "2.3.5-1ubuntu4.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libfreetype6-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libfreetype6-2.3.5-1ubuntu4.8.04.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libfreetype6-dev", pkgver: "2.3.5-1ubuntu4.8.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libfreetype6-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libfreetype6-dev-2.3.5-1ubuntu4.8.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
