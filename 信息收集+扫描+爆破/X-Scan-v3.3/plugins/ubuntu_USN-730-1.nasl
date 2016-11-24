# This script was automatically generated from the 730-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37042);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "730-1");
script_summary(english:"libpng vulnerabilities");
script_name(english:"USN730-1 : libpng vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpng12-0 
- libpng12-dev 
- libpng3 
');
script_set_attribute(attribute:'description', value: 'It was discovered that libpng did not properly perform bounds checking in
certain operations. An attacker could send a specially crafted PNG image and
cause a denial of service in applications linked against libpng. This issue
only affected Ubuntu 8.04 LTS. (CVE-2007-5268, CVE-2007-5269)

Tavis Ormandy discovered that libpng did not properly initialize memory. If a
user or automated system were tricked into opening a crafted PNG image, an
attacker could cause a denial of service via application crash, or possibly
execute arbitrary code with the privileges of the user invoking the program.
This issue did not affect Ubuntu 8.10. (CVE-2008-1382)

Harald van Dijk discovered an off-by-one error in libpng. An attacker could
could cause an application crash in programs using pngtest. (CVE-2008-3964)

It was discovered that libpng did not properly NULL terminate a keyword
string. An attacker could exploit this to set arbitrary memory locations to
zero. (CVE-2008-5907)

Glenn Randers-Pehrson discovered that libpng di
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpng12-0-1.2.27-1ubuntu0.1 (Ubuntu 8.10)
- libpng12-dev-1.2.27-1ubuntu0.1 (Ubuntu 8.10)
- libpng3-1.2.27-1ubuntu0.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-5268","CVE-2007-5269","CVE-2008-1382","CVE-2008-3964","CVE-2008-5907","CVE-2009-0040");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libpng12-0", pkgver: "1.2.27-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng12-0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpng12-0-1.2.27-1ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpng12-dev", pkgver: "1.2.27-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng12-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpng12-dev-1.2.27-1ubuntu0.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpng3", pkgver: "1.2.27-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpng3-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpng3-1.2.27-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
