# This script was automatically generated from the 836-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(41606);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "836-1");
script_summary(english:"webkit vulnerabilities");
script_name(english:"USN836-1 : webkit vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libwebkit-1.0-1 
- libwebkit-1.0-1-dbg 
- libwebkit-dev 
');
script_set_attribute(attribute:'description', value: 'It was discovered that WebKit did not properly handle certain SVGPathList
data structures. If a user were tricked into viewing a malicious website,
an attacker could exploit this to execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-0945)

Several flaws were discovered in the WebKit browser and JavaScript engines.
If a user were tricked into viewing a malicious website, a remote attacker
could cause a denial of service or possibly execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-1687, CVE-2009-1690,
CVE-2009-1698, CVE-2009-1711, CVE-2009-1725)

It was discovered that WebKit did not prevent the loading of local Java
applets. If a user were tricked into viewing a malicious website,
an attacker could exploit this to execute arbitrary code with the
privileges of the user invoking the program. (CVE-2009-1712)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libwebkit-1.0-1-1.0.1-4ubuntu0.1 (Ubuntu 9.04)
- libwebkit-1.0-1-dbg-1.0.1-4ubuntu0.1 (Ubuntu 9.04)
- libwebkit-dev-1.0.1-4ubuntu0.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0945","CVE-2009-1687","CVE-2009-1690","CVE-2009-1698","CVE-2009-1711","CVE-2009-1712","CVE-2009-1725");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libwebkit-1.0-1", pkgver: "1.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwebkit-1.0-1-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libwebkit-1.0-1-1.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libwebkit-1.0-1-dbg", pkgver: "1.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwebkit-1.0-1-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libwebkit-1.0-1-dbg-1.0.1-4ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libwebkit-dev", pkgver: "1.0.1-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwebkit-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libwebkit-dev-1.0.1-4ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
