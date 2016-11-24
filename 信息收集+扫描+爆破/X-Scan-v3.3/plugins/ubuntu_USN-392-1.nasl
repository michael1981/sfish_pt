# This script was automatically generated from the 392-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27977);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "392-1");
script_summary(english:"xine-lib vulnerability");
script_name(english:"USN392-1 : xine-lib vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libxine-dev 
- libxine-main1 
- libxine1 
- libxine1-dbg 
- libxine1c2 
');
script_set_attribute(attribute:'description', value: 'A buffer overflow was discovered in the Real Media input plugin in 
xine-lib.  If a user were tricked into loading a specially crafted 
stream from a malicious server, the attacker could execute arbitrary 
code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxine-dev-1.1.2+repacked1-0ubuntu3.2 (Ubuntu 6.10)
- libxine-main1-1.1.2+repacked1-0ubuntu3.2 (Ubuntu 6.10)
- libxine1-1.1.2+repacked1-0ubuntu3.2 (Ubuntu 6.10)
- libxine1-dbg-1.1.2+repacked1-0ubuntu3.2 (Ubuntu 6.10)
- libxine1c2-1.0.1-1ubuntu10.7 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-6172");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libxine-dev", pkgver: "1.1.2+repacked1-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libxine-dev-1.1.2+repacked1-0ubuntu3.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libxine-main1", pkgver: "1.1.2+repacked1-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-main1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libxine-main1-1.1.2+repacked1-0ubuntu3.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libxine1", pkgver: "1.1.2+repacked1-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libxine1-1.1.2+repacked1-0ubuntu3.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libxine1-dbg", pkgver: "1.1.2+repacked1-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libxine1-dbg-1.1.2+repacked1-0ubuntu3.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libxine1c2", pkgver: "1.0.1-1ubuntu10.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libxine1c2-1.0.1-1ubuntu10.7
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
