# This script was automatically generated from the 445-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28042);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "445-1");
script_summary(english:"XMMS vulnerabilities");
script_name(english:"USN445-1 : XMMS vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- xmms 
- xmms-dev 
');
script_set_attribute(attribute:'description', value: 'Sven Krewitt of Secunia Research discovered that XMMS did not correctly 
handle BMP images when loading GUI skins.  If a user were tricked into 
loading a specially crafted skin, a remote attacker could execute 
arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- xmms-1.2.10+cvs20060429-1ubuntu2.1 (Ubuntu 6.10)
- xmms-dev-1.2.10+cvs20060429-1ubuntu2.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-0653","CVE-2007-0654");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "xmms", pkgver: "1.2.10+cvs20060429-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xmms-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xmms-1.2.10+cvs20060429-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "xmms-dev", pkgver: "1.2.10+cvs20060429-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xmms-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to xmms-dev-1.2.10+cvs20060429-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
