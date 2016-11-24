# This script was automatically generated from the 279-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21373);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "279-1");
script_summary(english:"libnasl vulnerability");
script_name(english:"USN279-1 : libnasl vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libnasl-dev 
- libnasl2 
');
script_set_attribute(attribute:'description', value: 'Jayesh KS discovered that the nasl_split() function in the NASL
(Nessus Attack Scripting Language) library did not check for a
zero-length separator argument, which lead to an invalid memory
allocation. This library is primarily used in the Nessus security
scanner; a remote attacker could exploit this vulnerability to cause
the Nessus daemon to crash.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnasl-dev-2.2.4-1ubuntu0.1 (Ubuntu 5.10)
- libnasl2-2.2.4-1ubuntu0.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-2093");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libnasl-dev", pkgver: "2.2.4-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnasl-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnasl-dev-2.2.4-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnasl2", pkgver: "2.2.4-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnasl2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnasl2-2.2.4-1ubuntu0.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
