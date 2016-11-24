# This script was automatically generated from the 813-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40529);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "813-1");
script_summary(english:"apr vulnerability");
script_name(english:"USN813-1 : apr vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libapr1 
- libapr1-dbg 
- libapr1-dev 
');
script_set_attribute(attribute:'description', value: 'Matt Lewis discovered that apr did not properly sanitize its input when
allocating memory. If an application using apr processed crafted input, a
remote attacker could cause a denial of service or potentially execute
arbitrary code as the user invoking the application.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libapr1-1.2.12-5ubuntu0.1 (Ubuntu 9.04)
- libapr1-dbg-1.2.12-5ubuntu0.1 (Ubuntu 9.04)
- libapr1-dev-1.2.12-5ubuntu0.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-2412");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libapr1", pkgver: "1.2.12-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr1-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libapr1-1.2.12-5ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libapr1-dbg", pkgver: "1.2.12-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr1-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libapr1-dbg-1.2.12-5ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libapr1-dev", pkgver: "1.2.12-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr1-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libapr1-dev-1.2.12-5ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
