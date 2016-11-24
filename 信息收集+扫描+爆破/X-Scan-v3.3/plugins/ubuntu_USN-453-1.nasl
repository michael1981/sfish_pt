# This script was automatically generated from the 453-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28050);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "453-1");
script_summary(english:"X.org vulnerability");
script_name(english:"USN453-1 : X.org vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libx11-6 
- libx11-6-dbg 
- libx11-data 
- libx11-dev 
');
script_set_attribute(attribute:'description', value: 'Multiple integer overflows were found in the XGetPixel function of 
libx11.  If a user were tricked into opening a specially crafted XWD 
image, remote attackers could execute arbitrary code with user 
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libx11-6-1.0.3-0ubuntu4.1 (Ubuntu 6.10)
- libx11-6-dbg-1.0.3-0ubuntu4.1 (Ubuntu 6.10)
- libx11-data-1.0.3-0ubuntu4.1 (Ubuntu 6.10)
- libx11-dev-1.0.3-0ubuntu4.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-1667");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "libx11-6", pkgver: "1.0.3-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libx11-6-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libx11-6-1.0.3-0ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libx11-6-dbg", pkgver: "1.0.3-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libx11-6-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libx11-6-dbg-1.0.3-0ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libx11-data", pkgver: "1.0.3-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libx11-data-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libx11-data-1.0.3-0ubuntu4.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libx11-dev", pkgver: "1.0.3-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libx11-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libx11-dev-1.0.3-0ubuntu4.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
