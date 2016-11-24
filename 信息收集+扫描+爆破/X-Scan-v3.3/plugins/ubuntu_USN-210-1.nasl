# This script was automatically generated from the 210-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20628);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "210-1");
script_summary(english:"netpbm-free vulnerability");
script_name(english:"USN210-1 : netpbm-free vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libnetpbm10 
- libnetpbm10-dev 
- libnetpbm9 
- libnetpbm9-dev 
- netpbm 
');
script_set_attribute(attribute:'description', value: 'A buffer overflow was found in the "pnmtopng" conversion program. By
tricking an user (or automated system) to process a specially crafted
PNM image with pnmtopng, this could be exploited to execute arbitrary
code with the privileges of the user running pnmtopng.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnetpbm10-10.0-8ubuntu1.1 (Ubuntu 5.10)
- libnetpbm10-dev-10.0-8ubuntu1.1 (Ubuntu 5.10)
- libnetpbm9-10.0-8ubuntu1.1 (Ubuntu 5.10)
- libnetpbm9-dev-10.0-8ubuntu1.1 (Ubuntu 5.10)
- netpbm-10.0-8ubuntu1.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-2978");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm10", pkgver: "10.0-8ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm10-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm10-10.0-8ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm10-dev", pkgver: "10.0-8ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm10-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm10-dev-10.0-8ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm9", pkgver: "10.0-8ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm9-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm9-10.0-8ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm9-dev", pkgver: "10.0-8ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm9-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm9-dev-10.0-8ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "netpbm", pkgver: "10.0-8ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package netpbm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to netpbm-10.0-8ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
