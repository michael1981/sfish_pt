# This script was automatically generated from the 218-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20636);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "218-1");
script_summary(english:"netpbm-free vulnerabilities");
script_name(english:"USN218-1 : netpbm-free vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libnetpbm10 
- libnetpbm10-dev 
- libnetpbm9 
- libnetpbm9-dev 
- netpbm 
');
script_set_attribute(attribute:'description', value: 'Two buffer overflows were discovered in the \'pnmtopng\' tool, which
were triggered by processing an image with exactly 256 colors when
using the -alpha option (CVE-2005-3662) or by processing a text file
with very long lines when using the -text option (CVE-2005-3632).

A remote attacker could exploit these to execute arbitrary code by
tricking an user or an automated system into processing a specially
crafted PNM file with pnmtopng.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libnetpbm10-10.0-8ubuntu1.2 (Ubuntu 5.10)
- libnetpbm10-dev-10.0-8ubuntu1.2 (Ubuntu 5.10)
- libnetpbm9-10.0-8ubuntu1.2 (Ubuntu 5.10)
- libnetpbm9-dev-10.0-8ubuntu1.2 (Ubuntu 5.10)
- netpbm-10.0-8ubuntu1.2 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-3632","CVE-2005-3662");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm10", pkgver: "10.0-8ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm10-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm10-10.0-8ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm10-dev", pkgver: "10.0-8ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm10-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm10-dev-10.0-8ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm9", pkgver: "10.0-8ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm9-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm9-10.0-8ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libnetpbm9-dev", pkgver: "10.0-8ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libnetpbm9-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libnetpbm9-dev-10.0-8ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "netpbm", pkgver: "10.0-8ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package netpbm-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to netpbm-10.0-8ubuntu1.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
