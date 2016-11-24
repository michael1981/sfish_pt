# This script was automatically generated from the 608-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32188);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "608-1");
script_summary(english:"KDE vulnerability");
script_name(english:"USN608-1 : KDE vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- kdelibs 
- kdelibs-data 
- kdelibs-dbg 
- kdelibs4-dev 
- kdelibs4-doc 
- kdelibs4c2a 
');
script_set_attribute(attribute:'description', value: 'It was discovered that start_kdeinit in KDE 3 did not properly sanitize
its input. A local attacker could exploit this to send signals to other
processes and cause a denial of service or possibly execute arbitrary
code. (CVE-2008-1671)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- kdelibs-3.5.9-0ubuntu7.1 (Ubuntu 8.04)
- kdelibs-data-3.5.9-0ubuntu7.1 (Ubuntu 8.04)
- kdelibs-dbg-3.5.9-0ubuntu7.1 (Ubuntu 8.04)
- kdelibs4-dev-3.5.9-0ubuntu7.1 (Ubuntu 8.04)
- kdelibs4-doc-3.5.9-0ubuntu7.1 (Ubuntu 8.04)
- kdelibs4c2a-3.5.9-0ubuntu7.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-1671");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "kdelibs", pkgver: "3.5.9-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to kdelibs-3.5.9-0ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "kdelibs-data", pkgver: "3.5.9-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-data-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to kdelibs-data-3.5.9-0ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "kdelibs-dbg", pkgver: "3.5.9-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to kdelibs-dbg-3.5.9-0ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "kdelibs4-dev", pkgver: "3.5.9-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to kdelibs4-dev-3.5.9-0ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "kdelibs4-doc", pkgver: "3.5.9-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to kdelibs4-doc-3.5.9-0ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "kdelibs4c2a", pkgver: "3.5.9-0ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4c2a-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to kdelibs4c2a-3.5.9-0ubuntu7.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
