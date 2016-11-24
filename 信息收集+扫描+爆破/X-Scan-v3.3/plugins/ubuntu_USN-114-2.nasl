# This script was automatically generated from the 114-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20502);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "114-2");
script_summary(english:"kdelibs fixed packages");
script_name(english:"USN114-2 : kdelibs fixed packages");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- kdelibs 
- kdelibs-bin 
- kdelibs-data 
- kdelibs4 
- kdelibs4-dev 
- kdelibs4-doc 
');
script_set_attribute(attribute:'description', value: 'USN-114-1 fixed a vulnerability in the PCX decoder of kimgio.
Unfortunately it was discovered that the original patches were faulty
and caused regressions. This update now has the correct patches.

This update also fixes the disappearing KDE settings which were caused
by the accidential removal of /etc/kderc.
(https://bugzilla.ubuntu.com/10035)

We apologize for the inconvenience.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- kdelibs-3.4.0-0ubuntu3.2 (Ubuntu 5.04)
- kdelibs-bin-3.4.0-0ubuntu3.2 (Ubuntu 5.04)
- kdelibs-data-3.4.0-0ubuntu3.2 (Ubuntu 5.04)
- kdelibs4-3.4.0-0ubuntu3.2 (Ubuntu 5.04)
- kdelibs4-dev-3.4.0-0ubuntu3.2 (Ubuntu 5.04)
- kdelibs4-doc-3.4.0-0ubuntu3.2 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "kdelibs", pkgver: "3.4.0-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs-3.4.0-0ubuntu3.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdelibs-bin", pkgver: "3.4.0-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-bin-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs-bin-3.4.0-0ubuntu3.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdelibs-data", pkgver: "3.4.0-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs-data-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs-data-3.4.0-0ubuntu3.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdelibs4", pkgver: "3.4.0-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs4-3.4.0-0ubuntu3.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdelibs4-dev", pkgver: "3.4.0-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs4-dev-3.4.0-0ubuntu3.2
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kdelibs4-doc", pkgver: "3.4.0-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kdelibs4-doc-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kdelibs4-doc-3.4.0-0ubuntu3.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
