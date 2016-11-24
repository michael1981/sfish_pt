# This script was automatically generated from the 656-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37836);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "656-1");
script_summary(english:"cupsys vulnerabilities");
script_name(english:"USN656-1 : cupsys vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- cupsys 
- cupsys-bsd 
- cupsys-client 
- cupsys-common 
- libcupsimage2 
- libcupsimage2-dev 
- libcupsys2 
- libcupsys2-dev 
- libcupsys2-gnutls10 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the SGI image filter in CUPS did not perform
proper bounds checking. If a user or automated system were tricked
into opening a crafted SGI image, an attacker could cause a denial
of service. (CVE-2008-3639)

It was discovered that the texttops filter in CUPS did not properly
validate page metrics. If a user or automated system were tricked into
opening a crafted text file, an attacker could cause a denial of
service. (CVE-2008-3640)

It was discovered that the HP-GL filter in CUPS did not properly check
for invalid pen parameters. If a user or automated system were tricked
into opening a crafted HP-GL or HP-GL/2 file, a remote attacker could
cause a denial of service or execute arbitrary code with user
privileges. In Ubuntu 7.10 and 8.04 LTS, attackers would be isolated by
the AppArmor CUPS profile. (CVE-2008-3641)

NOTE: The previous update for CUPS on Ubuntu 6.06 LTS did not have the
the fix for CVE-2008-1722 applied. This update includes fixes for the
problem. We apologize for the i
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- cupsys-1.3.7-1ubuntu3.1 (Ubuntu 8.04)
- cupsys-bsd-1.3.7-1ubuntu3.1 (Ubuntu 8.04)
- cupsys-client-1.3.7-1ubuntu3.1 (Ubuntu 8.04)
- cupsys-common-1.3.7-1ubuntu3.1 (Ubuntu 8.04)
- libcupsimage2-1.3.7-1ubuntu3.1 (Ubuntu 8.04)
- libcupsimage2-dev-1.3.7-1ubuntu3.1 (Ubuntu 8.04)
- libcupsys2-1.3.7-1ubuntu3.1 (Ubuntu 8.04)
- libcupsys2-dev-1.3.7-1ubuntu3.1 (Ubuntu 8.04)
- libcupsys2-gnutls10-1.2.2-0ubuntu0.6.06.11 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1722","CVE-2008-3639","CVE-2008-3640","CVE-2008-3641");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "cupsys", pkgver: "1.3.7-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to cupsys-1.3.7-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "cupsys-bsd", pkgver: "1.3.7-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-bsd-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to cupsys-bsd-1.3.7-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "cupsys-client", pkgver: "1.3.7-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-client-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to cupsys-client-1.3.7-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "cupsys-common", pkgver: "1.3.7-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-common-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to cupsys-common-1.3.7-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libcupsimage2", pkgver: "1.3.7-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsimage2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libcupsimage2-1.3.7-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libcupsimage2-dev", pkgver: "1.3.7-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsimage2-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libcupsimage2-dev-1.3.7-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libcupsys2", pkgver: "1.3.7-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsys2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libcupsys2-1.3.7-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libcupsys2-dev", pkgver: "1.3.7-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsys2-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libcupsys2-dev-1.3.7-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libcupsys2-gnutls10", pkgver: "1.2.2-0ubuntu0.6.06.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsys2-gnutls10-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libcupsys2-gnutls10-1.2.2-0ubuntu0.6.06.11
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
