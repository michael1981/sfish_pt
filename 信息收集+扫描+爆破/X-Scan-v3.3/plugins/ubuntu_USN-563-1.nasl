# This script was automatically generated from the 563-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29919);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "563-1");
script_summary(english:"CUPS vulnerabilities");
script_name(english:"USN563-1 : CUPS vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'Wei Wang discovered that the SNMP discovery backend did not correctly
calculate the length of strings.  If a user were tricked into scanning
for printers, a remote attacker could send a specially crafted packet
and possibly execute arbitrary code.

Elias Pipping discovered that temporary files were not handled safely
in certain situations when converting PDF to PS.  A local attacker could
cause a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- cupsys-1.3.2-1ubuntu7.3 (Ubuntu 7.10)
- cupsys-bsd-1.3.2-1ubuntu7.3 (Ubuntu 7.10)
- cupsys-client-1.3.2-1ubuntu7.3 (Ubuntu 7.10)
- cupsys-common-1.3.2-1ubuntu7.3 (Ubuntu 7.10)
- libcupsimage2-1.3.2-1ubuntu7.3 (Ubuntu 7.10)
- libcupsimage2-dev-1.3.2-1ubuntu7.3 (Ubuntu 7.10)
- libcupsys2-1.3.2-1ubuntu7.3 (Ubuntu 7.10)
- libcupsys2-dev-1.3.2-1ubuntu7.3 (Ubuntu 7.10)
- libcupsys2-gnutls10-1.2.2-0ubuntu0.6.06.6 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-5849","CVE-2007-6358");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "cupsys", pkgver: "1.3.2-1ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to cupsys-1.3.2-1ubuntu7.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "cupsys-bsd", pkgver: "1.3.2-1ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-bsd-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to cupsys-bsd-1.3.2-1ubuntu7.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "cupsys-client", pkgver: "1.3.2-1ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-client-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to cupsys-client-1.3.2-1ubuntu7.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "cupsys-common", pkgver: "1.3.2-1ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package cupsys-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to cupsys-common-1.3.2-1ubuntu7.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcupsimage2", pkgver: "1.3.2-1ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsimage2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcupsimage2-1.3.2-1ubuntu7.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcupsimage2-dev", pkgver: "1.3.2-1ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsimage2-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcupsimage2-dev-1.3.2-1ubuntu7.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcupsys2", pkgver: "1.3.2-1ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsys2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcupsys2-1.3.2-1ubuntu7.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libcupsys2-dev", pkgver: "1.3.2-1ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsys2-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libcupsys2-dev-1.3.2-1ubuntu7.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libcupsys2-gnutls10", pkgver: "1.2.2-0ubuntu0.6.06.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcupsys2-gnutls10-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libcupsys2-gnutls10-1.2.2-0ubuntu0.6.06.6
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
