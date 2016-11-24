# This script was automatically generated from the 613-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32432);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "613-1");
script_summary(english:"GnuTLS vulnerabilities");
script_name(english:"USN613-1 : GnuTLS vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gnutls-bin 
- gnutls-doc 
- libgnutls-dev 
- libgnutls12 
- libgnutls12-dbg 
- libgnutls13 
- libgnutls13-dbg 
- libgnutlsxx13 
');
script_set_attribute(attribute:'description', value: 'Multiple flaws were discovered in the connection handling of GnuTLS.
A remote attacker could exploit this to crash applications linked
against GnuTLS, or possibly execute arbitrary code with permissions of
the application\'s user.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnutls-bin-2.0.4-1ubuntu2.1 (Ubuntu 8.04)
- gnutls-doc-2.0.4-1ubuntu2.1 (Ubuntu 8.04)
- libgnutls-dev-2.0.4-1ubuntu2.1 (Ubuntu 8.04)
- libgnutls12-1.2.9-2ubuntu1.2 (Ubuntu 6.06)
- libgnutls12-dbg-1.2.9-2ubuntu1.2 (Ubuntu 6.06)
- libgnutls13-2.0.4-1ubuntu2.1 (Ubuntu 8.04)
- libgnutls13-dbg-2.0.4-1ubuntu2.1 (Ubuntu 8.04)
- libgnutlsxx13-2.0.4-1ubuntu2.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1948","CVE-2008-1949","CVE-2008-1950");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "gnutls-bin", pkgver: "2.0.4-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnutls-bin-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to gnutls-bin-2.0.4-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "gnutls-doc", pkgver: "2.0.4-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnutls-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to gnutls-doc-2.0.4-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgnutls-dev", pkgver: "2.0.4-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgnutls-dev-2.0.4-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls12", pkgver: "1.2.9-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls12-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls12-1.2.9-2ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls12-dbg", pkgver: "1.2.9-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls12-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls12-dbg-1.2.9-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgnutls13", pkgver: "2.0.4-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls13-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgnutls13-2.0.4-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgnutls13-dbg", pkgver: "2.0.4-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls13-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgnutls13-dbg-2.0.4-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgnutlsxx13", pkgver: "2.0.4-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutlsxx13-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgnutlsxx13-2.0.4-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
