# This script was automatically generated from the 678-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37045);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "678-2");
script_summary(english:"gnutls12, gnutls13, gnutls26 regression");
script_name(english:"USN678-2 : gnutls12, gnutls13, gnutls26 regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gnutls-bin 
- gnutls-doc 
- guile-gnutls 
- libgnutls-dev 
- libgnutls12 
- libgnutls12-dbg 
- libgnutls13 
- libgnutls13-dbg 
- libgnutls26 
- libgnutls26-dbg 
- libgnutlsxx13 
');
script_set_attribute(attribute:'description', value: 'USN-678-1 fixed a vulnerability in GnuTLS. The upstream patch introduced a
regression when validating certain certificate chains that would report valid
certificates as untrusted. This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 Martin von Gagern discovered that GnuTLS did not properly verify certificate
 chains when the last certificate in the chain was self-signed. If a remote
 attacker were able to perform a man-in-the-middle attack, this flaw could be
 exploited to view sensitive information. (CVE-2008-4989)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnutls-bin-2.4.1-1ubuntu0.2 (Ubuntu 8.10)
- gnutls-doc-2.4.1-1ubuntu0.2 (Ubuntu 8.10)
- guile-gnutls-2.4.1-1ubuntu0.2 (Ubuntu 8.10)
- libgnutls-dev-2.4.1-1ubuntu0.2 (Ubuntu 8.10)
- libgnutls12-1.2.9-2ubuntu1.4 (Ubuntu 6.06)
- libgnutls12-dbg-1.2.9-2ubuntu1.4 (Ubuntu 6.06)
- libgnutls13-2.0.4-1ubuntu2.3 (Ubuntu 8.04)
- libgnutls13-dbg-2.0.4-1ubuntu2.3 (Ubuntu 8.04)
- libgnutls26-2.4.1-1ubuntu0.2 (Ubuntu 8.10)
- libgnutls26-dbg-2.4.1-1ubuntu0.2 (Ubuntu 8.10)
- libgnutlsxx13-2.0.4-1ubuntu2.3 (
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2008-4989");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "gnutls-bin", pkgver: "2.4.1-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnutls-bin-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gnutls-bin-2.4.1-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "gnutls-doc", pkgver: "2.4.1-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnutls-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to gnutls-doc-2.4.1-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "guile-gnutls", pkgver: "2.4.1-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package guile-gnutls-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to guile-gnutls-2.4.1-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgnutls-dev", pkgver: "2.4.1-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgnutls-dev-2.4.1-1ubuntu0.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls12", pkgver: "1.2.9-2ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls12-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls12-1.2.9-2ubuntu1.4
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls12-dbg", pkgver: "1.2.9-2ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls12-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls12-dbg-1.2.9-2ubuntu1.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgnutls13", pkgver: "2.0.4-1ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls13-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgnutls13-2.0.4-1ubuntu2.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgnutls13-dbg", pkgver: "2.0.4-1ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls13-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgnutls13-dbg-2.0.4-1ubuntu2.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgnutls26", pkgver: "2.4.1-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls26-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgnutls26-2.4.1-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgnutls26-dbg", pkgver: "2.4.1-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls26-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgnutls26-dbg-2.4.1-1ubuntu0.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgnutlsxx13", pkgver: "2.0.4-1ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutlsxx13-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgnutlsxx13-2.0.4-1ubuntu2.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
