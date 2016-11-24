# This script was automatically generated from the 809-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40656);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "809-1");
script_summary(english:"gnutls12, gnutls13, gnutls26 vulnerabilities");
script_name(english:"USN809-1 : gnutls12, gnutls13, gnutls26 vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'Moxie Marlinspike and Dan Kaminsky independently discovered that GnuTLS did
not properly handle certificates with NULL characters in the certificate
name. An attacker could exploit this to perform a man in the middle attack
to view sensitive information or alter encrypted communications.
(CVE-2009-2730)

Dan Kaminsky discovered GnuTLS would still accept certificates with MD2
hash signatures. As a result, an attacker could potentially create a
malicious trusted certificate to impersonate another site. This issue only
affected Ubuntu 6.06 LTS and Ubuntu 8.10. (CVE-2009-2409)

USN-678-1 fixed a vulnerability and USN-678-2 a regression in GnuTLS. The
 upstream patches introduced a regression when validating certain certificate
 chains that would report valid certificates as untrusted. This update
 fixes the problem, and only affected Ubuntu 6.06 LTS and Ubuntu 8.10 (Ubuntu
 8.04 LTS and 9.04 were fixed at an earlier date). In an effort to maintain a
 strong security stance and address all known regressions, this
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnutls-bin-2.4.2-6ubuntu0.1 (Ubuntu 9.04)
- gnutls-doc-2.4.2-6ubuntu0.1 (Ubuntu 9.04)
- guile-gnutls-2.4.2-6ubuntu0.1 (Ubuntu 9.04)
- libgnutls-dev-2.4.2-6ubuntu0.1 (Ubuntu 9.04)
- libgnutls12-1.2.9-2ubuntu1.7 (Ubuntu 6.06)
- libgnutls12-dbg-1.2.9-2ubuntu1.7 (Ubuntu 6.06)
- libgnutls13-2.0.4-1ubuntu2.6 (Ubuntu 8.04)
- libgnutls13-dbg-2.0.4-1ubuntu2.6 (Ubuntu 8.04)
- libgnutls26-2.4.2-6ubuntu0.1 (Ubuntu 9.04)
- libgnutls26-dbg-2.4.2-6ubuntu0.1 (Ubuntu 9.04)
- libgnutlsxx13-2.0.4-1ubuntu2.6 (
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-4989","CVE-2009-2409","CVE-2009-2730");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "gnutls-bin", pkgver: "2.4.2-6ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnutls-bin-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to gnutls-bin-2.4.2-6ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "gnutls-doc", pkgver: "2.4.2-6ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnutls-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to gnutls-doc-2.4.2-6ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "guile-gnutls", pkgver: "2.4.2-6ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package guile-gnutls-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to guile-gnutls-2.4.2-6ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libgnutls-dev", pkgver: "2.4.2-6ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libgnutls-dev-2.4.2-6ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls12", pkgver: "1.2.9-2ubuntu1.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls12-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls12-1.2.9-2ubuntu1.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls12-dbg", pkgver: "1.2.9-2ubuntu1.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls12-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls12-dbg-1.2.9-2ubuntu1.7
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgnutls13", pkgver: "2.0.4-1ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls13-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgnutls13-2.0.4-1ubuntu2.6
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgnutls13-dbg", pkgver: "2.0.4-1ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls13-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgnutls13-dbg-2.0.4-1ubuntu2.6
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libgnutls26", pkgver: "2.4.2-6ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls26-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libgnutls26-2.4.2-6ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libgnutls26-dbg", pkgver: "2.4.2-6ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls26-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libgnutls26-dbg-2.4.2-6ubuntu0.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgnutlsxx13", pkgver: "2.0.4-1ubuntu2.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutlsxx13-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgnutlsxx13-2.0.4-1ubuntu2.6
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
