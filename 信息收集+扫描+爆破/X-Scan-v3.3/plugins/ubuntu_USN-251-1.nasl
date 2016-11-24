# This script was automatically generated from the 251-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21060);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "251-1");
script_summary(english:"libtasn1-2 vulnerability");
script_name(english:"USN251-1 : libtasn1-2 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gnutls-bin 
- libgnutls-doc 
- libgnutls10 
- libgnutls10-dev 
- libgnutls11 
- libgnutls11-dbg 
- libgnutls11-dev 
- libtasn1-2 
- libtasn1-2-dev 
');
script_set_attribute(attribute:'description', value: 'Evgeny Legerov discovered a buffer overflow in the DER format decoding
function of the libtasn library. This library is mainly used by the
GNU TLS library; by sending a specially crafted X.509 certificate to a
server which uses TLS encryption/authentication, a remote attacker
could exploit this to crash that server process and possibly even
execute arbitrary code with the privileges of that server.

In order to fix the vulnerability in libtasn, several internal
function signatures had to be changed; some of these functions are
used by the GNU TLS library, so that library needs to be updated as
well.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnutls-bin-1.0.16-13.1ubuntu1.1 (Ubuntu 5.10)
- libgnutls-doc-1.0.4-3ubuntu1.2 (Ubuntu 4.10)
- libgnutls10-1.0.4-3ubuntu1.2 (Ubuntu 4.10)
- libgnutls10-dev-1.0.4-3ubuntu1.2 (Ubuntu 4.10)
- libgnutls11-1.0.16-13.1ubuntu1.1 (Ubuntu 5.10)
- libgnutls11-dbg-1.0.16-13.1ubuntu1.1 (Ubuntu 5.10)
- libgnutls11-dev-1.0.16-13.1ubuntu1.1 (Ubuntu 5.10)
- libtasn1-2-0.2.10-4ubuntu0.1 (Ubuntu 5.10)
- libtasn1-2-dev-0.2.10-4ubuntu0.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-0645");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "gnutls-bin", pkgver: "1.0.16-13.1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnutls-bin-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gnutls-bin-1.0.16-13.1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgnutls-doc", pkgver: "1.0.4-3ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgnutls-doc-1.0.4-3ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgnutls10", pkgver: "1.0.4-3ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls10-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgnutls10-1.0.4-3ubuntu1.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgnutls10-dev", pkgver: "1.0.4-3ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls10-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgnutls10-dev-1.0.4-3ubuntu1.2
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgnutls11", pkgver: "1.0.16-13.1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls11-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgnutls11-1.0.16-13.1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgnutls11-dbg", pkgver: "1.0.16-13.1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls11-dbg-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgnutls11-dbg-1.0.16-13.1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libgnutls11-dev", pkgver: "1.0.16-13.1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls11-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libgnutls11-dev-1.0.16-13.1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libtasn1-2", pkgver: "0.2.10-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtasn1-2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libtasn1-2-0.2.10-4ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libtasn1-2-dev", pkgver: "0.2.10-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtasn1-2-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libtasn1-2-dev-0.2.10-4ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
