# This script was automatically generated from the 348-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27928);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "348-1");
script_summary(english:"GnuTLS vulnerability");
script_name(english:"USN348-1 : GnuTLS vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gnutls-bin 
- libgnutls-dev 
- libgnutls11 
- libgnutls11-dbg 
- libgnutls11-dev 
- libgnutls12 
- libgnutls12-dbg 
');
script_set_attribute(attribute:'description', value: 'The GnuTLS library did not sufficiently check the padding of PKCS #1
v1.5 signatures if the exponent of the public key is 3 (which is
widely used for CAs). This could be exploited to forge signatures
without the need of the secret key.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnutls-bin-1.2.9-2ubuntu1.1 (Ubuntu 6.06)
- libgnutls-dev-1.2.9-2ubuntu1.1 (Ubuntu 6.06)
- libgnutls11-1.0.16-14ubuntu1.1 (Ubuntu 6.06)
- libgnutls11-dbg-1.0.16-14ubuntu1.1 (Ubuntu 6.06)
- libgnutls11-dev-1.0.16-14ubuntu1.1 (Ubuntu 6.06)
- libgnutls12-1.2.9-2ubuntu1.1 (Ubuntu 6.06)
- libgnutls12-dbg-1.2.9-2ubuntu1.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2006-4790");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "gnutls-bin", pkgver: "1.2.9-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnutls-bin-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gnutls-bin-1.2.9-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls-dev", pkgver: "1.2.9-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls-dev-1.2.9-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls11", pkgver: "1.0.16-14ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls11-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls11-1.0.16-14ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls11-dbg", pkgver: "1.0.16-14ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls11-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls11-dbg-1.0.16-14ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls11-dev", pkgver: "1.0.16-14ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls11-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls11-dev-1.0.16-14ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls12", pkgver: "1.2.9-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls12-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls12-1.2.9-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgnutls12-dbg", pkgver: "1.2.9-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgnutls12-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgnutls12-dbg-1.2.9-2ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
