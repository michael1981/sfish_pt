# This script was automatically generated from the 339-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27918);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "339-1");
script_summary(english:"OpenSSL vulnerability");
script_name(english:"USN339-1 : OpenSSL vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libssl-dev 
- libssl0.9.7 
- libssl0.9.8 
- libssl0.9.8-dbg 
- openssl 
');
script_set_attribute(attribute:'description', value: 'Philip Mackenzie, Marius Schilder, Jason Waddle and Ben Laurie of
Google Security discovered that the OpenSSL library did not
sufficiently check the padding of PKCS #1 v1.5 signatures if the
exponent of the public key is 3 (which is widely used for CAs). This
could be exploited to forge signatures without the need of the secret
key.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libssl-dev-0.9.8a-7ubuntu0.1 (Ubuntu 6.06)
- libssl0.9.7-0.9.7g-1ubuntu1.2 (Ubuntu 5.10)
- libssl0.9.8-0.9.8a-7ubuntu0.1 (Ubuntu 6.06)
- libssl0.9.8-dbg-0.9.8a-7ubuntu0.1 (Ubuntu 6.06)
- openssl-0.9.8a-7ubuntu0.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4339");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libssl-dev", pkgver: "0.9.8a-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libssl-dev-0.9.8a-7ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libssl0.9.7", pkgver: "0.9.7g-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libssl0.9.7-0.9.7g-1ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libssl0.9.8", pkgver: "0.9.8a-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libssl0.9.8-0.9.8a-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libssl0.9.8-dbg", pkgver: "0.9.8a-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libssl0.9.8-dbg-0.9.8a-7ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "openssl", pkgver: "0.9.8a-7ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to openssl-0.9.8a-7ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
