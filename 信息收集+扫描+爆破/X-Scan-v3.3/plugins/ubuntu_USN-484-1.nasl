# This script was automatically generated from the 484-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28085);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "484-1");
script_summary(english:"curl vulnerability");
script_name(english:"USN484-1 : curl vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- curl 
- libcurl3 
- libcurl3-dbg 
- libcurl3-dev 
- libcurl3-gnutls 
- libcurl3-gnutls-dev 
- libcurl3-openssl-dev 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the GnuTLS certificate verification methods
implemented in Curl did not check for expiration and activation dates.
When performing validations, tools using libcurl3-gnutls would
incorrectly allow connections to sites using expired certificates.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- curl-7.15.5-1ubuntu2.1 (Ubuntu 7.04)
- libcurl3-7.15.5-1ubuntu2.1 (Ubuntu 7.04)
- libcurl3-dbg-7.15.5-1ubuntu2.1 (Ubuntu 7.04)
- libcurl3-dev-7.15.5-1ubuntu2.1 (Ubuntu 7.04)
- libcurl3-gnutls-7.15.5-1ubuntu2.1 (Ubuntu 7.04)
- libcurl3-gnutls-dev-7.15.5-1ubuntu2.1 (Ubuntu 7.04)
- libcurl3-openssl-dev-7.15.5-1ubuntu2.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-3564");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "curl", pkgver: "7.15.5-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package curl-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to curl-7.15.5-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libcurl3", pkgver: "7.15.5-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcurl3-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libcurl3-7.15.5-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libcurl3-dbg", pkgver: "7.15.5-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcurl3-dbg-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libcurl3-dbg-7.15.5-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libcurl3-dev", pkgver: "7.15.5-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcurl3-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libcurl3-dev-7.15.5-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libcurl3-gnutls", pkgver: "7.15.5-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcurl3-gnutls-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libcurl3-gnutls-7.15.5-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libcurl3-gnutls-dev", pkgver: "7.15.5-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcurl3-gnutls-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libcurl3-gnutls-dev-7.15.5-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libcurl3-openssl-dev", pkgver: "7.15.5-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcurl3-openssl-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libcurl3-openssl-dev-7.15.5-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
