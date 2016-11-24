# This script was automatically generated from the 204-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20620);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "204-1");
script_summary(english:"openssl vulnerability");
script_name(english:"USN204-1 : openssl vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libssl-dev 
- libssl0.9.7 
- openssl 
');
script_set_attribute(attribute:'description', value: 'Yutaka Oiwa discovered a possible cryptographic weakness in OpenSSL
applications. Applications using the OpenSSL library can use the
SSL_OP_MSIE_SSLV2_RSA_PADDING option (or SSL_OP_ALL, which implies the
former) to maintain compatibility with third party products, which is
achieved by working around known bugs in them.

The SSL_OP_MSIE_SSLV2_RSA_PADDING option disabled a verification step
in the SSL 2.0 server supposed to prevent active protocol-version
rollback attacks.  With this verification step disabled, an attacker
acting as a "man in the middle" could force a client and a server to
negotiate the SSL 2.0 protocol even if these parties both supported
SSL 3.0 or TLS 1.0.  The SSL 2.0 protocol is known to have severe
cryptographic weaknesses and is supported as a fallback only.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libssl-dev-0.9.7g-1ubuntu1.1 (Ubuntu 5.10)
- libssl0.9.7-0.9.7g-1ubuntu1.1 (Ubuntu 5.10)
- openssl-0.9.7g-1ubuntu1.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2005-2969");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libssl-dev", pkgver: "0.9.7g-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libssl-dev-0.9.7g-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libssl0.9.7", pkgver: "0.9.7g-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.7-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libssl0.9.7-0.9.7g-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "openssl", pkgver: "0.9.7g-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to openssl-0.9.7g-1ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
