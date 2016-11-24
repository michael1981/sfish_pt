# This script was automatically generated from the 522-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28127);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "522-1");
script_summary(english:"OpenSSL vulnerabilities");
script_name(english:"USN522-1 : OpenSSL vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libssl-dev 
- libssl0.9.8 
- libssl0.9.8-dbg 
- openssl 
');
script_set_attribute(attribute:'description', value: 'It was discovered that OpenSSL did not correctly perform Montgomery
multiplications.  Local attackers might be able to reconstruct RSA
private keys by examining another user\'s OpenSSL processes. (CVE-2007-3108)

Moritz Jodeit discovered that OpenSSL\'s SSL_get_shared_ciphers function
did not correctly check the size of the buffer it was writing to.
A remote attacker could exploit this to write one NULL byte past the end of
an application\'s cipher list buffer, possibly leading to arbitrary code
execution or a denial of service. (CVE-2007-5135)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libssl-dev-0.9.8c-4ubuntu0.1 (Ubuntu 7.04)
- libssl0.9.8-0.9.8c-4ubuntu0.1 (Ubuntu 7.04)
- libssl0.9.8-dbg-0.9.8c-4ubuntu0.1 (Ubuntu 7.04)
- openssl-0.9.8c-4ubuntu0.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-3108","CVE-2007-5135");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libssl-dev", pkgver: "0.9.8c-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libssl-dev-0.9.8c-4ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libssl0.9.8", pkgver: "0.9.8c-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libssl0.9.8-0.9.8c-4ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libssl0.9.8-dbg", pkgver: "0.9.8c-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-dbg-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libssl0.9.8-dbg-0.9.8c-4ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "openssl", pkgver: "0.9.8c-4ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to openssl-0.9.8c-4ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
