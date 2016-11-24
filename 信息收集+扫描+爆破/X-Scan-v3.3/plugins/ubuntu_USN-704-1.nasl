# This script was automatically generated from the 704-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36382);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "704-1");
script_summary(english:"openssl vulnerability");
script_name(english:"USN704-1 : openssl vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libssl-dev 
- libssl0.9.8 
- libssl0.9.8-dbg 
- openssl 
- openssl-doc 
');
script_set_attribute(attribute:'description', value: 'It was discovered that OpenSSL did not properly perform signature verification
on DSA and ECDSA keys. If user or automated system connected to a malicious
server or a remote attacker were able to perform a man-in-the-middle attack,
this flaw could be exploited to view sensitive information.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libssl-dev-0.9.8g-10.1ubuntu2.1 (Ubuntu 8.10)
- libssl0.9.8-0.9.8g-10.1ubuntu2.1 (Ubuntu 8.10)
- libssl0.9.8-dbg-0.9.8g-10.1ubuntu2.1 (Ubuntu 8.10)
- openssl-0.9.8g-10.1ubuntu2.1 (Ubuntu 8.10)
- openssl-doc-0.9.8g-10.1ubuntu2.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-5077");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libssl-dev", pkgver: "0.9.8g-10.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libssl-dev-0.9.8g-10.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libssl0.9.8", pkgver: "0.9.8g-10.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libssl0.9.8-0.9.8g-10.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libssl0.9.8-dbg", pkgver: "0.9.8g-10.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libssl0.9.8-dbg-0.9.8g-10.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openssl", pkgver: "0.9.8g-10.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openssl-0.9.8g-10.1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "openssl-doc", pkgver: "0.9.8g-10.1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to openssl-doc-0.9.8g-10.1ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
