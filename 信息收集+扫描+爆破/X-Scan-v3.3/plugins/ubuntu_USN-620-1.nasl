# This script was automatically generated from the 620-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33389);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "620-1");
script_summary(english:"OpenSSL vulnerabilities");
script_name(english:"USN620-1 : OpenSSL vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libssl-dev 
- libssl0.9.8 
- libssl0.9.8-dbg 
- openssl 
- openssl-doc 
');
script_set_attribute(attribute:'description', value: 'It was discovered that OpenSSL was vulnerable to a double-free
when using TLS server extensions. A remote attacker could send a
crafted packet and cause a denial of service via application crash
in applications linked against OpenSSL. Ubuntu 8.04 LTS does not
compile TLS server extensions by default. (CVE-2008-0891)

It was discovered that OpenSSL could dereference a NULL pointer.
If a user or automated system were tricked into connecting to a
malicious server with particular cipher suites, a remote attacker
could cause a denial of service via application crash.
(CVE-2008-1672)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libssl-dev-0.9.8g-4ubuntu3.3 (Ubuntu 8.04)
- libssl0.9.8-0.9.8g-4ubuntu3.3 (Ubuntu 8.04)
- libssl0.9.8-dbg-0.9.8g-4ubuntu3.3 (Ubuntu 8.04)
- openssl-0.9.8g-4ubuntu3.3 (Ubuntu 8.04)
- openssl-doc-0.9.8g-4ubuntu3.3 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2008-0891","CVE-2008-1672");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "libssl-dev", pkgver: "0.9.8g-4ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libssl-dev-0.9.8g-4ubuntu3.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libssl0.9.8", pkgver: "0.9.8g-4ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libssl0.9.8-0.9.8g-4ubuntu3.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libssl0.9.8-dbg", pkgver: "0.9.8g-4ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libssl0.9.8-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libssl0.9.8-dbg-0.9.8g-4ubuntu3.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openssl", pkgver: "0.9.8g-4ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openssl-0.9.8g-4ubuntu3.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "openssl-doc", pkgver: "0.9.8g-4ubuntu3.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package openssl-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to openssl-doc-0.9.8g-4ubuntu3.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
