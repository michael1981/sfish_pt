# This script was automatically generated from the 835-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(41046);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "835-1");
script_summary(english:"neon, neon27 vulnerabilities");
script_name(english:"USN835-1 : neon, neon27 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libneon25 
- libneon25-dbg 
- libneon25-dev 
- libneon27 
- libneon27-dbg 
- libneon27-dev 
- libneon27-gnutls 
- libneon27-gnutls-dbg 
- libneon27-gnutls-dev 
');
script_set_attribute(attribute:'description', value: 'Joe Orton discovered that neon did not correctly handle SSL certificates
with zero bytes in the Common Name.  A remote attacker could exploit this
to perform a man in the middle attack to view sensitive information or
alter encrypted communications.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libneon25-0.25.5.dfsg-5ubuntu0.1 (Ubuntu 6.06)
- libneon25-dbg-0.25.5.dfsg-5ubuntu0.1 (Ubuntu 6.06)
- libneon25-dev-0.28.2-6.1ubuntu0.1 (Ubuntu 9.04)
- libneon27-0.28.2-6.1ubuntu0.1 (Ubuntu 9.04)
- libneon27-dbg-0.28.2-6.1ubuntu0.1 (Ubuntu 9.04)
- libneon27-dev-0.28.2-6.1ubuntu0.1 (Ubuntu 9.04)
- libneon27-gnutls-0.28.2-6.1ubuntu0.1 (Ubuntu 9.04)
- libneon27-gnutls-dbg-0.28.2-6.1ubuntu0.1 (Ubuntu 9.04)
- libneon27-gnutls-dev-0.28.2-6.1ubuntu0.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-3746","CVE-2009-2474");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libneon25", pkgver: "0.25.5.dfsg-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libneon25-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libneon25-0.25.5.dfsg-5ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libneon25-dbg", pkgver: "0.25.5.dfsg-5ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libneon25-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libneon25-dbg-0.25.5.dfsg-5ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libneon25-dev", pkgver: "0.28.2-6.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libneon25-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libneon25-dev-0.28.2-6.1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libneon27", pkgver: "0.28.2-6.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libneon27-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libneon27-0.28.2-6.1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libneon27-dbg", pkgver: "0.28.2-6.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libneon27-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libneon27-dbg-0.28.2-6.1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libneon27-dev", pkgver: "0.28.2-6.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libneon27-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libneon27-dev-0.28.2-6.1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libneon27-gnutls", pkgver: "0.28.2-6.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libneon27-gnutls-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libneon27-gnutls-0.28.2-6.1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libneon27-gnutls-dbg", pkgver: "0.28.2-6.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libneon27-gnutls-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libneon27-gnutls-dbg-0.28.2-6.1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libneon27-gnutls-dev", pkgver: "0.28.2-6.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libneon27-gnutls-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libneon27-gnutls-dev-0.28.2-6.1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
