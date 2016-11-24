# This script was automatically generated from the 343-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27922);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "343-1");
script_summary(english:"bind9 vulnerabilities");
script_name(english:"USN343-1 : bind9 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- bind9 
- bind9-doc 
- bind9-host 
- dnsutils 
- libbind-dev 
- libbind9-0 
- libdns16 
- libdns20 
- libdns21 
- libisc11 
- libisc7 
- libisc9 
- libisccc0 
- libisccfg0 
- libisccfg1 
- liblwres1 
- liblwres9 
- lwresd 
');
script_set_attribute(attribute:'description', value: 'bind did not sufficiently verify particular requests and responses
from other name servers and users. By sending a specially crafted
packet, a remote attacker could exploit this to crash the name server.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- bind9-9.3.2-2ubuntu1.1 (Ubuntu 6.06)
- bind9-doc-9.3.2-2ubuntu1.1 (Ubuntu 6.06)
- bind9-host-9.3.2-2ubuntu1.1 (Ubuntu 6.06)
- dnsutils-9.3.2-2ubuntu1.1 (Ubuntu 6.06)
- libbind-dev-9.3.2-2ubuntu1.1 (Ubuntu 6.06)
- libbind9-0-9.3.2-2ubuntu1.1 (Ubuntu 6.06)
- libdns16-9.2.4-1ubuntu1.1 (Ubuntu 5.04)
- libdns20-9.3.1-2ubuntu1.1 (Ubuntu 5.10)
- libdns21-9.3.2-2ubuntu1.1 (Ubuntu 6.06)
- libisc11-9.3.2-2ubuntu1.1 (Ubuntu 6.06)
- libisc7-9.2.4-1ubuntu1.1 (Ubuntu 5.04)
- libisc9-9.3.1-2ubuntu1.1 (Ubu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4095","CVE-2006-4096");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "bind9", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to bind9-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "bind9-doc", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to bind9-doc-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "bind9-host", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-host-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to bind9-host-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "dnsutils", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dnsutils-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to dnsutils-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libbind-dev", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbind-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libbind-dev-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libbind9-0", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbind9-0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libbind9-0-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libdns16", pkgver: "9.2.4-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns16-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libdns16-9.2.4-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libdns20", pkgver: "9.3.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns20-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libdns20-9.3.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdns21", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns21-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdns21-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libisc11", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisc11-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libisc11-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libisc7", pkgver: "9.2.4-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisc7-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libisc7-9.2.4-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libisc9", pkgver: "9.3.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisc9-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libisc9-9.3.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libisccc0", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccc0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libisccc0-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libisccfg0", pkgver: "9.2.4-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccfg0-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libisccfg0-9.2.4-1ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libisccfg1", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccfg1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libisccfg1-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "liblwres1", pkgver: "9.3.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblwres1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to liblwres1-9.3.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "liblwres9", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblwres9-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to liblwres9-9.3.2-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "lwresd", pkgver: "9.3.2-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lwresd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to lwresd-9.3.2-2ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
