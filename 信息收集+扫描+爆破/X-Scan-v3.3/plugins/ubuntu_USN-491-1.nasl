# This script was automatically generated from the 491-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28093);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "491-1");
script_summary(english:"Bind vulnerability");
script_name(english:"USN491-1 : Bind vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- bind9 
- bind9-doc 
- bind9-host 
- dnsutils 
- libbind-dev 
- libbind9-0 
- libdns21 
- libdns22 
- libisc11 
- libisccc0 
- libisccfg1 
- liblwres9 
- lwresd 
');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in Bind\'s sequence number generator.  A remote
attacker could calculate future sequence numbers and send forged DNS
query responses.  This could lead to client connections being directed
to attacker-controlled hosts, resulting in credential theft and other
attacks.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- bind9-9.3.4-2ubuntu2.1 (Ubuntu 7.04)
- bind9-doc-9.3.4-2ubuntu2.1 (Ubuntu 7.04)
- bind9-host-9.3.4-2ubuntu2.1 (Ubuntu 7.04)
- dnsutils-9.3.4-2ubuntu2.1 (Ubuntu 7.04)
- libbind-dev-9.3.4-2ubuntu2.1 (Ubuntu 7.04)
- libbind9-0-9.3.4-2ubuntu2.1 (Ubuntu 7.04)
- libdns21-9.3.2-2ubuntu3.2 (Ubuntu 6.10)
- libdns22-9.3.4-2ubuntu2.1 (Ubuntu 7.04)
- libisc11-9.3.4-2ubuntu2.1 (Ubuntu 7.04)
- libisccc0-9.3.4-2ubuntu2.1 (Ubuntu 7.04)
- libisccfg1-9.3.4-2ubuntu2.1 (Ubuntu 7.04)
- liblwres9-9.3.4-2ubuntu2.
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:N/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2007-2926");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "bind9", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to bind9-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "bind9-doc", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-doc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to bind9-doc-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "bind9-host", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-host-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to bind9-host-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "dnsutils", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dnsutils-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to dnsutils-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libbind-dev", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbind-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libbind-dev-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libbind9-0", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbind9-0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libbind9-0-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libdns21", pkgver: "9.3.2-2ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns21-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libdns21-9.3.2-2ubuntu3.2
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libdns22", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns22-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libdns22-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libisc11", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisc11-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libisc11-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libisccc0", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccc0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libisccc0-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libisccfg1", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccfg1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libisccfg1-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "liblwres9", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblwres9-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to liblwres9-9.3.4-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "lwresd", pkgver: "9.3.4-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lwresd-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to lwresd-9.3.4-2ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
