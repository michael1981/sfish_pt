# This script was automatically generated from the 622-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33464);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "622-1");
script_summary(english:"Bind vulnerability");
script_name(english:"USN622-1 : Bind vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- bind9 
- bind9-doc 
- bind9-host 
- dnsutils 
- libbind-dev 
- libbind9-0 
- libbind9-30 
- libdns21 
- libdns22 
- libdns32 
- libdns35 
- libisc11 
- libisc32 
- libisccc0 
- libisccc30 
- libisccfg1 
- libisccfg30 
- liblwres30 
- liblwres9 
- lwresd 
');
script_set_attribute(attribute:'description', value: 'Dan Kaminsky discovered weaknesses in the DNS protocol as implemented
by Bind.  A remote attacker could exploit this to spoof DNS entries and
poison DNS caches. Among other things, this could lead to misdirected
email and web traffic.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- bind9-9.4.2-10ubuntu0.1 (Ubuntu 8.04)
- bind9-doc-9.4.2-10ubuntu0.1 (Ubuntu 8.04)
- bind9-host-9.4.2-10ubuntu0.1 (Ubuntu 8.04)
- dnsutils-9.4.2-10ubuntu0.1 (Ubuntu 8.04)
- libbind-dev-9.4.2-10ubuntu0.1 (Ubuntu 8.04)
- libbind9-0-9.3.4-2ubuntu2.3 (Ubuntu 7.04)
- libbind9-30-9.4.2-10ubuntu0.1 (Ubuntu 8.04)
- libdns21-9.3.2-2ubuntu1.5 (Ubuntu 6.06)
- libdns22-9.3.4-2ubuntu2.3 (Ubuntu 7.04)
- libdns32-9.4.1-P1-3ubuntu2 (Ubuntu 7.10)
- libdns35-9.4.2-10ubuntu0.1 (Ubuntu 8.04)
- libisc11-9.3.4-2u
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-1447");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "bind9", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to bind9-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "bind9-doc", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to bind9-doc-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "bind9-host", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-host-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to bind9-host-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "dnsutils", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dnsutils-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to dnsutils-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libbind-dev", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbind-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libbind-dev-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libbind9-0", pkgver: "9.3.4-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbind9-0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libbind9-0-9.3.4-2ubuntu2.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libbind9-30", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbind9-30-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libbind9-30-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libdns21", pkgver: "9.3.2-2ubuntu1.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns21-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libdns21-9.3.2-2ubuntu1.5
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libdns22", pkgver: "9.3.4-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns22-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libdns22-9.3.4-2ubuntu2.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libdns32", pkgver: "9.4.1-P1-3ubuntu2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns32-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libdns32-9.4.1-P1-3ubuntu2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libdns35", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns35-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libdns35-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libisc11", pkgver: "9.3.4-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisc11-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libisc11-9.3.4-2ubuntu2.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libisc32", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisc32-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libisc32-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libisccc0", pkgver: "9.3.4-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccc0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libisccc0-9.3.4-2ubuntu2.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libisccc30", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccc30-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libisccc30-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libisccfg1", pkgver: "9.3.4-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccfg1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libisccfg1-9.3.4-2ubuntu2.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libisccfg30", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccfg30-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libisccfg30-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "liblwres30", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblwres30-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to liblwres30-9.4.2-10ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "liblwres9", pkgver: "9.3.4-2ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblwres9-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to liblwres9-9.3.4-2ubuntu2.3
');
}
found = ubuntu_check(osver: "8.04", pkgname: "lwresd", pkgver: "9.4.2-10ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lwresd-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to lwresd-9.4.2-10ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
