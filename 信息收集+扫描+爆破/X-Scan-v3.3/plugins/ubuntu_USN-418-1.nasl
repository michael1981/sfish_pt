# This script was automatically generated from the 418-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28010);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "418-1");
script_summary(english:"Bind vulnerabilities");
script_name(english:"USN418-1 : Bind vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- bind9 
- bind9-doc 
- bind9-host 
- dnsutils 
- libbind-dev 
- libbind9-0 
- libdns20 
- libdns21 
- libisc11 
- libisc9 
- libisccc0 
- libisccfg1 
- liblwres1 
- liblwres9 
- lwresd 
');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in Bind\'s DNSSEC validation code.  Remote 
attackers could send a specially crafted DNS query which would cause the 
Bind server to crash, resulting in a denial of service.  Only servers 
configured to use DNSSEC extensions were vulnerable.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- bind9-9.3.2-2ubuntu3.1 (Ubuntu 6.10)
- bind9-doc-9.3.2-2ubuntu3.1 (Ubuntu 6.10)
- bind9-host-9.3.2-2ubuntu3.1 (Ubuntu 6.10)
- dnsutils-9.3.2-2ubuntu3.1 (Ubuntu 6.10)
- libbind-dev-9.3.2-2ubuntu3.1 (Ubuntu 6.10)
- libbind9-0-9.3.2-2ubuntu3.1 (Ubuntu 6.10)
- libdns20-9.3.1-2ubuntu1.2 (Ubuntu 5.10)
- libdns21-9.3.2-2ubuntu3.1 (Ubuntu 6.10)
- libisc11-9.3.2-2ubuntu3.1 (Ubuntu 6.10)
- libisc9-9.3.1-2ubuntu1.2 (Ubuntu 5.10)
- libisccc0-9.3.2-2ubuntu3.1 (Ubuntu 6.10)
- libisccfg1-9.3.2-2ubuntu3.1 
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2007-0493","CVE-2007-0494");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "bind9", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to bind9-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "bind9-doc", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-doc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to bind9-doc-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "bind9-host", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bind9-host-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to bind9-host-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "dnsutils", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dnsutils-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to dnsutils-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libbind-dev", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbind-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libbind-dev-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libbind9-0", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libbind9-0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libbind9-0-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libdns20", pkgver: "9.3.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns20-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libdns20-9.3.1-2ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libdns21", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdns21-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libdns21-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libisc11", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisc11-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libisc11-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libisc9", pkgver: "9.3.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisc9-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libisc9-9.3.1-2ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libisccc0", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccc0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libisccc0-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libisccfg1", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libisccfg1-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libisccfg1-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "liblwres1", pkgver: "9.3.1-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblwres1-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to liblwres1-9.3.1-2ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "liblwres9", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblwres9-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to liblwres9-9.3.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "lwresd", pkgver: "9.3.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package lwresd-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to lwresd-9.3.2-2ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
