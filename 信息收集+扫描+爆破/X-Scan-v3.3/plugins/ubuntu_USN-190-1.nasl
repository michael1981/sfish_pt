# This script was automatically generated from the 190-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20603);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "190-1");
script_summary(english:"net-snmp vulnerability");
script_name(english:"USN190-1 : net-snmp vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libsnmp-base 
- libsnmp-perl 
- libsnmp5 
- libsnmp5-dev 
- snmp 
- snmpd 
- tkmib 
');
script_set_attribute(attribute:'description', value: 'A remote Denial of Service has been discovered in the SMNP (Simple
Network Management Protocol) library. If a SNMP agent uses TCP sockets
for communication, a malicious SNMP server could exploit this to crash
the agent. Please note that by default SNMP uses UDP sockets.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libsnmp-base-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- libsnmp-perl-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- libsnmp5-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- libsnmp5-dev-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- snmp-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- snmpd-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
- tkmib-5.1.2-6ubuntu2.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2005-2177");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "libsnmp-base", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp-base-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsnmp-base-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libsnmp-perl", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp-perl-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsnmp-perl-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libsnmp5", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp5-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsnmp5-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libsnmp5-dev", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp5-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libsnmp5-dev-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "snmp", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package snmp-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to snmp-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "snmpd", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package snmpd-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to snmpd-5.1.2-6ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "tkmib", pkgver: "5.1.2-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tkmib-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to tkmib-5.1.2-6ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
