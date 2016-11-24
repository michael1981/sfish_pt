# This script was automatically generated from the 456-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28054);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "456-1");
script_summary(english:"net-snmp vulnerability");
script_name(english:"USN456-1 : net-snmp vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libsnmp-base 
- libsnmp-perl 
- libsnmp9 
- libsnmp9-dev 
- snmp 
- snmpd 
- tkmib 
');
script_set_attribute(attribute:'description', value: 'The SNMP service did not correctly handle TCP disconnects.  Remote 
subagents could cause a denial of service if they dropped a connection 
at a specific time.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libsnmp-base-5.2.1.2-4ubuntu2.1 (Ubuntu 6.06)
- libsnmp-perl-5.2.1.2-4ubuntu2.1 (Ubuntu 6.06)
- libsnmp9-5.2.1.2-4ubuntu2.1 (Ubuntu 6.06)
- libsnmp9-dev-5.2.1.2-4ubuntu2.1 (Ubuntu 6.06)
- snmp-5.2.1.2-4ubuntu2.1 (Ubuntu 6.06)
- snmpd-5.2.1.2-4ubuntu2.1 (Ubuntu 6.06)
- tkmib-5.2.1.2-4ubuntu2.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2005-4837");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libsnmp-base", pkgver: "5.2.1.2-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp-base-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsnmp-base-5.2.1.2-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsnmp-perl", pkgver: "5.2.1.2-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp-perl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsnmp-perl-5.2.1.2-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsnmp9", pkgver: "5.2.1.2-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp9-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsnmp9-5.2.1.2-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsnmp9-dev", pkgver: "5.2.1.2-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp9-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsnmp9-dev-5.2.1.2-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "snmp", pkgver: "5.2.1.2-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package snmp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to snmp-5.2.1.2-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "snmpd", pkgver: "5.2.1.2-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package snmpd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to snmpd-5.2.1.2-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "tkmib", pkgver: "5.2.1.2-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tkmib-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to tkmib-5.2.1.2-4ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
