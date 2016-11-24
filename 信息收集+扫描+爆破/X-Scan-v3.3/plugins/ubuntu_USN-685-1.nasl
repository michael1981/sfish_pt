# This script was automatically generated from the 685-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38099);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "685-1");
script_summary(english:"net-snmp vulnerabilities");
script_name(english:"USN685-1 : net-snmp vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libsnmp-base 
- libsnmp-dev 
- libsnmp-perl 
- libsnmp10 
- libsnmp9 
- libsnmp9-dev 
- snmp 
- snmpd 
- tkmib 
');
script_set_attribute(attribute:'description', value: 'Wes Hardaker discovered that the SNMP service did not correctly validate
HMAC authentication requests.  An unauthenticated remote attacker
could send specially crafted SNMPv3 traffic with a valid username
and gain access to the user\'s views without a valid authentication
passphrase. (CVE-2008-0960)

John Kortink discovered that the Net-SNMP Perl module did not correctly
check the size of returned values.  If a user or automated system were
tricked into querying a malicious SNMP server, the application using
the Perl module could be made to crash, leading to a denial of service.
This did not affect Ubuntu 8.10. (CVE-2008-2292)

It was discovered that the SNMP service did not correctly handle large
GETBULK requests.  If an unauthenticated remote attacker sent a specially
crafted request, the SNMP service could be made to crash, leading to a
denial of service. (CVE-2008-4309)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libsnmp-base-5.3.1-6ubuntu2.2 (Ubuntu 7.10)
- libsnmp-dev-5.3.1-6ubuntu2.2 (Ubuntu 7.10)
- libsnmp-perl-5.3.1-6ubuntu2.2 (Ubuntu 7.10)
- libsnmp10-5.3.1-6ubuntu2.2 (Ubuntu 7.10)
- libsnmp9-5.2.1.2-4ubuntu2.3 (Ubuntu 6.06)
- libsnmp9-dev-5.2.1.2-4ubuntu2.3 (Ubuntu 6.06)
- snmp-5.3.1-6ubuntu2.2 (Ubuntu 7.10)
- snmpd-5.3.1-6ubuntu2.2 (Ubuntu 7.10)
- tkmib-5.3.1-6ubuntu2.2 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-0960","CVE-2008-2292","CVE-2008-4309");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libsnmp-base", pkgver: "5.3.1-6ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp-base-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsnmp-base-5.3.1-6ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libsnmp-dev", pkgver: "5.3.1-6ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsnmp-dev-5.3.1-6ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libsnmp-perl", pkgver: "5.3.1-6ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp-perl-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsnmp-perl-5.3.1-6ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libsnmp10", pkgver: "5.3.1-6ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp10-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsnmp10-5.3.1-6ubuntu2.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsnmp9", pkgver: "5.2.1.2-4ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp9-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsnmp9-5.2.1.2-4ubuntu2.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsnmp9-dev", pkgver: "5.2.1.2-4ubuntu2.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp9-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsnmp9-dev-5.2.1.2-4ubuntu2.3
');
}
found = ubuntu_check(osver: "7.10", pkgname: "snmp", pkgver: "5.3.1-6ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package snmp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to snmp-5.3.1-6ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "snmpd", pkgver: "5.3.1-6ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package snmpd-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to snmpd-5.3.1-6ubuntu2.2
');
}
found = ubuntu_check(osver: "7.10", pkgname: "tkmib", pkgver: "5.3.1-6ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tkmib-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to tkmib-5.3.1-6ubuntu2.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
