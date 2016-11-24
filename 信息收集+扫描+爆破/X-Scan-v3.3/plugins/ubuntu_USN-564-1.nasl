# This script was automatically generated from the 564-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29920);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "564-1");
script_summary(english:"Net-SNMP vulnerability");
script_name(english:"USN564-1 : Net-SNMP vulnerability");
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
script_set_attribute(attribute:'description', value: 'Bill Trost discovered that snmpd did not properly limit GETBULK
requests. A remote attacker could specify a large number of
max-repetitions and cause a denial of service via resource
exhaustion.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libsnmp-base-5.3.1-6ubuntu2.1 (Ubuntu 7.10)
- libsnmp-dev-5.3.1-6ubuntu2.1 (Ubuntu 7.10)
- libsnmp-perl-5.3.1-6ubuntu2.1 (Ubuntu 7.10)
- libsnmp10-5.3.1-6ubuntu2.1 (Ubuntu 7.10)
- libsnmp9-5.2.3-4ubuntu1.1 (Ubuntu 7.04)
- libsnmp9-dev-5.2.3-4ubuntu1.1 (Ubuntu 7.04)
- snmp-5.3.1-6ubuntu2.1 (Ubuntu 7.10)
- snmpd-5.3.1-6ubuntu2.1 (Ubuntu 7.10)
- tkmib-5.3.1-6ubuntu2.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2007-5846");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libsnmp-base", pkgver: "5.3.1-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp-base-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsnmp-base-5.3.1-6ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libsnmp-dev", pkgver: "5.3.1-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsnmp-dev-5.3.1-6ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libsnmp-perl", pkgver: "5.3.1-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp-perl-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsnmp-perl-5.3.1-6ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libsnmp10", pkgver: "5.3.1-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp10-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libsnmp10-5.3.1-6ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libsnmp9", pkgver: "5.2.3-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp9-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libsnmp9-5.2.3-4ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libsnmp9-dev", pkgver: "5.2.3-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsnmp9-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libsnmp9-dev-5.2.3-4ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "snmp", pkgver: "5.3.1-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package snmp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to snmp-5.3.1-6ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "snmpd", pkgver: "5.3.1-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package snmpd-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to snmpd-5.3.1-6ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "tkmib", pkgver: "5.3.1-6ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tkmib-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to tkmib-5.3.1-6ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
