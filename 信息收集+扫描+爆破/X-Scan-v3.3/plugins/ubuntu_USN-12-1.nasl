# This script was automatically generated from the 12-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20508);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "12-1");
script_summary(english:"ppp Denial of Service");
script_name(english:"USN12-1 : ppp Denial of Service");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ppp 
- ppp-dev 
');
script_set_attribute(attribute:'description', value: 'It has been discovered that ppp does not properly verify certain data
structures used in the CBCP protocol. This vulnerability could allow
an attacker to cause the pppd server to crash due to an invalid memory
access, leading to a denial of service. However, there is no
possibility of code execution or privilege escalation.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ppp-2.4.2+20040428-2ubuntu6.2 (Ubuntu 4.10)
- ppp-dev-2.4.2+20040428-2ubuntu6.2 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "ppp", pkgver: "2.4.2+20040428-2ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ppp-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ppp-2.4.2+20040428-2ubuntu6.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "ppp-dev", pkgver: "2.4.2+20040428-2ubuntu6.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ppp-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to ppp-dev-2.4.2+20040428-2ubuntu6.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
