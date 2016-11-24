# This script was automatically generated from the 785-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39353);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "785-1");
script_summary(english:"ipsec-tools vulnerabilities");
script_name(english:"USN785-1 : ipsec-tools vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ipsec-tools 
- racoon 
');
script_set_attribute(attribute:'description', value: 'It was discovered that ipsec-tools did not properly handle certain
fragmented packets. A remote attacker could send specially crafted packets
to the server and cause a denial of service. (CVE-2009-1574)

It was discovered that ipsec-tools did not properly handle memory usage
when verifying certificate signatures or processing nat-traversal
keep-alive messages. A remote attacker could send specially crafted packets
to the server and exhaust available memory, leading to a denial of service.
(CVE-2009-1632)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ipsec-tools-0.7-2.1ubuntu1.9.04.1 (Ubuntu 9.04)
- racoon-0.7-2.1ubuntu1.9.04.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2009-1574","CVE-2009-1632");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "ipsec-tools", pkgver: "0.7-2.1ubuntu1.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ipsec-tools-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ipsec-tools-0.7-2.1ubuntu1.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "racoon", pkgver: "0.7-2.1ubuntu1.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package racoon-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to racoon-0.7-2.1ubuntu1.9.04.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
