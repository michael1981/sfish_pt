# This script was automatically generated from the 827-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40848);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "827-1");
script_summary(english:"dnsmasq vulnerabilities");
script_name(english:"USN827-1 : dnsmasq vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- dnsmasq 
- dnsmasq-base 
');
script_set_attribute(attribute:'description', value: 'IvAin Arce, Pablo HernAin Jorge, Alejandro Pablo Rodriguez, MartA­n Coco,
Alberto SoliAto Testa and Pablo Annetta discovered that Dnsmasq did not
properly validate its input when processing TFTP requests for files with
long names. A remote attacker could cause a denial of service or execute
arbitrary code with user privileges. Dnsmasq runs as the \'dnsmasq\' user by
default on Ubuntu. (CVE-2009-2957)

Steve Grubb discovered that Dnsmasq could be made to dereference a NULL
pointer when processing certain TFTP requests. A remote attacker could
cause a denial of service by sending a crafted TFTP request.
(CVE-2009-2958)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- dnsmasq-2.47-3ubuntu0.1 (Ubuntu 9.04)
- dnsmasq-base-2.47-3ubuntu0.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

script_cve_id("CVE-2009-2957","CVE-2009-2958");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "dnsmasq", pkgver: "2.47-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dnsmasq-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dnsmasq-2.47-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "dnsmasq-base", pkgver: "2.47-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package dnsmasq-base-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to dnsmasq-base-2.47-3ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
