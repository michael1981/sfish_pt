# This script was automatically generated from the 459-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28058);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "459-2");
script_summary(english:"pptpd regression");
script_name(english:"USN459-2 : pptpd regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- bcrelay 
- pptpd 
');
script_set_attribute(attribute:'description', value: 'USN-459-1 fixed vulnerabilities in pptpd.  However, a portion of the fix 
caused a regression in session establishment under Dapper for certain 
PPTP clients.  This update fixes the problem.

We apologize for the inconvenience.

Original advisory details:

 A flaw was discovered in the PPTP tunnel server. Remote attackers could 
 send a specially crafted packet and disrupt established PPTP tunnels, 
 leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- bcrelay-1.2.3-1ubuntu0.2 (Ubuntu 6.06)
- pptpd-1.2.3-1ubuntu0.2 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "bcrelay", pkgver: "1.2.3-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bcrelay-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to bcrelay-1.2.3-1ubuntu0.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "pptpd", pkgver: "1.2.3-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pptpd-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to pptpd-1.2.3-1ubuntu0.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
