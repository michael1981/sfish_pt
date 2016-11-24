# This script was automatically generated from the 459-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28057);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "459-1");
script_summary(english:"pptpd vulnerability");
script_name(english:"USN459-1 : pptpd vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- bcrelay 
- pptpd 
');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in the PPTP tunnel server. Remote attackers could 
send a specially crafted packet and disrupt established PPTP tunnels, 
leading to a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- bcrelay-1.3.0-2ubuntu2.1 (Ubuntu 7.04)
- pptpd-1.3.0-2ubuntu2.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-0244");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "bcrelay", pkgver: "1.3.0-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bcrelay-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to bcrelay-1.3.0-2ubuntu2.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "pptpd", pkgver: "1.3.0-2ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pptpd-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to pptpd-1.3.0-2ubuntu2.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
