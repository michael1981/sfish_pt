# This script was automatically generated from the 310-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27885);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "310-1");
script_summary(english:"ppp vulnerability");
script_name(english:"USN310-1 : ppp vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ppp 
- ppp-dev 
');
script_set_attribute(attribute:'description', value: 'Marcus Meissner discovered that the winbind plugin of pppd does not
check the result of the setuid() call. On systems that configure PAM
limits for the maximum number of user processes and enable the winbind
plugin, a local attacker could exploit this to execute the winbind
NTLM authentication helper as root. Depending on the local winbind
configuration, this could potentially lead to privilege escalation.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ppp-2.4.4b1-1ubuntu3.1 (Ubuntu 6.06)
- ppp-dev-2.4.4b1-1ubuntu3.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-2194");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "ppp", pkgver: "2.4.4b1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ppp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ppp-2.4.4b1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "ppp-dev", pkgver: "2.4.4b1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ppp-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ppp-dev-2.4.4b1-1ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
