# This script was automatically generated from the 125-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20515);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "125-1");
script_summary(english:"gaim vulnerabilities");
script_name(english:"USN125-1 : gaim vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gaim 
- gaim-data 
- gaim-dev 
');
script_set_attribute(attribute:'description', value: 'Marco Alvarez found a Denial of Service vulnerability in the Jabber
protocol handler. A remote attacker could exploit this to crash Gaim
by sending specially crafted file transfers to the user.
(CVE-2005-0967)

Stu Tomlinson discovered an insufficient bounds checking flaw in the
URL parser. By sending a message containing a very long URL, a remote
attacker could crash Gaim or execute arbitrary code with the
privileges of the user. This was not possible on all protocols, due to
message length restrictions. Jabber are SILC were known to be
vulnerable. (CVE-2005-1261)

Siebe Tolsma discovered a Denial of Service attack in the MSN handler.
By sending a specially crafted SLP message with an empty body, a
remote attacker could crash Gaim. (CVE-2005-1262)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gaim-1.1.4-1ubuntu4.1 (Ubuntu 5.04)
- gaim-data-1.1.4-1ubuntu4.1 (Ubuntu 5.04)
- gaim-dev-1.1.4-1ubuntu4.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0967","CVE-2005-1261","CVE-2005-1262");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "gaim", pkgver: "1.1.4-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gaim-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gaim-1.1.4-1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gaim-data", pkgver: "1.1.4-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gaim-data-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gaim-data-1.1.4-1ubuntu4.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "gaim-dev", pkgver: "1.1.4-1ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gaim-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to gaim-dev-1.1.4-1ubuntu4.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
