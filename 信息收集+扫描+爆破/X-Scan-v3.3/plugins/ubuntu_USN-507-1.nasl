# This script was automatically generated from the 507-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28111);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "507-1");
script_summary(english:"tcp-wrappers vulnerability");
script_name(english:"USN507-1 : tcp-wrappers vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libwrap0 
- libwrap0-dev 
- tcpd 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the TCP wrapper library was incorrectly allowing
connections to services that did not specify server-side connection
details.  Remote attackers could connect to services that had been
configured to block such connections.  This only affected Ubuntu Feisty.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libwrap0-7.6.dbs-11ubuntu0.1 (Ubuntu 7.04)
- libwrap0-dev-7.6.dbs-11ubuntu0.1 (Ubuntu 7.04)
- tcpd-7.6.dbs-11ubuntu0.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libwrap0", pkgver: "7.6.dbs-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwrap0-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libwrap0-7.6.dbs-11ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libwrap0-dev", pkgver: "7.6.dbs-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwrap0-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libwrap0-dev-7.6.dbs-11ubuntu0.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "tcpd", pkgver: "7.6.dbs-11ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tcpd-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to tcpd-7.6.dbs-11ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
