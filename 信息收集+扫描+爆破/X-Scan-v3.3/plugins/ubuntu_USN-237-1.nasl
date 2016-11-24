# This script was automatically generated from the 237-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20783);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "237-1");
script_summary(english:"nbd vulnerability");
script_name(english:"USN237-1 : nbd vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- nbd-client 
- nbd-server 
');
script_set_attribute(attribute:'description', value: 'Kurt Fitzner discovered that the NBD (network block device) server did
not correctly verify the maximum size of request packets. By sending
specially crafted large request packets, a remote attacker who is
allowed to access the server could exploit this to execute arbitrary
code with root privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- nbd-client-2.7.4-1ubuntu0.1 (Ubuntu 5.10)
- nbd-server-2.7.4-1ubuntu0.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-3354");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "nbd-client", pkgver: "2.7.4-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nbd-client-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to nbd-client-2.7.4-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "nbd-server", pkgver: "2.7.4-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package nbd-server-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to nbd-server-2.7.4-1ubuntu0.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
