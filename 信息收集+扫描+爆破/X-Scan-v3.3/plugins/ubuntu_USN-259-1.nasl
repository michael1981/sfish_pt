# This script was automatically generated from the 259-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(21067);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "259-1");
script_summary(english:"irssi-text vulnerability");
script_name(english:"USN259-1 : irssi-text vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "irssi-text" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'A Denial of Service vulnerability was discoverd in irssi. The DCC
ACCEPT command handler did not sufficiently verify the remotely
specified arguments. A remote attacker could exploit this to crash
irssi by sending a specially crafted DCC commands.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- irssi-text-0.8.9+0.8.10rc5-0ubuntu4.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-0458");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "irssi-text", pkgver: "0.8.9+0.8.10rc5-0ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package irssi-text-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to irssi-text-0.8.9+0.8.10rc5-0ubuntu4.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
