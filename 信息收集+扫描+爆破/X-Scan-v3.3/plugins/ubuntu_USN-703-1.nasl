# This script was automatically generated from the 703-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37162);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "703-1");
script_summary(english:"xterm vulnerability");
script_name(english:"USN703-1 : xterm vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "xterm" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Paul Szabo discovered that the DECRQSS escape sequences were not handled
correctly by xterm.  Additionally, window title operations were also not
safely handled.  If a user were tricked into viewing a specially crafted
series of characters while in xterm, a remote attacker could execute
arbitrary commands with user privileges. (CVE-2006-7236, CVE-2008-2382)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- xterm-235-1ubuntu1.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-7236","CVE-2008-2382","CVE-2008-2383");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "xterm", pkgver: "235-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xterm-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to xterm-235-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
