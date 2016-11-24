# This script was automatically generated from the 497-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28100);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "497-1");
script_summary(english:"xfce4-terminal vulnerability");
script_name(english:"USN497-1 : xfce4-terminal vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "xfce4-terminal" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Lasse Kärkkäinen discovered that the Xfce Terminal did not correctly
escape shell meta-characters during "Open Link" actions.  If a remote
attacker tricked a user into opening a specially crafted URI, they could
execute arbitrary commands with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- xfce4-terminal-0.2.6-0ubuntu3.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2007-3770");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "xfce4-terminal", pkgver: "0.2.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xfce4-terminal-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to xfce4-terminal-0.2.6-0ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
