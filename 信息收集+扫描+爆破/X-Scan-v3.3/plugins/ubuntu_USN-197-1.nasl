# This script was automatically generated from the 197-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20611);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "197-1");
script_summary(english:"shorewall vulnerability");
script_name(english:"USN197-1 : shorewall vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "shorewall" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'A firewall bypass vulnerability has been found in shorewall. If
MACLIST_TTL was set to a value greater than 0 or MACLIST_DISPOSITION
was set to "ACCEPT" in /etc/shorewall/shorewall.conf, and a client was
positively identified through its MAC address, that client bypassed
all other policies/rules in place. This could allow external computers
to get access to ports that are intended to be restricted by the
firewall policy.

Please note that this does not affect the default configuration, which
does not enable MAC based client identification.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- shorewall-2.0.13-1ubuntu0.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-2317");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "shorewall", pkgver: "2.0.13-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package shorewall-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to shorewall-2.0.13-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
