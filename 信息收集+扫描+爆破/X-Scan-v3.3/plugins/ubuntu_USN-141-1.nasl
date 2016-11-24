# This script was automatically generated from the 141-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20534);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "141-1");
script_summary(english:"tcpdump vulnerability");
script_name(english:"USN141-1 : tcpdump vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "tcpdump" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'It was discovered that certain invalid BGP packets triggered an
infinite loop in tcpdump, which caused tcpdump to stop working. This
could be abused by a remote attacker to bypass tcpdump analysis of
network traffic.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- tcpdump-3.8.3-3ubuntu0.4 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2005-1267");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "tcpdump", pkgver: "3.8.3-3ubuntu0.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package tcpdump-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to tcpdump-3.8.3-3ubuntu0.4
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
