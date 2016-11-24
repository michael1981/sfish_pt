# This script was automatically generated from the 145-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20539);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "145-2");
script_summary(english:"wget bug fix");
script_name(english:"USN145-2 : wget bug fix");
script_set_attribute(attribute:'synopsis', value: 'The remote package "wget" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-145-1 fixed several vulnerabilities in wget. However, Ralph
Corderoy discovered some regressions that caused wget to crash in some
cases. The updated version fixes this flaw.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- wget-1.9.1-10ubuntu2.2 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "wget", pkgver: "1.9.1-10ubuntu2.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package wget-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to wget-1.9.1-10ubuntu2.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
