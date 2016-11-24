# This script was automatically generated from the 526-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28131);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "526-1");
script_summary(english:"debian-goodies vulnerability");
script_name(english:"USN526-1 : debian-goodies vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "debian-goodies" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Thomas de Grenier de Latour discovered that the checkrestart program included
in debian-goodies did not correctly handle shell meta-characters.  A local
attacker could exploit this to gain the privileges of the user running
checkrestart.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- debian-goodies-0.27ubuntu0.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-3912");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "debian-goodies", pkgver: "0.27ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package debian-goodies-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to debian-goodies-0.27ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
