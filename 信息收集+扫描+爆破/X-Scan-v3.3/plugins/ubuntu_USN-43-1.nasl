# This script was automatically generated from the 43-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20660);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "43-1");
script_summary(english:"groff vulnerabilities");
script_name(english:"USN43-1 : groff vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- groff 
- groff-base 
');
script_set_attribute(attribute:'description', value: 'Javier Fernández-Sanguino Peña discovered that the auxiliary scripts
"eqn2graph" and "pic2graph" created temporary files in an insecure
way, which allowed exploitation of a race condition to create or
overwrite files with the privileges of the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- groff-1.18.1.1-1ubuntu0.2 (Ubuntu 4.10)
- groff-base-1.18.1.1-1ubuntu0.2 (Ubuntu 4.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "groff", pkgver: "1.18.1.1-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package groff-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to groff-1.18.1.1-1ubuntu0.2
');
}
found = ubuntu_check(osver: "4.10", pkgname: "groff-base", pkgver: "1.18.1.1-1ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package groff-base-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to groff-base-1.18.1.1-1ubuntu0.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
