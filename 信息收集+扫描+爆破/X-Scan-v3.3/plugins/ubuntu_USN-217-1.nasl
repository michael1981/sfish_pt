# This script was automatically generated from the 217-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20635);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "217-1");
script_summary(english:"inkscape vulnerability");
script_name(english:"USN217-1 : inkscape vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "inkscape" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'A buffer overflow has been discovered in the SVG importer of Inkscape.
By tricking an user into opening a specially crafted SVG image this
could be exploited to execute arbitrary code with the privileges of
the Inkscape user.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- inkscape-0.42-1build1ubuntu0.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "inkscape", pkgver: "0.42-1build1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package inkscape-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to inkscape-0.42-1build1ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
