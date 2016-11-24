# This script was automatically generated from the 453-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28051);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "453-2");
script_summary(english:"rdesktop regression");
script_name(english:"USN453-2 : rdesktop regression");
script_set_attribute(attribute:'synopsis', value: 'The remote package "rdesktop" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'USN-453-1 provided an updated libx11 package to fix a security
vulnerability. This triggered an error in rdesktop so that it crashed
on startup. This update fixes the problem.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- rdesktop-1.4.1-1.1ubuntu0.6.10 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "rdesktop", pkgver: "1.4.1-1.1ubuntu0.6.10");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rdesktop-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to rdesktop-1.4.1-1.1ubuntu0.6.10
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
