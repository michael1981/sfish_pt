# This script was automatically generated from the 537-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28143);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "537-1");
script_summary(english:"gnome-screensaver vulnerability");
script_name(english:"USN537-1 : gnome-screensaver vulnerability");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gnome-screensaver" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'Jens Askengren discovered that gnome-screensaver became confused when
running under Compiz, and could lose keyboard lock focus.  A local
attacker could exploit this to bypass the user\'s locked screen saver.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnome-screensaver-2.20.0-0ubuntu4.2 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-3920");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "gnome-screensaver", pkgver: "2.20.0-0ubuntu4.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnome-screensaver-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to gnome-screensaver-2.20.0-0ubuntu4.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
