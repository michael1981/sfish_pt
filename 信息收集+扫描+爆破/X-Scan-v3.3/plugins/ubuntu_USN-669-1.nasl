# This script was automatically generated from the 669-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36364);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "669-1");
script_summary(english:"gnome-screensaver vulnerabilities");
script_name(english:"USN669-1 : gnome-screensaver vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "gnome-screensaver" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'It was discovered that the notify feature in gnome-screensaver could let
a local attacker read the clipboard contents of a locked session by
using Ctrl-V. (CVE-2007-6389)

Alan Matsuoka discovered that gnome-screensaver did not properly handle
network outages when using a remote authentication service. During a
network interruption, or by disconnecting the network cable, a local
attacker could gain access to locked sessions. (CVE-2008-0887)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnome-screensaver-2.20.0-0ubuntu4.3 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2007-6389","CVE-2008-0887");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "gnome-screensaver", pkgver: "2.20.0-0ubuntu4.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnome-screensaver-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to gnome-screensaver-2.20.0-0ubuntu4.3
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
