# This script was automatically generated from the 727-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38131);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "727-1");
script_summary(english:"network-manager-applet vulnerabilities");
script_name(english:"USN727-1 : network-manager-applet vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'The remote package "network-manager-gnome" is missing a security patch.');
script_set_attribute(attribute:'description', value: 'It was discovered that network-manager-applet did not properly enforce
permissions when responding to dbus requests. A local user could perform dbus
queries to view other users\' network connection passwords and pre-shared keys.
(CVE-2009-0365)

It was discovered that network-manager-applet did not properly enforce
permissions when responding to dbus modify and delete requests. A local user
could use dbus to modify or delete other users\' network connections. This issue
only applied to Ubuntu 8.10. (CVE-2009-0578)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- network-manager-gnome-0.6.6-0ubuntu3.1 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:S/C:N/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-0365","CVE-2009-0578");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "network-manager-gnome", pkgver: "0.6.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package network-manager-gnome-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to network-manager-gnome-0.6.6-0ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
