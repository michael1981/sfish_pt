# This script was automatically generated from the 413-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28002);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "413-1");
script_summary(english:"BlueZ vulnerability");
script_name(english:"USN413-1 : BlueZ vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- bluez-cups 
- bluez-pcmcia-support 
- bluez-utils 
');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in the HID daemon of bluez-utils.  A remote 
attacker could gain control of the mouse and keyboard if hidd was 
enabled.  This does not affect a default Ubuntu installation, since hidd 
is normally disabled.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- bluez-cups-2.20-0ubuntu3.1 (Ubuntu 5.10)
- bluez-pcmcia-support-2.20-0ubuntu3.1 (Ubuntu 5.10)
- bluez-utils-2.20-0ubuntu3.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:A/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-6899");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "bluez-cups", pkgver: "2.20-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bluez-cups-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to bluez-cups-2.20-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "bluez-pcmcia-support", pkgver: "2.20-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bluez-pcmcia-support-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to bluez-pcmcia-support-2.20-0ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "bluez-utils", pkgver: "2.20-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bluez-utils-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to bluez-utils-2.20-0ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
