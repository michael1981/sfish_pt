# This script was automatically generated from the 610-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32190);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "610-1");
script_summary(english:"LTSP vulnerability");
script_name(english:"USN610-1 : LTSP vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ldm 
- ltsp-client 
- ltsp-client-core 
- ltsp-server 
- ltsp-server-standalone 
');
script_set_attribute(attribute:'description', value: 'Christian Herzog discovered that it was possible to connect to any
LTSP client\'s X session over the network.  A remote attacker could
eavesdrop on X events, read window contents, and record keystrokes,
possibly gaining access to private information.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ldm-5.0.39.1 (Ubuntu 7.10)
- ltsp-client-5.0.39.1 (Ubuntu 7.10)
- ltsp-client-core-5.0.39.1 (Ubuntu 7.10)
- ltsp-server-5.0.39.1 (Ubuntu 7.10)
- ltsp-server-standalone-5.0.39.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:A/AC:L/Au:N/C:P/I:P/A:N');
script_end_attributes();

script_cve_id("CVE-2008-1293");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "ldm", pkgver: "5.0.39.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ldm-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ldm-5.0.39.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ltsp-client", pkgver: "5.0.39.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ltsp-client-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ltsp-client-5.0.39.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ltsp-client-core", pkgver: "5.0.39.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ltsp-client-core-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ltsp-client-core-5.0.39.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ltsp-server", pkgver: "5.0.39.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ltsp-server-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ltsp-server-5.0.39.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "ltsp-server-standalone", pkgver: "5.0.39.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ltsp-server-standalone-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to ltsp-server-standalone-5.0.39.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
