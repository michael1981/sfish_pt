# This script was automatically generated from the 415-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28004);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "415-1");
script_summary(english:"GTK vulnerability");
script_name(english:"USN415-1 : GTK vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gtk2-engines-pixbuf 
- gtk2.0-examples 
- libgtk2.0-0 
- libgtk2.0-0-dbg 
- libgtk2.0-bin 
- libgtk2.0-common 
- libgtk2.0-dev 
- libgtk2.0-doc 
');
script_set_attribute(attribute:'description', value: 'A flaw was discovered in the error handling of GTK\'s image loading 
library.  Applications opening certain corrupted images could be made to 
crash, causing a denial of service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gtk2-engines-pixbuf-2.10.6-0ubuntu3.1 (Ubuntu 6.10)
- gtk2.0-examples-2.10.6-0ubuntu3.1 (Ubuntu 6.10)
- libgtk2.0-0-2.10.6-0ubuntu3.1 (Ubuntu 6.10)
- libgtk2.0-0-dbg-2.10.6-0ubuntu3.1 (Ubuntu 6.10)
- libgtk2.0-bin-2.10.6-0ubuntu3.1 (Ubuntu 6.10)
- libgtk2.0-common-2.10.6-0ubuntu3.1 (Ubuntu 6.10)
- libgtk2.0-dev-2.10.6-0ubuntu3.1 (Ubuntu 6.10)
- libgtk2.0-doc-2.10.6-0ubuntu3.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-0010");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "gtk2-engines-pixbuf", pkgver: "2.10.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gtk2-engines-pixbuf-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to gtk2-engines-pixbuf-2.10.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "gtk2.0-examples", pkgver: "2.10.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gtk2.0-examples-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to gtk2.0-examples-2.10.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgtk2.0-0", pkgver: "2.10.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-0-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgtk2.0-0-2.10.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgtk2.0-0-dbg", pkgver: "2.10.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-0-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgtk2.0-0-dbg-2.10.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgtk2.0-bin", pkgver: "2.10.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-bin-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgtk2.0-bin-2.10.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgtk2.0-common", pkgver: "2.10.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-common-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgtk2.0-common-2.10.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgtk2.0-dev", pkgver: "2.10.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgtk2.0-dev-2.10.6-0ubuntu3.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgtk2.0-doc", pkgver: "2.10.6-0ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-doc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgtk2.0-doc-2.10.6-0ubuntu3.1
');
}

if (w) { security_note(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
