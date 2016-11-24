# This script was automatically generated from the 108-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20494);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "108-1");
script_summary(english:"gtk+2.0, gdk-pixbuf vulnerabilities");
script_name(english:"USN108-1 : gtk+2.0, gdk-pixbuf vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gtk2.0-examples 
- libgdk-pixbuf-dev 
- libgdk-pixbuf-gnome-dev 
- libgdk-pixbuf-gnome2 
- libgdk-pixbuf2 
- libgtk2.0-0 
- libgtk2.0-bin 
- libgtk2.0-common 
- libgtk2.0-dbg 
- libgtk2.0-dev 
- libgtk2.0-doc 
');
script_set_attribute(attribute:'description', value: 'Matthias Clasen discovered a Denial of Service vulnerability in the
BMP image module of gdk. Processing a specially crafted BMP image with
an application using gdk-pixbuf caused an allocated memory block to be
free()\'ed twice, leading to a crash of the application.  However, it
is believed that this cannot be exploited to execute arbitrary
attacker provided code.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gtk2.0-examples-2.4.10-1ubuntu1.1 (Ubuntu 4.10)
- libgdk-pixbuf-dev-0.22.0-7ubuntu1.1 (Ubuntu 4.10)
- libgdk-pixbuf-gnome-dev-0.22.0-7ubuntu1.1 (Ubuntu 4.10)
- libgdk-pixbuf-gnome2-0.22.0-7ubuntu1.1 (Ubuntu 4.10)
- libgdk-pixbuf2-0.22.0-7ubuntu1.1 (Ubuntu 4.10)
- libgtk2.0-0-2.4.10-1ubuntu1.1 (Ubuntu 4.10)
- libgtk2.0-bin-2.4.10-1ubuntu1.1 (Ubuntu 4.10)
- libgtk2.0-common-2.4.10-1ubuntu1.1 (Ubuntu 4.10)
- libgtk2.0-dbg-2.4.10-1ubuntu1.1 (Ubuntu 4.10)
- libgtk2.0-dev-2.4.10-1ubuntu1.1 (Ubunt
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2005-0891");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "gtk2.0-examples", pkgver: "2.4.10-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gtk2.0-examples-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to gtk2.0-examples-2.4.10-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgdk-pixbuf-dev", pkgver: "0.22.0-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgdk-pixbuf-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgdk-pixbuf-dev-0.22.0-7ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgdk-pixbuf-gnome-dev", pkgver: "0.22.0-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgdk-pixbuf-gnome-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgdk-pixbuf-gnome-dev-0.22.0-7ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgdk-pixbuf-gnome2", pkgver: "0.22.0-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgdk-pixbuf-gnome2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgdk-pixbuf-gnome2-0.22.0-7ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgdk-pixbuf2", pkgver: "0.22.0-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgdk-pixbuf2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgdk-pixbuf2-0.22.0-7ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgtk2.0-0", pkgver: "2.4.10-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-0-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgtk2.0-0-2.4.10-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgtk2.0-bin", pkgver: "2.4.10-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-bin-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgtk2.0-bin-2.4.10-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgtk2.0-common", pkgver: "2.4.10-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgtk2.0-common-2.4.10-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgtk2.0-dbg", pkgver: "2.4.10-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-dbg-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgtk2.0-dbg-2.4.10-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgtk2.0-dev", pkgver: "2.4.10-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgtk2.0-dev-2.4.10-1ubuntu1.1
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libgtk2.0-doc", pkgver: "2.4.10-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgtk2.0-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libgtk2.0-doc-2.4.10-1ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
