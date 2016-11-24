# This script was automatically generated from the 804-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39851);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "804-1");
script_summary(english:"pulseaudio vulnerability");
script_name(english:"USN804-1 : pulseaudio vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpulse-browse0 
- libpulse-browse0-dbg 
- libpulse-dev 
- libpulse-mainloop-glib0 
- libpulse-mainloop-glib0-dbg 
- libpulse0 
- libpulse0-dbg 
- libpulsecore5 
- libpulsecore5-dbg 
- libpulsecore9 
- libpulsecore9-dbg 
- pulseaudio 
- pulseaudio-dbg 
- pulseaudio-esound-compat 
- pulseaudio-esound-compat-dbg 
- pulseaudio-module-gconf 
- pulseaudio-module-gconf-dbg 
- pulseaudio-module-hal 
- pulseaudio-module-hal-dbg 
- pulseaudio-module-lirc 
- pu
[...]');
script_set_attribute(attribute:'description', value: 'Tavis Ormandy and Yorick Koster discovered that PulseAudio did not
safely re-execute itself.  A local attacker could exploit this to gain
root privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpulse-browse0-0.9.14-0ubuntu20.2 (Ubuntu 9.04)
- libpulse-browse0-dbg-0.9.14-0ubuntu20.2 (Ubuntu 9.04)
- libpulse-dev-0.9.14-0ubuntu20.2 (Ubuntu 9.04)
- libpulse-mainloop-glib0-0.9.14-0ubuntu20.2 (Ubuntu 9.04)
- libpulse-mainloop-glib0-dbg-0.9.14-0ubuntu20.2 (Ubuntu 9.04)
- libpulse0-0.9.14-0ubuntu20.2 (Ubuntu 9.04)
- libpulse0-dbg-0.9.14-0ubuntu20.2 (Ubuntu 9.04)
- libpulsecore5-0.9.10-2ubuntu9.4 (Ubuntu 8.10)
- libpulsecore5-dbg-0.9.10-2ubuntu9.4 (Ubuntu 8.10)
- libpulsecore9-0.9.14-0u
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-1894");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libpulse-browse0", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse-browse0-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpulse-browse0-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpulse-browse0-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse-browse0-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpulse-browse0-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpulse-dev", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpulse-dev-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpulse-mainloop-glib0", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse-mainloop-glib0-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpulse-mainloop-glib0-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpulse-mainloop-glib0-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse-mainloop-glib0-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpulse-mainloop-glib0-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpulse0", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse0-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpulse0-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpulse0-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse0-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpulse0-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpulsecore5", pkgver: "0.9.10-2ubuntu9.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulsecore5-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpulsecore5-0.9.10-2ubuntu9.4
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpulsecore5-dbg", pkgver: "0.9.10-2ubuntu9.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulsecore5-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpulsecore5-dbg-0.9.10-2ubuntu9.4
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpulsecore9", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulsecore9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpulsecore9-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libpulsecore9-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulsecore9-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libpulsecore9-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-esound-compat", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-esound-compat-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-esound-compat-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-esound-compat-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-esound-compat-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-esound-compat-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-module-gconf", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-gconf-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-module-gconf-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-module-gconf-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-gconf-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-module-gconf-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-module-hal", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-hal-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-module-hal-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-module-hal-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-hal-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-module-hal-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-module-lirc", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-lirc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-module-lirc-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-module-lirc-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-lirc-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-module-lirc-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-module-x11", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-x11-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-module-x11-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-module-x11-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-x11-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-module-x11-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-module-zeroconf", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-zeroconf-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-module-zeroconf-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-module-zeroconf-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-zeroconf-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-module-zeroconf-dbg-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-utils", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-utils-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-utils-0.9.14-0ubuntu20.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "pulseaudio-utils-dbg", pkgver: "0.9.14-0ubuntu20.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-utils-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to pulseaudio-utils-dbg-0.9.14-0ubuntu20.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
