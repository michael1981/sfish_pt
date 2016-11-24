# This script was automatically generated from the 573-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(30147);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "573-1");
script_summary(english:"PulseAudio vulnerability");
script_name(english:"USN573-1 : PulseAudio vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpulse-browse0 
- libpulse-dev 
- libpulse-mainloop-glib0 
- libpulse0 
- pulseaudio 
- pulseaudio-esound-compat 
- pulseaudio-module-gconf 
- pulseaudio-module-hal 
- pulseaudio-module-lirc 
- pulseaudio-module-x11 
- pulseaudio-module-zeroconf 
- pulseaudio-utils 
');
script_set_attribute(attribute:'description', value: 'It was discovered that PulseAudio did not properly drop privileges
when running as a daemon. Local users may be able to exploit this
and gain privileges. The default Ubuntu configuration is not
affected.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpulse-browse0-0.9.6-1ubuntu2.1 (Ubuntu 7.10)
- libpulse-dev-0.9.6-1ubuntu2.1 (Ubuntu 7.10)
- libpulse-mainloop-glib0-0.9.6-1ubuntu2.1 (Ubuntu 7.10)
- libpulse0-0.9.6-1ubuntu2.1 (Ubuntu 7.10)
- pulseaudio-0.9.6-1ubuntu2.1 (Ubuntu 7.10)
- pulseaudio-esound-compat-0.9.6-1ubuntu2.1 (Ubuntu 7.10)
- pulseaudio-module-gconf-0.9.6-1ubuntu2.1 (Ubuntu 7.10)
- pulseaudio-module-hal-0.9.6-1ubuntu2.1 (Ubuntu 7.10)
- pulseaudio-module-lirc-0.9.6-1ubuntu2.1 (Ubuntu 7.10)
- pulseaudio-module-x11-0.9.6-1
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-0008");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libpulse-browse0", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse-browse0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpulse-browse0-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpulse-dev", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpulse-dev-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpulse-mainloop-glib0", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse-mainloop-glib0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpulse-mainloop-glib0-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libpulse0", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpulse0-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libpulse0-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pulseaudio", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pulseaudio-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pulseaudio-esound-compat", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-esound-compat-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pulseaudio-esound-compat-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pulseaudio-module-gconf", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-gconf-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pulseaudio-module-gconf-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pulseaudio-module-hal", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-hal-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pulseaudio-module-hal-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pulseaudio-module-lirc", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-lirc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pulseaudio-module-lirc-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pulseaudio-module-x11", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-x11-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pulseaudio-module-x11-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pulseaudio-module-zeroconf", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-module-zeroconf-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pulseaudio-module-zeroconf-0.9.6-1ubuntu2.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pulseaudio-utils", pkgver: "0.9.6-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pulseaudio-utils-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pulseaudio-utils-0.9.6-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
