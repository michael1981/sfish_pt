# This script was automatically generated from the 746-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37983);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "746-1");
script_summary(english:"xine-lib vulnerability");
script_name(english:"USN746-1 : xine-lib vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libxine-dev 
- libxine-main1 
- libxine1 
- libxine1-all-plugins 
- libxine1-bin 
- libxine1-console 
- libxine1-dbg 
- libxine1-doc 
- libxine1-ffmpeg 
- libxine1-gnome 
- libxine1-misc-plugins 
- libxine1-plugins 
- libxine1-x 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the 4xm demuxer in xine-lib did not correctly handle
a large current_track value in a 4xm file, resulting in an integer
overflow. If a user or automated system were tricked into opening a
specially crafted 4xm movie file, an attacker could crash xine-lib or
possibly execute arbitrary code with the privileges of the user invoking
the program. (CVE-2009-0698)

USN-710-1 provided updated xine-lib packages to fix multiple security
vulnerabilities. The security patch to fix CVE-2008-5239 introduced a
regression causing some media files to be unplayable. This update corrects
the problem. We apologize for the inconvenience.

Original advisory details:
 It was discovered that the input handlers in xine-lib did not correctly
 handle certain error codes, resulting in out-of-bounds reads and heap-
 based buffer overflows. If a user or automated system were tricked into
 opening a specially crafted file, stream, or URL, an attacker could
 execute arbitrary code as the user invoking the program. (C
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxine-dev-1.1.15-0ubuntu3.2 (Ubuntu 8.10)
- libxine-main1-1.1.1+ubuntu2-7.11 (Ubuntu 6.06)
- libxine1-1.1.15-0ubuntu3.2 (Ubuntu 8.10)
- libxine1-all-plugins-1.1.15-0ubuntu3.2 (Ubuntu 8.10)
- libxine1-bin-1.1.15-0ubuntu3.2 (Ubuntu 8.10)
- libxine1-console-1.1.15-0ubuntu3.2 (Ubuntu 8.10)
- libxine1-dbg-1.1.15-0ubuntu3.2 (Ubuntu 8.10)
- libxine1-doc-1.1.15-0ubuntu3.2 (Ubuntu 8.10)
- libxine1-ffmpeg-1.1.15-0ubuntu3.2 (Ubuntu 8.10)
- libxine1-gnome-1.1.15-0ubuntu3.2 (Ubuntu 8.10)
- libxine1-mi
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-5239","CVE-2009-0698");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libxine-dev", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine-dev-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libxine-main1", pkgver: "1.1.1+ubuntu2-7.11");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-main1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libxine-main1-1.1.1+ubuntu2-7.11
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1-all-plugins", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-all-plugins-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-all-plugins-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1-bin", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-bin-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-bin-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1-console", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-console-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-console-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1-dbg", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-dbg-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1-doc", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-doc-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1-ffmpeg", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-ffmpeg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-ffmpeg-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1-gnome", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-gnome-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-gnome-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1-misc-plugins", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-misc-plugins-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-misc-plugins-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1-plugins", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-plugins-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-plugins-1.1.15-0ubuntu3.2
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxine1-x", pkgver: "1.1.15-0ubuntu3.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-x-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxine1-x-1.1.15-0ubuntu3.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
