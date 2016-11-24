# This script was automatically generated from the 635-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33940);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "635-1");
script_summary(english:"xine-lib vulnerabilities");
script_name(english:"USN635-1 : xine-lib vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libxine-dev 
- libxine-extracodecs 
- libxine-main1 
- libxine1 
- libxine1-all-plugins 
- libxine1-bin 
- libxine1-console 
- libxine1-dbg 
- libxine1-doc 
- libxine1-ffmpeg 
- libxine1-gnome 
- libxine1-kde 
- libxine1-misc-plugins 
- libxine1-plugins 
- libxine1-x 
');
script_set_attribute(attribute:'description', value: 'Alin Rad Pop discovered an array index vulnerability in the SDP
parser. If a user or automated system were tricked into opening a
malicious RTSP stream, a remote attacker may be able to execute
arbitrary code with the privileges of the user invoking the program.
(CVE-2008-0073)

Luigi Auriemma discovered that xine-lib did not properly check
buffer sizes in the RTSP header-handling code. If xine-lib opened an
RTSP stream with crafted SDP attributes, a remote attacker may be
able to execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-0225, CVE-2008-0238)

Damian Frizza and Alfredo Ortega discovered that xine-lib did not
properly validate FLAC tags. If a user or automated system were
tricked into opening a crafted FLAC file, a remote attacker may be
able to execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-0486)

It was discovered that the ASF demuxer in xine-lib did not properly
check the length if the ASF header. If a user or automated sy
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxine-dev-1.1.11.1-1ubuntu3.1 (Ubuntu 8.04)
- libxine-extracodecs-1.1.4-2ubuntu3.1 (Ubuntu 7.04)
- libxine-main1-1.1.4-2ubuntu3.1 (Ubuntu 7.04)
- libxine1-1.1.11.1-1ubuntu3.1 (Ubuntu 8.04)
- libxine1-all-plugins-1.1.11.1-1ubuntu3.1 (Ubuntu 8.04)
- libxine1-bin-1.1.11.1-1ubuntu3.1 (Ubuntu 8.04)
- libxine1-console-1.1.11.1-1ubuntu3.1 (Ubuntu 8.04)
- libxine1-dbg-1.1.11.1-1ubuntu3.1 (Ubuntu 8.04)
- libxine1-doc-1.1.11.1-1ubuntu3.1 (Ubuntu 8.04)
- libxine1-ffmpeg-1.1.11.1-1ubuntu3.1 (Ubuntu 8
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-0073","CVE-2008-0225","CVE-2008-0238","CVE-2008-0486","CVE-2008-1110","CVE-2008-1161","CVE-2008-1482","CVE-2008-1686","CVE-2008-1878");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "libxine-dev", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine-dev-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libxine-extracodecs", pkgver: "1.1.4-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-extracodecs-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libxine-extracodecs-1.1.4-2ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libxine-main1", pkgver: "1.1.4-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-main1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libxine-main1-1.1.4-2ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1-all-plugins", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-all-plugins-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-all-plugins-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1-bin", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-bin-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-bin-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1-console", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-console-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-console-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1-dbg", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-dbg-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1-doc", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-doc-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1-ffmpeg", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-ffmpeg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-ffmpeg-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1-gnome", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-gnome-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-gnome-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libxine1-kde", pkgver: "1.1.4-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-kde-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libxine1-kde-1.1.4-2ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1-misc-plugins", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-misc-plugins-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-misc-plugins-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1-plugins", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-plugins-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-plugins-1.1.11.1-1ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxine1-x", pkgver: "1.1.11.1-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-x-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxine1-x-1.1.11.1-1ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
