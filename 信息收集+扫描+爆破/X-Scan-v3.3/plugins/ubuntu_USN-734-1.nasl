# This script was automatically generated from the 734-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38037);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "734-1");
script_summary(english:"ffmpeg, ffmpeg-debian vulnerabilities");
script_name(english:"USN734-1 : ffmpeg, ffmpeg-debian vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ffmpeg 
- ffmpeg-dbg 
- ffmpeg-doc 
- libavcodec-dev 
- libavcodec1d 
- libavcodec51 
- libavdevice-dev 
- libavdevice52 
- libavformat-dev 
- libavformat1d 
- libavformat52 
- libavutil-dev 
- libavutil1d 
- libavutil49 
- libpostproc-dev 
- libpostproc1d 
- libpostproc51 
- libswscale-dev 
- libswscale0 
- libswscale1d 
');
script_set_attribute(attribute:'description', value: 'It was discovered that FFmpeg did not correctly handle certain malformed
Ogg Media (OGM) files. If a user were tricked into opening a crafted Ogg
Media file, an attacker could cause the application using FFmpeg to crash,
leading to a denial of service. (CVE-2008-4610)

It was discovered that FFmpeg did not correctly handle certain parameters
when creating DTS streams. If a user were tricked into processing certain
commands, an attacker could cause a denial of service via application
crash, or possibly execute arbitrary code with the privileges of the user
invoking the program. This issue only affected Ubuntu 8.10. (CVE-2008-4866)

It was discovered that FFmpeg did not correctly handle certain malformed
DTS Coherent Acoustics (DCA) files. If a user were tricked into opening a
crafted DCA file, an attacker could cause a denial of service via
application crash, or possibly execute arbitrary code with the privileges
of the user invoking the program. (CVE-2008-4867)

It was discovered that FFmpeg did not correctl
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ffmpeg-0.svn20080206-12ubuntu3.1 (Ubuntu 8.10)
- ffmpeg-dbg-0.svn20080206-12ubuntu3.1 (Ubuntu 8.10)
- ffmpeg-doc-0.svn20080206-12ubuntu3.1 (Ubuntu 8.10)
- libavcodec-dev-0.svn20080206-12ubuntu3.1 (Ubuntu 8.10)
- libavcodec1d-0.cvs20070307-5ubuntu7.3 (Ubuntu 8.04)
- libavcodec51-0.svn20080206-12ubuntu3.1 (Ubuntu 8.10)
- libavdevice-dev-0.svn20080206-12ubuntu3.1 (Ubuntu 8.10)
- libavdevice52-0.svn20080206-12ubuntu3.1 (Ubuntu 8.10)
- libavformat-dev-0.svn20080206-12ubuntu3.1 (Ubuntu 8.10)
- li
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-4610","CVE-2008-4866","CVE-2008-4867","CVE-2009-0385");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "ffmpeg", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ffmpeg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ffmpeg-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ffmpeg-dbg", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ffmpeg-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ffmpeg-dbg-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ffmpeg-doc", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ffmpeg-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ffmpeg-doc-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavcodec-dev", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavcodec-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavcodec-dev-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libavcodec1d", pkgver: "0.cvs20070307-5ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavcodec1d-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libavcodec1d-0.cvs20070307-5ubuntu7.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavcodec51", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavcodec51-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavcodec51-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavdevice-dev", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavdevice-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavdevice-dev-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavdevice52", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavdevice52-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavdevice52-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavformat-dev", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavformat-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavformat-dev-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libavformat1d", pkgver: "0.cvs20070307-5ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavformat1d-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libavformat1d-0.cvs20070307-5ubuntu7.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavformat52", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavformat52-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavformat52-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavutil-dev", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavutil-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavutil-dev-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libavutil1d", pkgver: "0.cvs20070307-5ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavutil1d-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libavutil1d-0.cvs20070307-5ubuntu7.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libavutil49", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavutil49-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libavutil49-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpostproc-dev", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpostproc-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpostproc-dev-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libpostproc1d", pkgver: "0.cvs20070307-5ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpostproc1d-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libpostproc1d-0.cvs20070307-5ubuntu7.3
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpostproc51", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpostproc51-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpostproc51-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libswscale-dev", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libswscale-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libswscale-dev-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libswscale0", pkgver: "0.svn20080206-12ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libswscale0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libswscale0-0.svn20080206-12ubuntu3.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libswscale1d", pkgver: "0.cvs20070307-5ubuntu7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libswscale1d-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libswscale1d-0.cvs20070307-5ubuntu7.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
