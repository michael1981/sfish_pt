# This script was automatically generated from the 358-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27938);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "358-1");
script_summary(english:"ffmpeg, xine-lib vulnerabilities");
script_name(english:"USN358-1 : ffmpeg, xine-lib vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ffmpeg 
- kino 
- libavcodec-dev 
- libavformat-dev 
- libpostproc-dev 
- libxine-dev 
- libxine-main1 
- libxine1 
- libxine1c2 
');
script_set_attribute(attribute:'description', value: 'XFOCUS Security Team discovered that the AVI decoder used in xine-lib did not
correctly validate certain headers.  By tricking a user into playing an AVI
with malicious headers, an attacker could execute arbitrary code with the
target user\'s privileges.  (CVE-2006-4799)

Multiple integer overflows were discovered in ffmpeg and tools that contain a
copy of ffmpeg (like xine-lib and kino), for several types of video formats.
By tricking a user into running a video player that uses ffmpeg on a stream
with malicious content, an attacker could execute arbitrary code with the
target user\'s privileges.  (CVE-2006-4800)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ffmpeg-0.cvs20050918-5ubuntu1.1 (Ubuntu 6.06)
- kino-0.75-6ubuntu0.2 (Ubuntu 5.04)
- libavcodec-dev-0.cvs20050918-5ubuntu1.1 (Ubuntu 6.06)
- libavformat-dev-0.cvs20050918-5ubuntu1.1 (Ubuntu 6.06)
- libpostproc-dev-0.cvs20050918-5ubuntu1.1 (Ubuntu 6.06)
- libxine-dev-1.1.1+ubuntu2-7.3 (Ubuntu 6.06)
- libxine-main1-1.1.1+ubuntu2-7.3 (Ubuntu 6.06)
- libxine1-1.0-1ubuntu3.9 (Ubuntu 5.04)
- libxine1c2-1.0.1-1ubuntu10.5 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4799","CVE-2006-4800");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "ffmpeg", pkgver: "0.cvs20050918-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ffmpeg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to ffmpeg-0.cvs20050918-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kino", pkgver: "0.75-6ubuntu0.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kino-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kino-0.75-6ubuntu0.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libavcodec-dev", pkgver: "0.cvs20050918-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavcodec-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libavcodec-dev-0.cvs20050918-5ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libavformat-dev", pkgver: "0.cvs20050918-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavformat-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libavformat-dev-0.cvs20050918-5ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libpostproc-dev", pkgver: "0.cvs20050918-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpostproc-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libpostproc-dev-0.cvs20050918-5ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libxine-dev", pkgver: "1.1.1+ubuntu2-7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libxine-dev-1.1.1+ubuntu2-7.3
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libxine-main1", pkgver: "1.1.1+ubuntu2-7.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine-main1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libxine-main1-1.1.1+ubuntu2-7.3
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libxine1", pkgver: "1.0-1ubuntu3.9");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libxine1-1.0-1ubuntu3.9
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libxine1c2", pkgver: "1.0.1-1ubuntu10.5");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxine1c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libxine1c2-1.0.1-1ubuntu10.5
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
