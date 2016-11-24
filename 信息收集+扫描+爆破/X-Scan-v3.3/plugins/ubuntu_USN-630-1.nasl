# This script was automatically generated from the 630-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33759);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "630-1");
script_summary(english:"ffmpeg vulnerability");
script_name(english:"USN630-1 : ffmpeg vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ffmpeg 
- libavcodec-dev 
- libavcodec1d 
- libavformat-dev 
- libavformat1d 
- libavutil-dev 
- libavutil1d 
- libpostproc-dev 
- libpostproc1d 
- libswscale-dev 
- libswscale1d 
');
script_set_attribute(attribute:'description', value: 'It was discovered that ffmpeg did not correctly handle STR file
demuxing.  If a user were tricked into processing a malicious STR file,
a remote attacker could execute arbitrary code with user privileges via
applications linked against ffmpeg.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ffmpeg-0.cvs20070307-5ubuntu7.1 (Ubuntu 8.04)
- libavcodec-dev-0.cvs20070307-5ubuntu7.1 (Ubuntu 8.04)
- libavcodec1d-0.cvs20070307-5ubuntu7.1 (Ubuntu 8.04)
- libavformat-dev-0.cvs20070307-5ubuntu7.1 (Ubuntu 8.04)
- libavformat1d-0.cvs20070307-5ubuntu7.1 (Ubuntu 8.04)
- libavutil-dev-0.cvs20070307-5ubuntu7.1 (Ubuntu 8.04)
- libavutil1d-0.cvs20070307-5ubuntu7.1 (Ubuntu 8.04)
- libpostproc-dev-0.cvs20070307-5ubuntu7.1 (Ubuntu 8.04)
- libpostproc1d-0.cvs20070307-5ubuntu7.1 (Ubuntu 8.04)
- libsw
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-3162");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "ffmpeg", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ffmpeg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ffmpeg-0.cvs20070307-5ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libavcodec-dev", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavcodec-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libavcodec-dev-0.cvs20070307-5ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libavcodec1d", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavcodec1d-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libavcodec1d-0.cvs20070307-5ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libavformat-dev", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavformat-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libavformat-dev-0.cvs20070307-5ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libavformat1d", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavformat1d-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libavformat1d-0.cvs20070307-5ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libavutil-dev", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavutil-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libavutil-dev-0.cvs20070307-5ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libavutil1d", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavutil1d-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libavutil1d-0.cvs20070307-5ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libpostproc-dev", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpostproc-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libpostproc-dev-0.cvs20070307-5ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libpostproc1d", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpostproc1d-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libpostproc1d-0.cvs20070307-5ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libswscale-dev", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libswscale-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libswscale-dev-0.cvs20070307-5ubuntu7.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libswscale1d", pkgver: "0.cvs20070307-5ubuntu7.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libswscale1d-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libswscale1d-0.cvs20070307-5ubuntu7.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
