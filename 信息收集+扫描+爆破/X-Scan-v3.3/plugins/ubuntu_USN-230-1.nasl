# This script was automatically generated from the 230-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20773);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "230-1");
script_summary(english:"ffmpeg vulnerability");
script_name(english:"USN230-1 : ffmpeg vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- ffmpeg 
- kino 
- libavcodec-dev 
- libavformat-dev 
- libpostproc-dev 
');
script_set_attribute(attribute:'description', value: 'Simon Kilvington discovered a buffer overflow in the
avcodec_default_get_buffer() function of the ffmpeg library. By
tricking an user into opening a malicious movie which contains
specially crafted PNG images, this could be exploited to execute
arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- ffmpeg-0.cvs20050121-1ubuntu1.1 (Ubuntu 5.04)
- kino-0.75-6ubuntu0.1 (Ubuntu 5.04)
- libavcodec-dev-0.cvs20050121-1ubuntu1.1 (Ubuntu 5.04)
- libavformat-dev-0.cvs20050121-1ubuntu1.1 (Ubuntu 5.04)
- libpostproc-dev-0.cvs20050121-1ubuntu1.1 (Ubuntu 5.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-4048");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "ffmpeg", pkgver: "0.cvs20050121-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ffmpeg-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to ffmpeg-0.cvs20050121-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "kino", pkgver: "0.75-6ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package kino-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to kino-0.75-6ubuntu0.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libavcodec-dev", pkgver: "0.cvs20050121-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavcodec-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libavcodec-dev-0.cvs20050121-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libavformat-dev", pkgver: "0.cvs20050121-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libavformat-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libavformat-dev-0.cvs20050121-1ubuntu1.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libpostproc-dev", pkgver: "0.cvs20050121-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpostproc-dev-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libpostproc-dev-0.cvs20050121-1ubuntu1.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
