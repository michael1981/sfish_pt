# This script was automatically generated from the 498-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28101);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "498-1");
script_summary(english:"libvorbis vulnerabilities");
script_name(english:"USN498-1 : libvorbis vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libvorbis-dev 
- libvorbis0a 
- libvorbisenc2 
- libvorbisfile3 
');
script_set_attribute(attribute:'description', value: 'David Thiel discovered that libvorbis did not correctly verify the size
of certain headers, and did not correctly clean up a broken stream.
If a user were tricked into processing a specially crafted Vorbis stream,
a remote attacker could execute arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libvorbis-dev-1.1.2.dfsg-1.2ubuntu2 (Ubuntu 7.04)
- libvorbis0a-1.1.2.dfsg-1.2ubuntu2 (Ubuntu 7.04)
- libvorbisenc2-1.1.2.dfsg-1.2ubuntu2 (Ubuntu 7.04)
- libvorbisfile3-1.1.2.dfsg-1.2ubuntu2 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-3106","CVE-2007-4029");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libvorbis-dev", pkgver: "1.1.2.dfsg-1.2ubuntu2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvorbis-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libvorbis-dev-1.1.2.dfsg-1.2ubuntu2
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libvorbis0a", pkgver: "1.1.2.dfsg-1.2ubuntu2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvorbis0a-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libvorbis0a-1.1.2.dfsg-1.2ubuntu2
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libvorbisenc2", pkgver: "1.1.2.dfsg-1.2ubuntu2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvorbisenc2-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libvorbisenc2-1.1.2.dfsg-1.2ubuntu2
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libvorbisfile3", pkgver: "1.1.2.dfsg-1.2ubuntu2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvorbisfile3-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libvorbisfile3-1.1.2.dfsg-1.2ubuntu2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
