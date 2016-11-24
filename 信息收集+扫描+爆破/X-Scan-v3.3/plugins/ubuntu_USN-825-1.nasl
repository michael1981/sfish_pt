# This script was automatically generated from the 825-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40769);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "825-1");
script_summary(english:"libvorbis vulnerability");
script_name(english:"USN825-1 : libvorbis vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libvorbis-dev 
- libvorbis0a 
- libvorbisenc2 
- libvorbisfile3 
');
script_set_attribute(attribute:'description', value: 'It was discovered that libvorbis did not correctly handle certain malformed
ogg files. If a user were tricked into opening a specially crafted ogg file
with an application that uses libvorbis, an attacker could execute
arbitrary code with the user\'s privileges. (CVE-2009-2663)

USN-682-1 provided updated libvorbis packages to fix multiple security
vulnerabilities. The upstream security patch to fix CVE-2008-1420
introduced a regression when reading sound files encoded with libvorbis
1.0beta1. This update corrects the problem.

Original advisory details:

 It was discovered that libvorbis did not correctly handle certain
 malformed sound files. If a user were tricked into opening a specially
 crafted sound file with an application that uses libvorbis, an attacker
 could execute arbitrary code with the user\'s privileges. (CVE-2008-1420)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libvorbis-dev-1.2.0.dfsg-3.1ubuntu0.9.04.1 (Ubuntu 9.04)
- libvorbis0a-1.2.0.dfsg-3.1ubuntu0.9.04.1 (Ubuntu 9.04)
- libvorbisenc2-1.2.0.dfsg-3.1ubuntu0.9.04.1 (Ubuntu 9.04)
- libvorbisfile3-1.2.0.dfsg-3.1ubuntu0.9.04.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1420","CVE-2009-2663");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libvorbis-dev", pkgver: "1.2.0.dfsg-3.1ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvorbis-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libvorbis-dev-1.2.0.dfsg-3.1ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libvorbis0a", pkgver: "1.2.0.dfsg-3.1ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvorbis0a-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libvorbis0a-1.2.0.dfsg-3.1ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libvorbisenc2", pkgver: "1.2.0.dfsg-3.1ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvorbisenc2-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libvorbisenc2-1.2.0.dfsg-3.1ubuntu0.9.04.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libvorbisfile3", pkgver: "1.2.0.dfsg-3.1ubuntu0.9.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libvorbisfile3-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libvorbisfile3-1.2.0.dfsg-3.1ubuntu0.9.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
