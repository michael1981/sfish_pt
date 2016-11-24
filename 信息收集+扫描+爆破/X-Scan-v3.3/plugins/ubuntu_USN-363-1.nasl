# This script was automatically generated from the 363-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27943);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "363-1");
script_summary(english:"libmusicbrainz vulnerability");
script_name(english:"USN363-1 : libmusicbrainz vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libmusicbrainz2 
- libmusicbrainz2-dev 
- libmusicbrainz2c2 
- libmusicbrainz4 
- libmusicbrainz4-dev 
- libmusicbrainz4c2 
- libmusicbrainz4c2a 
- python-musicbrainz 
- python2.3-musicbrainz 
- python2.4-musicbrainz 
');
script_set_attribute(attribute:'description', value: 'Luigi Auriemma discovered multiple buffer overflows in libmusicbrainz. 
When a user made queries to MusicBrainz servers, it was possible for 
malicious servers, or man-in-the-middle systems posing as servers, to 
send a crafted reply to the client request and remotely gain access to 
the user\'s system with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libmusicbrainz2-2.0.2-10ubuntu1.1 (Ubuntu 5.04)
- libmusicbrainz2-dev-2.0.2-10ubuntu2.1 (Ubuntu 5.10)
- libmusicbrainz2c2-2.0.2-10ubuntu2.1 (Ubuntu 5.10)
- libmusicbrainz4-2.1.1-3ubuntu1.1 (Ubuntu 5.04)
- libmusicbrainz4-dev-2.1.2-2ubuntu3.1 (Ubuntu 6.06)
- libmusicbrainz4c2-2.1.1-3ubuntu3.1 (Ubuntu 5.10)
- libmusicbrainz4c2a-2.1.2-2ubuntu3.1 (Ubuntu 6.06)
- python-musicbrainz-2.0.2-10ubuntu2.1 (Ubuntu 5.10)
- python2.3-musicbrainz-2.0.2-10ubuntu2.1 (Ubuntu 5.10)
- python2.4-musicbrainz-2.0
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4197");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.04", pkgname: "libmusicbrainz2", pkgver: "2.0.2-10ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmusicbrainz2-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libmusicbrainz2-2.0.2-10ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmusicbrainz2-dev", pkgver: "2.0.2-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmusicbrainz2-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmusicbrainz2-dev-2.0.2-10ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmusicbrainz2c2", pkgver: "2.0.2-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmusicbrainz2c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmusicbrainz2c2-2.0.2-10ubuntu2.1
');
}
found = ubuntu_check(osver: "5.04", pkgname: "libmusicbrainz4", pkgver: "2.1.1-3ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmusicbrainz4-',found,' is vulnerable in Ubuntu 5.04
Upgrade it to libmusicbrainz4-2.1.1-3ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmusicbrainz4-dev", pkgver: "2.1.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmusicbrainz4-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmusicbrainz4-dev-2.1.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libmusicbrainz4c2", pkgver: "2.1.1-3ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmusicbrainz4c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libmusicbrainz4c2-2.1.1-3ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libmusicbrainz4c2a", pkgver: "2.1.2-2ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libmusicbrainz4c2a-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libmusicbrainz4c2a-2.1.2-2ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python-musicbrainz", pkgver: "2.0.2-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-musicbrainz-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python-musicbrainz-2.0.2-10ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python2.3-musicbrainz", pkgver: "2.0.2-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-musicbrainz-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python2.3-musicbrainz-2.0.2-10ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "python2.4-musicbrainz", pkgver: "2.0.2-10ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-musicbrainz-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to python2.4-musicbrainz-2.0.2-10ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
