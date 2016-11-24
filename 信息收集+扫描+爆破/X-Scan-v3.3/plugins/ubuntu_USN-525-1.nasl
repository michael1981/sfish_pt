# This script was automatically generated from the 525-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28130);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "525-1");
script_summary(english:"libsndfile vulnerability");
script_name(english:"USN525-1 : libsndfile vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libsndfile1 
- libsndfile1-dev 
- sndfile-programs 
');
script_set_attribute(attribute:'description', value: 'Robert Buchholz discovered that libsndfile did not correctly validate the
size of its memory buffers.  If a user were tricked into playing a specially
crafted FLAC file, a remote attacker could execute arbitrary code with user
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libsndfile1-1.0.16-1ubuntu0.7.04.1 (Ubuntu 7.04)
- libsndfile1-dev-1.0.16-1ubuntu0.7.04.1 (Ubuntu 7.04)
- sndfile-programs-1.0.16-1ubuntu0.7.04.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-4974");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libsndfile1", pkgver: "1.0.16-1ubuntu0.7.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsndfile1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libsndfile1-1.0.16-1ubuntu0.7.04.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libsndfile1-dev", pkgver: "1.0.16-1ubuntu0.7.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsndfile1-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libsndfile1-dev-1.0.16-1ubuntu0.7.04.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "sndfile-programs", pkgver: "1.0.16-1ubuntu0.7.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package sndfile-programs-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to sndfile-programs-1.0.16-1ubuntu0.7.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
