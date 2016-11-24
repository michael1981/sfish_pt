# This script was automatically generated from the 794-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(39600);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "794-1");
script_summary(english:"libcompress-raw-zlib-perl, perl vulnerability");
script_name(english:"USN794-1 : libcompress-raw-zlib-perl, perl vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libcgi-fast-perl 
- libcompress-raw-zlib-perl 
- libperl-dev 
- libperl5.10 
- perl 
- perl-base 
- perl-debug 
- perl-doc 
- perl-modules 
- perl-suid 
');
script_set_attribute(attribute:'description', value: 'It was discovered that the Compress::Raw::Zlib Perl module incorrectly
handled certain zlib compressed streams. If a user or automated system were
tricked into processing a specially crafted compressed stream or file, a
remote attacker could crash the application, leading to a denial of
service.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libcgi-fast-perl-5.10.0-19ubuntu1.1 (Ubuntu 9.04)
- libcompress-raw-zlib-perl-2.015-1ubuntu0.1 (Ubuntu 9.04)
- libperl-dev-5.10.0-19ubuntu1.1 (Ubuntu 9.04)
- libperl5.10-5.10.0-19ubuntu1.1 (Ubuntu 9.04)
- perl-5.10.0-19ubuntu1.1 (Ubuntu 9.04)
- perl-base-5.10.0-19ubuntu1.1 (Ubuntu 9.04)
- perl-debug-5.10.0-19ubuntu1.1 (Ubuntu 9.04)
- perl-doc-5.10.0-19ubuntu1.1 (Ubuntu 9.04)
- perl-modules-5.10.0-19ubuntu1.1 (Ubuntu 9.04)
- perl-suid-5.10.0-19ubuntu1.1 (Ubuntu 9.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-1391");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libcgi-fast-perl", pkgver: "5.10.0-19ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcgi-fast-perl-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libcgi-fast-perl-5.10.0-19ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libcompress-raw-zlib-perl", pkgver: "2.015-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcompress-raw-zlib-perl-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libcompress-raw-zlib-perl-2.015-1ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libperl-dev", pkgver: "5.10.0-19ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libperl-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libperl-dev-5.10.0-19ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libperl5.10", pkgver: "5.10.0-19ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libperl5.10-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libperl5.10-5.10.0-19ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "perl", pkgver: "5.10.0-19ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to perl-5.10.0-19ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "perl-base", pkgver: "5.10.0-19ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-base-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to perl-base-5.10.0-19ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "perl-debug", pkgver: "5.10.0-19ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-debug-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to perl-debug-5.10.0-19ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "perl-doc", pkgver: "5.10.0-19ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to perl-doc-5.10.0-19ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "perl-modules", pkgver: "5.10.0-19ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-modules-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to perl-modules-5.10.0-19ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "perl-suid", pkgver: "5.10.0-19ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-suid-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to perl-suid-5.10.0-19ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
