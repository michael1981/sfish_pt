# This script was automatically generated from the 700-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37746);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "700-2");
script_summary(english:"perl regression");
script_name(english:"USN700-2 : perl regression");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libcgi-fast-perl 
- libperl-dev 
- libperl5.8 
- perl 
- perl-base 
- perl-debug 
- perl-doc 
- perl-modules 
- perl-suid 
');
script_set_attribute(attribute:'description', value: 'USN-700-1 fixed vulnerabilities in Perl.  Due to problems with the Ubuntu
8.04 build, some Perl .ph files were missing from the resulting update.
This update fixes the problem.  We apologize for the inconvenience.

Original advisory details:

 Jonathan Smith discovered that the Archive::Tar Perl module did not
 correctly handle symlinks when extracting archives.  If a user or
 automated system were tricked into opening a specially crafted tar file,
 a remote attacker could over-write arbitrary files.  (CVE-2007-4829)
 
 Tavis Ormandy and Will Drewry discovered that Perl did not correctly
 handle certain utf8 characters in regular expressions.  If a user or
 automated system were tricked into using a specially crafted expression,
 a remote attacker could crash the application, leading to a denial
 of service.  Ubuntu 8.10 was not affected by this issue.  (CVE-2008-1927)
 
 A race condition was discovered in the File::Path Perl module\'s rmtree
 function.  If a local attacker successfully raced another user\'s
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libcgi-fast-perl-5.8.8-12ubuntu0.4 (Ubuntu 8.04)
- libperl-dev-5.8.8-12ubuntu0.4 (Ubuntu 8.04)
- libperl5.8-5.8.8-12ubuntu0.4 (Ubuntu 8.04)
- perl-5.8.8-12ubuntu0.4 (Ubuntu 8.04)
- perl-base-5.8.8-12ubuntu0.4 (Ubuntu 8.04)
- perl-debug-5.8.8-12ubuntu0.4 (Ubuntu 8.04)
- perl-doc-5.8.8-12ubuntu0.4 (Ubuntu 8.04)
- perl-modules-5.8.8-12ubuntu0.4 (Ubuntu 8.04)
- perl-suid-5.8.8-12ubuntu0.4 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-4829","CVE-2008-1927","CVE-2008-5302","CVE-2008-5303");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "libcgi-fast-perl", pkgver: "5.8.8-12ubuntu0.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcgi-fast-perl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libcgi-fast-perl-5.8.8-12ubuntu0.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libperl-dev", pkgver: "5.8.8-12ubuntu0.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libperl-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libperl-dev-5.8.8-12ubuntu0.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libperl5.8", pkgver: "5.8.8-12ubuntu0.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libperl5.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libperl5.8-5.8.8-12ubuntu0.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "perl", pkgver: "5.8.8-12ubuntu0.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to perl-5.8.8-12ubuntu0.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "perl-base", pkgver: "5.8.8-12ubuntu0.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-base-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to perl-base-5.8.8-12ubuntu0.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "perl-debug", pkgver: "5.8.8-12ubuntu0.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-debug-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to perl-debug-5.8.8-12ubuntu0.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "perl-doc", pkgver: "5.8.8-12ubuntu0.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to perl-doc-5.8.8-12ubuntu0.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "perl-modules", pkgver: "5.8.8-12ubuntu0.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-modules-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to perl-modules-5.8.8-12ubuntu0.4
');
}
found = ubuntu_check(osver: "8.04", pkgname: "perl-suid", pkgver: "5.8.8-12ubuntu0.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-suid-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to perl-suid-5.8.8-12ubuntu0.4
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
