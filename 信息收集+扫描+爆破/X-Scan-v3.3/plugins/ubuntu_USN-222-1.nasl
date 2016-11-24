# This script was automatically generated from the 222-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20764);
script_version("$Revision: 1.4 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "222-1");
script_summary(english:"perl vulnerability");
script_name(english:"USN222-1 : perl vulnerability");
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
script_set_attribute(attribute:'description', value: 'Jack Louis of Dyad Security discovered that Perl did not sufficiently
check the explicit length argument in format strings. Specially
crafted format strings with overly large length arguments led to a
crash of the Perl interpreter or even to execution of arbitrary
attacker-defined code with the privileges of the user running the Perl
program.

However, this attack was only possible in insecure Perl programs which
use variables with user-defined values in string interpolations
without checking their validity.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libcgi-fast-perl-5.8.7-5ubuntu1.1 (Ubuntu 5.10)
- libperl-dev-5.8.7-5ubuntu1.1 (Ubuntu 5.10)
- libperl5.8-5.8.7-5ubuntu1.1 (Ubuntu 5.10)
- perl-5.8.7-5ubuntu1.1 (Ubuntu 5.10)
- perl-base-5.8.7-5ubuntu1.1 (Ubuntu 5.10)
- perl-debug-5.8.7-5ubuntu1.1 (Ubuntu 5.10)
- perl-doc-5.8.7-5ubuntu1.1 (Ubuntu 5.10)
- perl-modules-5.8.7-5ubuntu1.1 (Ubuntu 5.10)
- perl-suid-5.8.7-5ubuntu1.1 (Ubuntu 5.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:L/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2005-3962");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libcgi-fast-perl", pkgver: "5.8.7-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libcgi-fast-perl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libcgi-fast-perl-5.8.7-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libperl-dev", pkgver: "5.8.7-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libperl-dev-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libperl-dev-5.8.7-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libperl5.8", pkgver: "5.8.7-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libperl5.8-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libperl5.8-5.8.7-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "perl", pkgver: "5.8.7-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to perl-5.8.7-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "perl-base", pkgver: "5.8.7-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-base-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to perl-base-5.8.7-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "perl-debug", pkgver: "5.8.7-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-debug-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to perl-debug-5.8.7-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "perl-doc", pkgver: "5.8.7-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-doc-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to perl-doc-5.8.7-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "perl-modules", pkgver: "5.8.7-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-modules-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to perl-modules-5.8.7-5ubuntu1.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "perl-suid", pkgver: "5.8.7-5ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package perl-suid-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to perl-suid-5.8.7-5ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
