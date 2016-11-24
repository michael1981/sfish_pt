# This script was automatically generated from the 812-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40528);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "812-1");
script_summary(english:"subversion vulnerability");
script_name(english:"USN812-1 : subversion vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libapache2-svn 
- libsvn-core-perl 
- libsvn-dev 
- libsvn-doc 
- libsvn-java 
- libsvn-javahl 
- libsvn-perl 
- libsvn-ruby 
- libsvn-ruby1.8 
- libsvn0 
- libsvn0-dev 
- libsvn1 
- python-subversion 
- python-subversion-dbg 
- python2.4-subversion 
- subversion 
- subversion-tools 
');
script_set_attribute(attribute:'description', value: 'Matt Lewis discovered that Subversion did not properly sanitize its input
when processing svndiff streams, leading to various integer and heap
overflows. If a user or automated system processed crafted input, a remote
attacker could cause a denial of service or potentially execute arbitrary
code as the user processing the input.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libapache2-svn-1.5.4dfsg1-1ubuntu2.1 (Ubuntu 9.04)
- libsvn-core-perl-1.3.1-3ubuntu1.2 (Ubuntu 6.06)
- libsvn-dev-1.5.4dfsg1-1ubuntu2.1 (Ubuntu 9.04)
- libsvn-doc-1.5.4dfsg1-1ubuntu2.1 (Ubuntu 9.04)
- libsvn-java-1.5.4dfsg1-1ubuntu2.1 (Ubuntu 9.04)
- libsvn-javahl-1.4.6dfsg1-2ubuntu1.1 (Ubuntu 8.04)
- libsvn-perl-1.5.4dfsg1-1ubuntu2.1 (Ubuntu 9.04)
- libsvn-ruby-1.5.4dfsg1-1ubuntu2.1 (Ubuntu 9.04)
- libsvn-ruby1.8-1.5.4dfsg1-1ubuntu2.1 (Ubuntu 9.04)
- libsvn0-1.3.1-3ubuntu1.2 (Ubuntu 6.06)

[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:S/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-2411");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "libapache2-svn", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache2-svn-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libapache2-svn-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsvn-core-perl", pkgver: "1.3.1-3ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn-core-perl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsvn-core-perl-1.3.1-3ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsvn-dev", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsvn-dev-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsvn-doc", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn-doc-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsvn-doc-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsvn-java", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn-java-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsvn-java-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libsvn-javahl", pkgver: "1.4.6dfsg1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn-javahl-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libsvn-javahl-1.4.6dfsg1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsvn-perl", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn-perl-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsvn-perl-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsvn-ruby", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn-ruby-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsvn-ruby-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsvn-ruby1.8", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn-ruby1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsvn-ruby1.8-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsvn0", pkgver: "1.3.1-3ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsvn0-1.3.1-3ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libsvn0-dev", pkgver: "1.3.1-3ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn0-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libsvn0-dev-1.3.1-3ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libsvn1", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libsvn1-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libsvn1-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "python-subversion", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-subversion-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to python-subversion-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "python-subversion-dbg", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-subversion-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to python-subversion-dbg-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-subversion", pkgver: "1.3.1-3ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-subversion-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-subversion-1.3.1-3ubuntu1.2
');
}
found = ubuntu_check(osver: "9.04", pkgname: "subversion", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package subversion-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to subversion-1.5.4dfsg1-1ubuntu2.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "subversion-tools", pkgver: "1.5.4dfsg1-1ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package subversion-tools-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to subversion-tools-1.5.4dfsg1-1ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
