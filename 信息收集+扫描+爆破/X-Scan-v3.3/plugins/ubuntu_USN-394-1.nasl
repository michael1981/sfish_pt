# This script was automatically generated from the 394-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27980);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "394-1");
script_summary(english:"Ruby vulnerability");
script_name(english:"USN394-1 : Ruby vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- irb1.8 
- libdbm-ruby1.8 
- libgdbm-ruby1.8 
- libopenssl-ruby1.8 
- libreadline-ruby1.8 
- libruby1.8 
- libruby1.8-dbg 
- libtcltk-ruby1.8 
- rdoc1.8 
- ri1.8 
- ruby1.8 
- ruby1.8-dev 
- ruby1.8-elisp 
- ruby1.8-examples 
');
script_set_attribute(attribute:'description', value: 'An error was found in Ruby\'s CGI library that did not correctly quote 
the boundary of multipart MIME requests.  Using a crafted HTTP request, 
a remote user could cause a denial of service, where Ruby CGI 
applications would end up in a loop, monopolizing a CPU.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- irb1.8-1.8.4-5ubuntu1.2 (Ubuntu 6.10)
- libdbm-ruby1.8-1.8.4-5ubuntu1.2 (Ubuntu 6.10)
- libgdbm-ruby1.8-1.8.4-5ubuntu1.2 (Ubuntu 6.10)
- libopenssl-ruby1.8-1.8.4-5ubuntu1.2 (Ubuntu 6.10)
- libreadline-ruby1.8-1.8.4-5ubuntu1.2 (Ubuntu 6.10)
- libruby1.8-1.8.4-5ubuntu1.2 (Ubuntu 6.10)
- libruby1.8-dbg-1.8.4-5ubuntu1.2 (Ubuntu 6.10)
- libtcltk-ruby1.8-1.8.4-5ubuntu1.2 (Ubuntu 6.10)
- rdoc1.8-1.8.4-5ubuntu1.2 (Ubuntu 6.10)
- ri1.8-1.8.4-5ubuntu1.2 (Ubuntu 6.10)
- ruby1.8-1.8.4-5ubuntu1.2 (Ubunt
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2006-6303");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.10", pkgname: "irb1.8", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package irb1.8-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to irb1.8-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libdbm-ruby1.8", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbm-ruby1.8-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libdbm-ruby1.8-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libgdbm-ruby1.8", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgdbm-ruby1.8-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libgdbm-ruby1.8-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libopenssl-ruby1.8", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopenssl-ruby1.8-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libopenssl-ruby1.8-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libreadline-ruby1.8", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libreadline-ruby1.8-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libreadline-ruby1.8-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libruby1.8", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libruby1.8-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libruby1.8-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libruby1.8-dbg", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libruby1.8-dbg-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libruby1.8-dbg-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libtcltk-ruby1.8", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtcltk-ruby1.8-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libtcltk-ruby1.8-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "rdoc1.8", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rdoc1.8-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to rdoc1.8-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "ri1.8", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ri1.8-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to ri1.8-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "ruby1.8", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to ruby1.8-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "ruby1.8-dev", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to ruby1.8-dev-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "ruby1.8-elisp", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-elisp-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to ruby1.8-elisp-1.8.4-5ubuntu1.2
');
}
found = ubuntu_check(osver: "6.10", pkgname: "ruby1.8-examples", pkgver: "1.8.4-5ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-examples-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to ruby1.8-examples-1.8.4-5ubuntu1.2
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
