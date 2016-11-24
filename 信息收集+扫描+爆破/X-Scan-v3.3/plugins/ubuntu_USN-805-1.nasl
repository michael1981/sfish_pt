# This script was automatically generated from the 805-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40329);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "805-1");
script_summary(english:"ruby1.8, ruby1.9 vulnerabilities");
script_name(english:"USN805-1 : ruby1.8, ruby1.9 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- irb1.8 
- irb1.9 
- libdbm-ruby1.8 
- libdbm-ruby1.9 
- libgdbm-ruby1.8 
- libgdbm-ruby1.9 
- libopenssl-ruby1.8 
- libopenssl-ruby1.9 
- libreadline-ruby1.8 
- libreadline-ruby1.9 
- libruby1.8 
- libruby1.8-dbg 
- libruby1.9 
- libruby1.9-dbg 
- libtcltk-ruby1.8 
- libtcltk-ruby1.9 
- rdoc1.8 
- rdoc1.9 
- ri1.8 
- ri1.9 
- ruby1.8 
- ruby1.8-dev 
- ruby1.8-elisp 
- ruby1.8-examples 
- ruby1.9 
- ruby1.9-dev 
- ruby1.9-elisp 
- ruby1.9-examples 
');
script_set_attribute(attribute:'description', value: 'It was discovered that Ruby did not properly validate certificates. An
attacker could exploit this and present invalid or revoked X.509
certificates. (CVE-2009-0642)

It was discovered that Ruby did not properly handle string arguments that
represent large numbers. An attacker could exploit this and cause a denial
of service. (CVE-2009-1904)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- irb1.8-1.8.7.72-3ubuntu0.1 (Ubuntu 9.04)
- irb1.9-1.9.0.2-9ubuntu1.1 (Ubuntu 9.04)
- libdbm-ruby1.8-1.8.7.72-3ubuntu0.1 (Ubuntu 9.04)
- libdbm-ruby1.9-1.9.0.2-9ubuntu1.1 (Ubuntu 9.04)
- libgdbm-ruby1.8-1.8.7.72-3ubuntu0.1 (Ubuntu 9.04)
- libgdbm-ruby1.9-1.9.0.2-9ubuntu1.1 (Ubuntu 9.04)
- libopenssl-ruby1.8-1.8.7.72-3ubuntu0.1 (Ubuntu 9.04)
- libopenssl-ruby1.9-1.9.0.2-9ubuntu1.1 (Ubuntu 9.04)
- libreadline-ruby1.8-1.8.7.72-3ubuntu0.1 (Ubuntu 9.04)
- libreadline-ruby1.9-1.9.0.2-9ubuntu1.1 (U
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-0642","CVE-2009-1904");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "9.04", pkgname: "irb1.8", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package irb1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to irb1.8-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "irb1.9", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package irb1.9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to irb1.9-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libdbm-ruby1.8", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbm-ruby1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libdbm-ruby1.8-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libdbm-ruby1.9", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbm-ruby1.9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libdbm-ruby1.9-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libgdbm-ruby1.8", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgdbm-ruby1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libgdbm-ruby1.8-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libgdbm-ruby1.9", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgdbm-ruby1.9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libgdbm-ruby1.9-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libopenssl-ruby1.8", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopenssl-ruby1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libopenssl-ruby1.8-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libopenssl-ruby1.9", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopenssl-ruby1.9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libopenssl-ruby1.9-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libreadline-ruby1.8", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libreadline-ruby1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libreadline-ruby1.8-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libreadline-ruby1.9", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libreadline-ruby1.9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libreadline-ruby1.9-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libruby1.8", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libruby1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libruby1.8-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libruby1.8-dbg", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libruby1.8-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libruby1.8-dbg-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libruby1.9", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libruby1.9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libruby1.9-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libruby1.9-dbg", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libruby1.9-dbg-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libruby1.9-dbg-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libtcltk-ruby1.8", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtcltk-ruby1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libtcltk-ruby1.8-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "libtcltk-ruby1.9", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtcltk-ruby1.9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to libtcltk-ruby1.9-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "rdoc1.8", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rdoc1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to rdoc1.8-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "rdoc1.9", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rdoc1.9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to rdoc1.9-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ri1.8", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ri1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ri1.8-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ri1.9", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ri1.9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ri1.9-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ruby1.8", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ruby1.8-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ruby1.8-dev", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ruby1.8-dev-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ruby1.8-elisp", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-elisp-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ruby1.8-elisp-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ruby1.8-examples", pkgver: "1.8.7.72-3ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-examples-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ruby1.8-examples-1.8.7.72-3ubuntu0.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ruby1.9", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.9-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ruby1.9-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ruby1.9-dev", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.9-dev-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ruby1.9-dev-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ruby1.9-elisp", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.9-elisp-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ruby1.9-elisp-1.9.0.2-9ubuntu1.1
');
}
found = ubuntu_check(osver: "9.04", pkgname: "ruby1.9-examples", pkgver: "1.9.0.2-9ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.9-examples-',found,' is vulnerable in Ubuntu 9.04
Upgrade it to ruby1.9-examples-1.9.0.2-9ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
