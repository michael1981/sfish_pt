# This script was automatically generated from the 691-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37474);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "691-1");
script_summary(english:"ruby1.9 vulnerability");
script_name(english:"USN691-1 : ruby1.9 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- irb1.9 
- libdbm-ruby1.9 
- libgdbm-ruby1.9 
- libopenssl-ruby1.9 
- libreadline-ruby1.9 
- libruby1.9 
- libruby1.9-dbg 
- libtcltk-ruby1.9 
- rdoc1.9 
- ri1.9 
- ruby1.9 
- ruby1.9-dev 
- ruby1.9-elisp 
- ruby1.9-examples 
');
script_set_attribute(attribute:'description', value: 'Laurent Gaffie discovered that Ruby did not properly check for memory
allocation failures. If a user or automated system were tricked into
running a malicious script, an attacker could cause a denial of
service. (CVE-2008-3443)

This update also fixes a regression in the upstream patch previously
applied to fix CVE-2008-3790. The regression would cause parsing of
some XML documents to fail.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- irb1.9-1.9.0.2-7ubuntu1.1 (Ubuntu 8.10)
- libdbm-ruby1.9-1.9.0.2-7ubuntu1.1 (Ubuntu 8.10)
- libgdbm-ruby1.9-1.9.0.2-7ubuntu1.1 (Ubuntu 8.10)
- libopenssl-ruby1.9-1.9.0.2-7ubuntu1.1 (Ubuntu 8.10)
- libreadline-ruby1.9-1.9.0.2-7ubuntu1.1 (Ubuntu 8.10)
- libruby1.9-1.9.0.2-7ubuntu1.1 (Ubuntu 8.10)
- libruby1.9-dbg-1.9.0.2-7ubuntu1.1 (Ubuntu 8.10)
- libtcltk-ruby1.9-1.9.0.2-7ubuntu1.1 (Ubuntu 8.10)
- rdoc1.9-1.9.0.2-7ubuntu1.1 (Ubuntu 8.10)
- ri1.9-1.9.0.2-7ubuntu1.1 (Ubuntu 8.10)
- ruby1.9-1.9
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2008-3443","CVE-2008-3790");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "irb1.9", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package irb1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to irb1.9-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libdbm-ruby1.9", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbm-ruby1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libdbm-ruby1.9-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libgdbm-ruby1.9", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgdbm-ruby1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libgdbm-ruby1.9-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libopenssl-ruby1.9", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopenssl-ruby1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libopenssl-ruby1.9-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libreadline-ruby1.9", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libreadline-ruby1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libreadline-ruby1.9-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libruby1.9", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libruby1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libruby1.9-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libruby1.9-dbg", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libruby1.9-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libruby1.9-dbg-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libtcltk-ruby1.9", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtcltk-ruby1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libtcltk-ruby1.9-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "rdoc1.9", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rdoc1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to rdoc1.9-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ri1.9", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ri1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ri1.9-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ruby1.9", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.9-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ruby1.9-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ruby1.9-dev", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.9-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ruby1.9-dev-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ruby1.9-elisp", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.9-elisp-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ruby1.9-elisp-1.9.0.2-7ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "ruby1.9-examples", pkgver: "1.9.0.2-7ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.9-examples-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to ruby1.9-examples-1.9.0.2-7ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
