# This script was automatically generated from the 651-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37068);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "651-1");
script_summary(english:"ruby1.8 vulnerabilities");
script_name(english:"USN651-1 : ruby1.8 vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'Akira Tagoh discovered a vulnerability in Ruby which lead to an integer
overflow. If a user or automated system were tricked into running a
malicious script, an attacker could cause a denial of service or
possibly execute arbitrary code with the privileges of the user
invoking the program. (CVE-2008-2376)

Laurent Gaffie discovered that Ruby did not properly check for memory
allocation failures. If a user or automated system were tricked into
running a malicious script, an attacker could cause a denial of
service. (CVE-2008-3443)

Keita Yamaguchi discovered several safe level vulnerabilities in Ruby.
An attacker could use this to bypass intended access restrictions.
(CVE-2008-3655)

Keita Yamaguchi discovered that WEBrick in Ruby did not properly
validate paths ending with ".". A remote attacker could send a crafted
HTTP request and cause a denial of service. (CVE-2008-3656)

Keita Yamaguchi discovered that the dl module in Ruby did not check
the taintness of inputs. An attacker could exploit this vulnerabil
[...]');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- irb1.8-1.8.6.111-2ubuntu1.2 (Ubuntu 8.04)
- libdbm-ruby1.8-1.8.6.111-2ubuntu1.2 (Ubuntu 8.04)
- libgdbm-ruby1.8-1.8.6.111-2ubuntu1.2 (Ubuntu 8.04)
- libopenssl-ruby1.8-1.8.6.111-2ubuntu1.2 (Ubuntu 8.04)
- libreadline-ruby1.8-1.8.6.111-2ubuntu1.2 (Ubuntu 8.04)
- libruby1.8-1.8.6.111-2ubuntu1.2 (Ubuntu 8.04)
- libruby1.8-dbg-1.8.6.111-2ubuntu1.2 (Ubuntu 8.04)
- libtcltk-ruby1.8-1.8.6.111-2ubuntu1.2 (Ubuntu 8.04)
- rdoc1.8-1.8.6.111-2ubuntu1.2 (Ubuntu 8.04)
- ri1.8-1.8.6.111-2ubuntu1.2 (Ubuntu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:C');
script_end_attributes();

script_cve_id("CVE-2008-1447","CVE-2008-2376","CVE-2008-3443","CVE-2008-3655","CVE-2008-3656","CVE-2008-3657","CVE-2008-3790","CVE-2008-3905");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "irb1.8", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package irb1.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to irb1.8-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libdbm-ruby1.8", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libdbm-ruby1.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libdbm-ruby1.8-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libgdbm-ruby1.8", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgdbm-ruby1.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libgdbm-ruby1.8-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libopenssl-ruby1.8", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libopenssl-ruby1.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libopenssl-ruby1.8-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libreadline-ruby1.8", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libreadline-ruby1.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libreadline-ruby1.8-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libruby1.8", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libruby1.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libruby1.8-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libruby1.8-dbg", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libruby1.8-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libruby1.8-dbg-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libtcltk-ruby1.8", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libtcltk-ruby1.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libtcltk-ruby1.8-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "rdoc1.8", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package rdoc1.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to rdoc1.8-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "ri1.8", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ri1.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ri1.8-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "ruby1.8", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ruby1.8-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "ruby1.8-dev", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ruby1.8-dev-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "ruby1.8-elisp", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-elisp-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ruby1.8-elisp-1.8.6.111-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "ruby1.8-examples", pkgver: "1.8.6.111-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package ruby1.8-examples-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to ruby1.8-examples-1.8.6.111-2ubuntu1.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
