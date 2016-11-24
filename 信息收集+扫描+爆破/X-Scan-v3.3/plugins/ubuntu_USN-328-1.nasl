# This script was automatically generated from the 328-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27907);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "328-1");
script_summary(english:"Apache vulnerability");
script_name(english:"USN328-1 : Apache vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- apache 
- apache-common 
- apache-dbg 
- apache-dev 
- apache-doc 
- apache-perl 
- apache-ssl 
- apache2 
- apache2-common 
- apache2-doc 
- apache2-mpm-perchild 
- apache2-mpm-prefork 
- apache2-mpm-threadpool 
- apache2-mpm-worker 
- apache2-prefork-dev 
- apache2-threaded-dev 
- apache2-utils 
- libapache-mod-perl 
- libapr0 
- libapr0-dev 
');
script_set_attribute(attribute:'description', value: 'Mark Dowd discovered an off-by-one buffer overflow in the mod_rewrite
module\'s ldap scheme handling. On systems which activate
"RewriteEngine on",  a remote attacker could exploit certain rewrite
rules to crash Apache, or potentially even execute arbitrary code
(this has not been verified).

"RewriteEngine on" is disabled by default. Systems which have this
directive disabled are not affected at all.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- apache-1.3.34-2ubuntu0.1 (Ubuntu 6.06)
- apache-common-1.3.34-2ubuntu0.1 (Ubuntu 6.06)
- apache-dbg-1.3.34-2ubuntu0.1 (Ubuntu 6.06)
- apache-dev-1.3.34-2ubuntu0.1 (Ubuntu 6.06)
- apache-doc-1.3.34-2ubuntu0.1 (Ubuntu 6.06)
- apache-perl-1.3.34-2ubuntu0.1 (Ubuntu 6.06)
- apache-ssl-1.3.34-2ubuntu0.1 (Ubuntu 6.06)
- apache2-2.0.55-4ubuntu2.1 (Ubuntu 6.06)
- apache2-common-2.0.55-4ubuntu2.1 (Ubuntu 6.06)
- apache2-doc-2.0.55-4ubuntu2.1 (Ubuntu 6.06)
- apache2-mpm-perchild-2.0.55-4ubuntu2.1 (Ubu
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2006-3747");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "apache", pkgver: "1.3.34-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache-1.3.34-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache-common", pkgver: "1.3.34-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache-common-1.3.34-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache-dbg", pkgver: "1.3.34-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache-dbg-1.3.34-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache-dev", pkgver: "1.3.34-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache-dev-1.3.34-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache-doc", pkgver: "1.3.34-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache-doc-1.3.34-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache-perl", pkgver: "1.3.34-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-perl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache-perl-1.3.34-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache-ssl", pkgver: "1.3.34-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache-ssl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache-ssl-1.3.34-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-2.0.55-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-common", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-common-2.0.55-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-doc", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-doc-2.0.55-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-mpm-perchild", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-perchild-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-mpm-perchild-2.0.55-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-mpm-prefork", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-prefork-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-mpm-prefork-2.0.55-4ubuntu2.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "apache2-mpm-threadpool", pkgver: "2.0.54-5ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-threadpool-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to apache2-mpm-threadpool-2.0.54-5ubuntu4.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-mpm-worker", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-worker-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-mpm-worker-2.0.55-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-prefork-dev", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-prefork-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-prefork-dev-2.0.55-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-threaded-dev", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-threaded-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-threaded-dev-2.0.55-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-utils", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-utils-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-utils-2.0.55-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapache-mod-perl", pkgver: "1.29.0.4-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapache-mod-perl-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapache-mod-perl-1.29.0.4-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapr0", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapr0-2.0.55-4ubuntu2.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapr0-dev", pkgver: "2.0.55-4ubuntu2.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapr0-dev-2.0.55-4ubuntu2.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
