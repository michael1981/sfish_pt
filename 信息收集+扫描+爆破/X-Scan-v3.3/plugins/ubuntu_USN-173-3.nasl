# This script was automatically generated from the 173-3 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(20582);
script_version("$Revision: 1.5 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "173-3");
script_summary(english:"apache2 bug fix");
script_name(english:"USN173-3 : apache2 bug fix");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- apache2 
- apache2-common 
- apache2-doc 
- apache2-mpm-perchild 
- apache2-mpm-prefork 
- apache2-mpm-threadpool 
- apache2-mpm-worker 
- apache2-prefork-dev 
- apache2-threaded-dev 
- libapr0 
- libapr0-dev 
');
script_set_attribute(attribute:'description', value: 'USN-173-2 fixed a vulnerability in Apache\'s regular expression parser.
However, the packages from that advisories had a bug that prevented
Apache from starting. This update fixes this.

We apologize for the inconvenience!');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- apache2-2.0.50-12ubuntu4.6 (Ubuntu 4.10)
- apache2-common-2.0.50-12ubuntu4.6 (Ubuntu 4.10)
- apache2-doc-2.0.50-12ubuntu4.6 (Ubuntu 4.10)
- apache2-mpm-perchild-2.0.50-12ubuntu4.6 (Ubuntu 4.10)
- apache2-mpm-prefork-2.0.50-12ubuntu4.6 (Ubuntu 4.10)
- apache2-mpm-threadpool-2.0.50-12ubuntu4.6 (Ubuntu 4.10)
- apache2-mpm-worker-2.0.50-12ubuntu4.6 (Ubuntu 4.10)
- apache2-prefork-dev-2.0.50-12ubuntu4.6 (Ubuntu 4.10)
- apache2-threaded-dev-2.0.50-12ubuntu4.6 (Ubuntu 4.10)
- libapr0-2.0.50-12ubun
[...]');
script_set_attribute(attribute: 'risk_factor', value: 'High');
script_end_attributes();

exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "4.10", pkgname: "apache2", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-2.0.50-12ubuntu4.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-common", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-common-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-common-2.0.50-12ubuntu4.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-doc", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-doc-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-doc-2.0.50-12ubuntu4.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-mpm-perchild", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-perchild-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-mpm-perchild-2.0.50-12ubuntu4.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-mpm-prefork", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-prefork-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-mpm-prefork-2.0.50-12ubuntu4.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-mpm-threadpool", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-threadpool-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-mpm-threadpool-2.0.50-12ubuntu4.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-mpm-worker", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-worker-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-mpm-worker-2.0.50-12ubuntu4.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-prefork-dev", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-prefork-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-prefork-dev-2.0.50-12ubuntu4.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "apache2-threaded-dev", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-threaded-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to apache2-threaded-dev-2.0.50-12ubuntu4.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libapr0", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapr0-2.0.50-12ubuntu4.6
');
}
found = ubuntu_check(osver: "4.10", pkgname: "libapr0-dev", pkgver: "2.0.50-12ubuntu4.6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-dev-',found,' is vulnerable in Ubuntu 4.10
Upgrade it to libapr0-dev-2.0.50-12ubuntu4.6
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
