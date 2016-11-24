# This script was automatically generated from the 813-2 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(40530);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "813-2");
script_summary(english:"apache2 vulnerability");
script_name(english:"USN813-2 : apache2 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- apache2 
- apache2-common 
- apache2-doc 
- apache2-mpm-perchild 
- apache2-mpm-prefork 
- apache2-mpm-worker 
- apache2-prefork-dev 
- apache2-threaded-dev 
- apache2-utils 
- libapr0 
- libapr0-dev 
');
script_set_attribute(attribute:'description', value: 'USN-813-1 fixed vulnerabilities in apr. This update provides the
corresponding updates for apr as provided by Apache on Ubuntu 6.06 LTS.

Original advisory details:

 Matt Lewis discovered that apr did not properly sanitize its input when
 allocating memory. If an application using apr processed crafted input, a
 remote attacker could cause a denial of service or potentially execute
 arbitrary code as the user invoking the application.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- apache2-2.0.55-4ubuntu2.7 (Ubuntu 6.06)
- apache2-common-2.0.55-4ubuntu2.7 (Ubuntu 6.06)
- apache2-doc-2.0.55-4ubuntu2.7 (Ubuntu 6.06)
- apache2-mpm-perchild-2.0.55-4ubuntu2.7 (Ubuntu 6.06)
- apache2-mpm-prefork-2.0.55-4ubuntu2.7 (Ubuntu 6.06)
- apache2-mpm-worker-2.0.55-4ubuntu2.7 (Ubuntu 6.06)
- apache2-prefork-dev-2.0.55-4ubuntu2.7 (Ubuntu 6.06)
- apache2-threaded-dev-2.0.55-4ubuntu2.7 (Ubuntu 6.06)
- apache2-utils-2.0.55-4ubuntu2.7 (Ubuntu 6.06)
- libapr0-2.0.55-4ubuntu2.7 (Ubuntu 6.06)
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2009-2412");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "apache2", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-2.0.55-4ubuntu2.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-common", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-common-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-common-2.0.55-4ubuntu2.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-doc", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-doc-2.0.55-4ubuntu2.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-mpm-perchild", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-perchild-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-mpm-perchild-2.0.55-4ubuntu2.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-mpm-prefork", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-prefork-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-mpm-prefork-2.0.55-4ubuntu2.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-mpm-worker", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-mpm-worker-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-mpm-worker-2.0.55-4ubuntu2.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-prefork-dev", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-prefork-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-prefork-dev-2.0.55-4ubuntu2.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-threaded-dev", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-threaded-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-threaded-dev-2.0.55-4ubuntu2.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "apache2-utils", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package apache2-utils-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to apache2-utils-2.0.55-4ubuntu2.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapr0", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapr0-2.0.55-4ubuntu2.7
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libapr0-dev", pkgver: "2.0.55-4ubuntu2.7");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libapr0-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libapr0-dev-2.0.55-4ubuntu2.7
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
