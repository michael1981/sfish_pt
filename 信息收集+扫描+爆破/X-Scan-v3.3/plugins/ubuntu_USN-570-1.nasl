# This script was automatically generated from the 570-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(30018);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "570-1");
script_summary(english:"boost vulnerabilities");
script_name(english:"USN570-1 : boost vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- bcp 
- libboost-date-time-dev 
- libboost-date-time1.33.1 
- libboost-date-time1.34.1 
- libboost-dbg 
- libboost-dev 
- libboost-doc 
- libboost-filesystem-dev 
- libboost-filesystem1.33.1 
- libboost-filesystem1.34.1 
- libboost-graph-dev 
- libboost-graph1.33.1 
- libboost-graph1.34.1 
- libboost-iostreams-dev 
- libboost-iostreams1.33.1 
- libboost-iostreams1.34.1 
- libboost-program-options-dev 
- libboost-program-options1.33.1 
- libboost-program
[...]');
script_set_attribute(attribute:'description', value: 'Will Drewry and Tavis Ormandy discovered that the boost library 
did not properly perform input validation on regular expressions.
An attacker could send a specially crafted regular expression to
an application linked against boost and cause a denial of service
via application crash.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- bcp-1.34.1-2ubuntu1.1 (Ubuntu 7.10)
- libboost-date-time-dev-1.34.1-2ubuntu1.1 (Ubuntu 7.10)
- libboost-date-time1.33.1-1.33.1-9ubuntu3.1 (Ubuntu 7.04)
- libboost-date-time1.34.1-1.34.1-2ubuntu1.1 (Ubuntu 7.10)
- libboost-dbg-1.34.1-2ubuntu1.1 (Ubuntu 7.10)
- libboost-dev-1.34.1-2ubuntu1.1 (Ubuntu 7.10)
- libboost-doc-1.34.1-2ubuntu1.1 (Ubuntu 7.10)
- libboost-filesystem-dev-1.34.1-2ubuntu1.1 (Ubuntu 7.10)
- libboost-filesystem1.33.1-1.33.1-9ubuntu3.1 (Ubuntu 7.04)
- libboost-filesystem1.34
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2008-0171","CVE-2008-0172");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "bcp", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package bcp-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to bcp-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-date-time-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-date-time-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-date-time-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libboost-date-time1.33.1", pkgver: "1.33.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-date-time1.33.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libboost-date-time1.33.1-1.33.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-date-time1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-date-time1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-date-time1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-dbg", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-dbg-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-doc", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-doc-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-filesystem-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-filesystem-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-filesystem-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libboost-filesystem1.33.1", pkgver: "1.33.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-filesystem1.33.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libboost-filesystem1.33.1-1.33.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-filesystem1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-filesystem1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-filesystem1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-graph-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-graph-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-graph-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libboost-graph1.33.1", pkgver: "1.33.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-graph1.33.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libboost-graph1.33.1-1.33.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-graph1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-graph1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-graph1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-iostreams-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-iostreams-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-iostreams-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libboost-iostreams1.33.1", pkgver: "1.33.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-iostreams1.33.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libboost-iostreams1.33.1-1.33.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-iostreams1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-iostreams1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-iostreams1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-program-options-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-program-options-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-program-options-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libboost-program-options1.33.1", pkgver: "1.33.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-program-options1.33.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libboost-program-options1.33.1-1.33.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-program-options1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-program-options1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-program-options1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-python-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-python-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-python-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libboost-python1.33.1", pkgver: "1.33.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-python1.33.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libboost-python1.33.1-1.33.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-python1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-python1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-python1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-regex-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-regex-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-regex-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libboost-regex1.33.1", pkgver: "1.33.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-regex1.33.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libboost-regex1.33.1-1.33.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-regex1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-regex1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-regex1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-serialization-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-serialization-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-serialization-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-serialization1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-serialization1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-serialization1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-signals-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-signals-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-signals-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libboost-signals1.33.1", pkgver: "1.33.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-signals1.33.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libboost-signals1.33.1-1.33.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-signals1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-signals1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-signals1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-test-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-test-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-test-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libboost-test1.33.1", pkgver: "1.33.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-test1.33.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libboost-test1.33.1-1.33.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-test1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-test1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-test1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-thread-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-thread-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-thread-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libboost-thread1.33.1", pkgver: "1.33.1-9ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-thread1.33.1-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libboost-thread1.33.1-1.33.1-9ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-thread1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-thread1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-thread1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-wave-dev", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-wave-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-wave-dev-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libboost-wave1.34.1", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libboost-wave1.34.1-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libboost-wave1.34.1-1.34.1-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "pyste", pkgver: "1.34.1-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package pyste-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to pyste-1.34.1-2ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
