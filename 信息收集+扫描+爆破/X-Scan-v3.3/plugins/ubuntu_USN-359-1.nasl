# This script was automatically generated from the 359-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27939);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "359-1");
script_summary(english:"Python vulnerability");
script_name(english:"USN359-1 : Python vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- idle-python2.3 
- idle-python2.4 
- python2.3 
- python2.3-dbg 
- python2.3-dev 
- python2.3-doc 
- python2.3-examples 
- python2.3-gdbm 
- python2.3-mpz 
- python2.3-tk 
- python2.4 
- python2.4-dbg 
- python2.4-dev 
- python2.4-doc 
- python2.4-examples 
- python2.4-gdbm 
- python2.4-minimal 
- python2.4-tk 
');
script_set_attribute(attribute:'description', value: 'Benjamin C. Wiley Sittler discovered that Python\'s repr() function did
not properly handle UTF-32/UCS-4 strings. If an application uses
repr() on arbitrary untrusted data, this could be exploited to execute
arbitrary code with the privileges of the python application.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- idle-python2.3-2.3.5-9ubuntu1.2 (Ubuntu 6.06)
- idle-python2.4-2.4.3-0ubuntu6 (Ubuntu 6.06)
- python2.3-2.3.5-9ubuntu1.2 (Ubuntu 6.06)
- python2.3-dbg-2.3.5-9ubuntu1.2 (Ubuntu 6.06)
- python2.3-dev-2.3.5-9ubuntu1.2 (Ubuntu 6.06)
- python2.3-doc-2.3.5-9ubuntu1.2 (Ubuntu 6.06)
- python2.3-examples-2.3.5-9ubuntu1.2 (Ubuntu 6.06)
- python2.3-gdbm-2.3.5-9ubuntu1.2 (Ubuntu 6.06)
- python2.3-mpz-2.3.5-9ubuntu1.2 (Ubuntu 6.06)
- python2.3-tk-2.3.5-9ubuntu1.2 (Ubuntu 6.06)
- python2.4-2.4.3-0ubuntu6
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-4980");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "idle-python2.3", pkgver: "2.3.5-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package idle-python2.3-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to idle-python2.3-2.3.5-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "idle-python2.4", pkgver: "2.4.3-0ubuntu6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package idle-python2.4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to idle-python2.4-2.4.3-0ubuntu6
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.3", pkgver: "2.3.5-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.3-2.3.5-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.3-dbg", pkgver: "2.3.5-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.3-dbg-2.3.5-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.3-dev", pkgver: "2.3.5-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.3-dev-2.3.5-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.3-doc", pkgver: "2.3.5-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.3-doc-2.3.5-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.3-examples", pkgver: "2.3.5-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-examples-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.3-examples-2.3.5-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.3-gdbm", pkgver: "2.3.5-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-gdbm-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.3-gdbm-2.3.5-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.3-mpz", pkgver: "2.3.5-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-mpz-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.3-mpz-2.3.5-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.3-tk", pkgver: "2.3.5-9ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.3-tk-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.3-tk-2.3.5-9ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4", pkgver: "2.4.3-0ubuntu6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-2.4.3-0ubuntu6
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-dbg", pkgver: "2.4.3-0ubuntu6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-dbg-2.4.3-0ubuntu6
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-dev", pkgver: "2.4.3-0ubuntu6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-dev-2.4.3-0ubuntu6
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-doc", pkgver: "2.4.3-0ubuntu6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-doc-2.4.3-0ubuntu6
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-examples", pkgver: "2.4.3-0ubuntu6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-examples-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-examples-2.4.3-0ubuntu6
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-gdbm", pkgver: "2.4.3-0ubuntu6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-gdbm-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-gdbm-2.4.3-0ubuntu6
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-minimal", pkgver: "2.4.3-0ubuntu6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-minimal-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-minimal-2.4.3-0ubuntu6
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-tk", pkgver: "2.4.3-0ubuntu6");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-tk-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-tk-2.4.3-0ubuntu6
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
