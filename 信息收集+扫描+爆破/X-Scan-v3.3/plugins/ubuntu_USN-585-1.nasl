# This script was automatically generated from the 585-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(31461);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "585-1");
script_summary(english:"Python vulnerabilities");
script_name(english:"USN585-1 : Python vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- idle-python2.4 
- idle-python2.5 
- python2.4 
- python2.4-dbg 
- python2.4-dev 
- python2.4-doc 
- python2.4-examples 
- python2.4-gdbm 
- python2.4-minimal 
- python2.4-tk 
- python2.5 
- python2.5-dbg 
- python2.5-dev 
- python2.5-doc 
- python2.5-examples 
- python2.5-minimal 
');
script_set_attribute(attribute:'description', value: 'Piotr Engelking discovered that strxfrm in Python was not correctly
calculating the size of the destination buffer.  This could lead to small
information leaks, which might be used by attackers to gain additional
knowledge about the state of a running Python script. (CVE-2007-2052)

A flaw was discovered in the Python imageop module.  If a script using
the module could be tricked into processing a specially crafted set of
arguments, a remote attacker could execute arbitrary code, or cause the
application to crash. (CVE-2007-4965)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- idle-python2.4-2.4.4-6ubuntu4.1 (Ubuntu 7.10)
- idle-python2.5-2.5.1-5ubuntu5.1 (Ubuntu 7.10)
- python2.4-2.4.4-6ubuntu4.1 (Ubuntu 7.10)
- python2.4-dbg-2.4.4-6ubuntu4.1 (Ubuntu 7.10)
- python2.4-dev-2.4.4-6ubuntu4.1 (Ubuntu 7.10)
- python2.4-doc-2.4.4-6ubuntu4.1 (Ubuntu 7.10)
- python2.4-examples-2.4.4-6ubuntu4.1 (Ubuntu 7.10)
- python2.4-gdbm-2.4.3-0ubuntu6.1 (Ubuntu 6.06)
- python2.4-minimal-2.4.4-6ubuntu4.1 (Ubuntu 7.10)
- python2.4-tk-2.4.3-0ubuntu6.1 (Ubuntu 6.06)
- python2.5-2.5.1-5u
[...]');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-2052","CVE-2007-4965");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "idle-python2.4", pkgver: "2.4.4-6ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package idle-python2.4-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to idle-python2.4-2.4.4-6ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "idle-python2.5", pkgver: "2.5.1-5ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package idle-python2.5-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to idle-python2.5-2.5.1-5ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.4", pkgver: "2.4.4-6ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.4-2.4.4-6ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.4-dbg", pkgver: "2.4.4-6ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.4-dbg-2.4.4-6ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.4-dev", pkgver: "2.4.4-6ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.4-dev-2.4.4-6ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.4-doc", pkgver: "2.4.4-6ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.4-doc-2.4.4-6ubuntu4.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.4-examples", pkgver: "2.4.4-6ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-examples-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.4-examples-2.4.4-6ubuntu4.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-gdbm", pkgver: "2.4.3-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-gdbm-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-gdbm-2.4.3-0ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.4-minimal", pkgver: "2.4.4-6ubuntu4.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-minimal-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.4-minimal-2.4.4-6ubuntu4.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-tk", pkgver: "2.4.3-0ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-tk-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-tk-2.4.3-0ubuntu6.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.5", pkgver: "2.5.1-5ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.5-2.5.1-5ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.5-dbg", pkgver: "2.5.1-5ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.5-dbg-2.5.1-5ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.5-dev", pkgver: "2.5.1-5ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.5-dev-2.5.1-5ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.5-doc", pkgver: "2.5.1-5ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.5-doc-2.5.1-5ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.5-examples", pkgver: "2.5.1-5ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-examples-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.5-examples-2.5.1-5ubuntu5.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python2.5-minimal", pkgver: "2.5.1-5ubuntu5.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.5-minimal-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python2.5-minimal-2.5.1-5ubuntu5.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
