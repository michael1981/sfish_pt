# This script was automatically generated from the 633-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(33808);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "633-1");
script_summary(english:"libxslt vulnerabilities");
script_name(english:"USN633-1 : libxslt vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libxslt1-dbg 
- libxslt1-dev 
- libxslt1.1 
- python-libxslt1 
- python-libxslt1-dbg 
- python2.4-libxslt1 
- xsltproc 
');
script_set_attribute(attribute:'description', value: 'It was discovered that long transformation matches in libxslt could
overflow.  If an attacker were able to make an application linked against
libxslt process malicious XSL style sheet input, they could execute
arbitrary code with user privileges or cause the application to crash,
leading to a denial of serivce. (CVE-2008-1767)

Chris Evans discovered that the RC4 processing code in libxslt did not
correctly handle corrupted key information.  If a remote attacker were
able to make an application linked against libxslt process malicious
XML input, they could crash the application, leading to a denial of
service. (CVE-2008-2935)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxslt1-dbg-1.1.22-1ubuntu1.2 (Ubuntu 8.04)
- libxslt1-dev-1.1.22-1ubuntu1.2 (Ubuntu 8.04)
- libxslt1.1-1.1.22-1ubuntu1.2 (Ubuntu 8.04)
- python-libxslt1-1.1.22-1ubuntu1.2 (Ubuntu 8.04)
- python-libxslt1-dbg-1.1.22-1ubuntu1.2 (Ubuntu 8.04)
- python2.4-libxslt1-1.1.15-1ubuntu1.2 (Ubuntu 6.06)
- xsltproc-1.1.22-1ubuntu1.2 (Ubuntu 8.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2008-1767","CVE-2008-2935");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "libxslt1-dbg", pkgver: "1.1.22-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxslt1-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxslt1-dbg-1.1.22-1ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxslt1-dev", pkgver: "1.1.22-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxslt1-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxslt1-dev-1.1.22-1ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxslt1.1", pkgver: "1.1.22-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxslt1.1-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxslt1.1-1.1.22-1ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python-libxslt1", pkgver: "1.1.22-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-libxslt1-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python-libxslt1-1.1.22-1ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python-libxslt1-dbg", pkgver: "1.1.22-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-libxslt1-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python-libxslt1-dbg-1.1.22-1ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-libxslt1", pkgver: "1.1.15-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-libxslt1-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-libxslt1-1.1.15-1ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "xsltproc", pkgver: "1.1.22-1ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package xsltproc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to xsltproc-1.1.22-1ubuntu1.2
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
