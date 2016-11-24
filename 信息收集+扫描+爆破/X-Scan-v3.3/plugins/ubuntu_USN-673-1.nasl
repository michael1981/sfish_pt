# This script was automatically generated from the 673-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(36916);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "673-1");
script_summary(english:"libxml2 vulnerabilities");
script_name(english:"USN673-1 : libxml2 vulnerabilities");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libxml2 
- libxml2-dbg 
- libxml2-dev 
- libxml2-doc 
- libxml2-utils 
- python-libxml2 
- python-libxml2-dbg 
- python2.4-libxml2 
');
script_set_attribute(attribute:'description', value: 'Drew Yao discovered that libxml2 did not correctly handle certain corrupt
XML documents.  If a user or automated system were tricked into processing
a malicious XML document, a remote attacker could cause applications
linked against libxml2 to enter an infinite loop, leading to a denial
of service. (CVE-2008-4225)

Drew Yao discovered that libxml2 did not correctly handle large memory
allocations.  If a user or automated system were tricked into processing a
very large XML document, a remote attacker could cause applications linked
against libxml2 to crash, leading to a denial of service. (CVE-2008-4226)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxml2-2.6.32.dfsg-4ubuntu1.1 (Ubuntu 8.10)
- libxml2-dbg-2.6.32.dfsg-4ubuntu1.1 (Ubuntu 8.10)
- libxml2-dev-2.6.32.dfsg-4ubuntu1.1 (Ubuntu 8.10)
- libxml2-doc-2.6.32.dfsg-4ubuntu1.1 (Ubuntu 8.10)
- libxml2-utils-2.6.32.dfsg-4ubuntu1.1 (Ubuntu 8.10)
- python-libxml2-2.6.32.dfsg-4ubuntu1.1 (Ubuntu 8.10)
- python-libxml2-dbg-2.6.32.dfsg-4ubuntu1.1 (Ubuntu 8.10)
- python2.4-libxml2-2.6.24.dfsg-1ubuntu1.4 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-4225","CVE-2008-4226");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libxml2", pkgver: "2.6.32.dfsg-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxml2-2.6.32.dfsg-4ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxml2-dbg", pkgver: "2.6.32.dfsg-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxml2-dbg-2.6.32.dfsg-4ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxml2-dev", pkgver: "2.6.32.dfsg-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxml2-dev-2.6.32.dfsg-4ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxml2-doc", pkgver: "2.6.32.dfsg-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxml2-doc-2.6.32.dfsg-4ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libxml2-utils", pkgver: "2.6.32.dfsg-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-utils-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libxml2-utils-2.6.32.dfsg-4ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "python-libxml2", pkgver: "2.6.32.dfsg-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-libxml2-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-libxml2-2.6.32.dfsg-4ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "python-libxml2-dbg", pkgver: "2.6.32.dfsg-4ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-libxml2-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to python-libxml2-dbg-2.6.32.dfsg-4ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-libxml2", pkgver: "2.6.24.dfsg-1ubuntu1.4");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-libxml2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-libxml2-2.6.24.dfsg-1ubuntu1.4
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
