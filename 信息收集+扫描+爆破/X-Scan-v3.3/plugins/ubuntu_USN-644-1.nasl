# This script was automatically generated from the 644-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(37936);
script_version("$Revision: 1.1 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "644-1");
script_summary(english:"libxml2 vulnerabilities");
script_name(english:"USN644-1 : libxml2 vulnerabilities");
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
script_set_attribute(attribute:'description', value: 'It was discovered that libxml2 did not correctly handle long entity names.
If a user were tricked into processing a specially crafted XML document,
a remote attacker could execute arbitrary code with user privileges
or cause the application linked against libxml2 to crash, leading to a
denial of service. (CVE-2008-3529)

USN-640-1 fixed vulnerabilities in libxml2.  When processing extremely
large XML documents with valid entities, it was possible to incorrectly
trigger the newly added vulnerability protections.  This update fixes
the problem.  (CVE-2008-3281)');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxml2-2.6.31.dfsg-2ubuntu1.2 (Ubuntu 8.04)
- libxml2-dbg-2.6.31.dfsg-2ubuntu1.2 (Ubuntu 8.04)
- libxml2-dev-2.6.31.dfsg-2ubuntu1.2 (Ubuntu 8.04)
- libxml2-doc-2.6.31.dfsg-2ubuntu1.2 (Ubuntu 8.04)
- libxml2-utils-2.6.31.dfsg-2ubuntu1.2 (Ubuntu 8.04)
- python-libxml2-2.6.31.dfsg-2ubuntu1.2 (Ubuntu 8.04)
- python-libxml2-dbg-2.6.31.dfsg-2ubuntu1.2 (Ubuntu 8.04)
- python2.4-libxml2-2.6.24.dfsg-1ubuntu1.3 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-3281","CVE-2008-3529");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.04", pkgname: "libxml2", pkgver: "2.6.31.dfsg-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxml2-2.6.31.dfsg-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxml2-dbg", pkgver: "2.6.31.dfsg-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxml2-dbg-2.6.31.dfsg-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxml2-dev", pkgver: "2.6.31.dfsg-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-dev-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxml2-dev-2.6.31.dfsg-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxml2-doc", pkgver: "2.6.31.dfsg-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-doc-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxml2-doc-2.6.31.dfsg-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "libxml2-utils", pkgver: "2.6.31.dfsg-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-utils-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to libxml2-utils-2.6.31.dfsg-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python-libxml2", pkgver: "2.6.31.dfsg-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-libxml2-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python-libxml2-2.6.31.dfsg-2ubuntu1.2
');
}
found = ubuntu_check(osver: "8.04", pkgname: "python-libxml2-dbg", pkgver: "2.6.31.dfsg-2ubuntu1.2");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-libxml2-dbg-',found,' is vulnerable in Ubuntu 8.04
Upgrade it to python-libxml2-dbg-2.6.31.dfsg-2ubuntu1.2
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-libxml2", pkgver: "2.6.24.dfsg-1ubuntu1.3");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-libxml2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-libxml2-2.6.24.dfsg-1ubuntu1.3
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
