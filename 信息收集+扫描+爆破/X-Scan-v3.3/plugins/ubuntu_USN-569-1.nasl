# This script was automatically generated from the 569-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(29979);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "569-1");
script_summary(english:"libxml2 vulnerability");
script_name(english:"USN569-1 : libxml2 vulnerability");
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
script_set_attribute(attribute:'description', value: 'Brad Fitzpatrick discovered that libxml2 did not correctly handle certain
UTF-8 sequences.  If a remote attacker were able to trick a user or
automated system into processing a specially crafted XML document, the
application linked against libxml2 could enter an infinite loop, leading
to a denial of service via CPU resource consumption.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libxml2-2.6.30.dfsg-2ubuntu1.1 (Ubuntu 7.10)
- libxml2-dbg-2.6.30.dfsg-2ubuntu1.1 (Ubuntu 7.10)
- libxml2-dev-2.6.30.dfsg-2ubuntu1.1 (Ubuntu 7.10)
- libxml2-doc-2.6.30.dfsg-2ubuntu1.1 (Ubuntu 7.10)
- libxml2-utils-2.6.30.dfsg-2ubuntu1.1 (Ubuntu 7.10)
- python-libxml2-2.6.30.dfsg-2ubuntu1.1 (Ubuntu 7.10)
- python-libxml2-dbg-2.6.30.dfsg-2ubuntu1.1 (Ubuntu 7.10)
- python2.4-libxml2-2.6.24.dfsg-1ubuntu1.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:N/I:N/A:P');
script_end_attributes();

script_cve_id("CVE-2007-6284");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "libxml2", pkgver: "2.6.30.dfsg-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libxml2-2.6.30.dfsg-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libxml2-dbg", pkgver: "2.6.30.dfsg-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libxml2-dbg-2.6.30.dfsg-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libxml2-dev", pkgver: "2.6.30.dfsg-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libxml2-dev-2.6.30.dfsg-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libxml2-doc", pkgver: "2.6.30.dfsg-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libxml2-doc-2.6.30.dfsg-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "libxml2-utils", pkgver: "2.6.30.dfsg-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libxml2-utils-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to libxml2-utils-2.6.30.dfsg-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python-libxml2", pkgver: "2.6.30.dfsg-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-libxml2-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python-libxml2-2.6.30.dfsg-2ubuntu1.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "python-libxml2-dbg", pkgver: "2.6.30.dfsg-2ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python-libxml2-dbg-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to python-libxml2-dbg-2.6.30.dfsg-2ubuntu1.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "python2.4-libxml2", pkgver: "2.6.24.dfsg-1ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package python2.4-libxml2-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to python2.4-libxml2-2.6.24.dfsg-1ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
