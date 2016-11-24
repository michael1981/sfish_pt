# This script was automatically generated from the 437-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28033);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "437-1");
script_summary(english:"libwpd vulnerability");
script_name(english:"USN437-1 : libwpd vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libwpd-stream8c2 
- libwpd-stream8c2a 
- libwpd-tools 
- libwpd8-dev 
- libwpd8-doc 
- libwpd8c2 
- libwpd8c2a 
');
script_set_attribute(attribute:'description', value: 'Sean Larsson of iDefense Labs discovered that libwpd was vulnerable to 
integer overflows.  If a user were tricked into opening a specially 
crafted WordPerfect document with an application that used libwpd, an 
attacker could execute arbitrary code with user privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libwpd-stream8c2-0.8.2-2ubuntu0.1 (Ubuntu 5.10)
- libwpd-stream8c2a-0.8.6-1ubuntu0.1 (Ubuntu 6.10)
- libwpd-tools-0.8.6-1ubuntu0.1 (Ubuntu 6.10)
- libwpd8-dev-0.8.6-1ubuntu0.1 (Ubuntu 6.10)
- libwpd8-doc-0.8.6-1ubuntu0.1 (Ubuntu 6.10)
- libwpd8c2-0.8.2-2ubuntu0.1 (Ubuntu 5.10)
- libwpd8c2a-0.8.6-1ubuntu0.1 (Ubuntu 6.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-0002");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "5.10", pkgname: "libwpd-stream8c2", pkgver: "0.8.2-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwpd-stream8c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libwpd-stream8c2-0.8.2-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libwpd-stream8c2a", pkgver: "0.8.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwpd-stream8c2a-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libwpd-stream8c2a-0.8.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libwpd-tools", pkgver: "0.8.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwpd-tools-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libwpd-tools-0.8.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libwpd8-dev", pkgver: "0.8.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwpd8-dev-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libwpd8-dev-0.8.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libwpd8-doc", pkgver: "0.8.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwpd8-doc-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libwpd8-doc-0.8.6-1ubuntu0.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "libwpd8c2", pkgver: "0.8.2-2ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwpd8c2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to libwpd8c2-0.8.2-2ubuntu0.1
');
}
found = ubuntu_check(osver: "6.10", pkgname: "libwpd8c2a", pkgver: "0.8.6-1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwpd8c2a-',found,' is vulnerable in Ubuntu 6.10
Upgrade it to libwpd8c2a-0.8.6-1ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
