# This script was automatically generated from the 604-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(32054);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "604-1");
script_summary(english:"Gnumeric vulnerability");
script_name(english:"USN604-1 : Gnumeric vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gnumeric 
- gnumeric-common 
- gnumeric-doc 
- gnumeric-gtk 
- gnumeric-plugins-extra 
');
script_set_attribute(attribute:'description', value: 'Thilo Pfennig and Morten Welinder discovered that the XLS spreadsheet
handling code in Gnumeric did not correctly calculate needed memory sizes.
If a user or automated system were tricked into loading a specially crafted
XLS document, a remote attacker could execute arbitrary code with user
privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gnumeric-1.7.11-1ubuntu3.1 (Ubuntu 7.10)
- gnumeric-common-1.7.11-1ubuntu3.1 (Ubuntu 7.10)
- gnumeric-doc-1.7.11-1ubuntu3.1 (Ubuntu 7.10)
- gnumeric-gtk-1.7.11-1ubuntu3.1 (Ubuntu 7.10)
- gnumeric-plugins-extra-1.7.11-1ubuntu3.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2008-0668");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "gnumeric", pkgver: "1.7.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnumeric-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to gnumeric-1.7.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "gnumeric-common", pkgver: "1.7.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnumeric-common-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to gnumeric-common-1.7.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "gnumeric-doc", pkgver: "1.7.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnumeric-doc-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to gnumeric-doc-1.7.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "gnumeric-gtk", pkgver: "1.7.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnumeric-gtk-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to gnumeric-gtk-1.7.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "gnumeric-plugins-extra", pkgver: "1.7.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gnumeric-plugins-extra-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to gnumeric-plugins-extra-1.7.11-1ubuntu3.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
