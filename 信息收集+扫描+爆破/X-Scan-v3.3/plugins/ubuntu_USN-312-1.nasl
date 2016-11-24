# This script was automatically generated from the 312-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27887);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "312-1");
script_summary(english:"gimp vulnerability");
script_name(english:"USN312-1 : gimp vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- gimp 
- gimp-data 
- gimp-dbg 
- gimp-helpbrowser 
- gimp-python 
- gimp-svg 
- gimp1.2 
- libgimp2.0 
- libgimp2.0-dev 
- libgimp2.0-doc 
');
script_set_attribute(attribute:'description', value: 'Henning Makholm discovered that gimp did not sufficiently validate the
\'num_axes\' parameter in XCF files. By tricking a user into opening a
specially crafted XCF file with Gimp, an attacker could exploit this
to execute arbitrary code with the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- gimp-2.2.11-1ubuntu3.1 (Ubuntu 6.06)
- gimp-data-2.2.11-1ubuntu3.1 (Ubuntu 6.06)
- gimp-dbg-2.2.11-1ubuntu3.1 (Ubuntu 6.06)
- gimp-helpbrowser-2.2.11-1ubuntu3.1 (Ubuntu 6.06)
- gimp-python-2.2.11-1ubuntu3.1 (Ubuntu 6.06)
- gimp-svg-2.2.11-1ubuntu3.1 (Ubuntu 6.06)
- gimp1.2-2.2.8-2ubuntu6.1 (Ubuntu 5.10)
- libgimp2.0-2.2.11-1ubuntu3.1 (Ubuntu 6.06)
- libgimp2.0-dev-2.2.11-1ubuntu3.1 (Ubuntu 6.06)
- libgimp2.0-doc-2.2.11-1ubuntu3.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:H/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-3404");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "gimp", pkgver: "2.2.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gimp-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gimp-2.2.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "gimp-data", pkgver: "2.2.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gimp-data-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gimp-data-2.2.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "gimp-dbg", pkgver: "2.2.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gimp-dbg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gimp-dbg-2.2.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "gimp-helpbrowser", pkgver: "2.2.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gimp-helpbrowser-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gimp-helpbrowser-2.2.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "gimp-python", pkgver: "2.2.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gimp-python-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gimp-python-2.2.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "gimp-svg", pkgver: "2.2.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gimp-svg-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to gimp-svg-2.2.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "5.10", pkgname: "gimp1.2", pkgver: "2.2.8-2ubuntu6.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package gimp1.2-',found,' is vulnerable in Ubuntu 5.10
Upgrade it to gimp1.2-2.2.8-2ubuntu6.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgimp2.0", pkgver: "2.2.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgimp2.0-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgimp2.0-2.2.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgimp2.0-dev", pkgver: "2.2.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgimp2.0-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgimp2.0-dev-2.2.11-1ubuntu3.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libgimp2.0-doc", pkgver: "2.2.11-1ubuntu3.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libgimp2.0-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libgimp2.0-doc-2.2.11-1ubuntu3.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
