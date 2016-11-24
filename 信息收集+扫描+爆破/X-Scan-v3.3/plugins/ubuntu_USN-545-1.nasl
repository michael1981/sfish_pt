# This script was automatically generated from the 545-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28357);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "545-1");
script_summary(english:"link-grammar vulnerability");
script_name(english:"USN545-1 : link-grammar vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- liblink-grammar4 
- liblink-grammar4-dev 
- link-grammar 
- link-grammar-dictionaries-en 
');
script_set_attribute(attribute:'description', value: 'Alin Rad Pop discovered that AbiWord\'s Link Grammar parser did not
correctly handle overly-long words.  If a user were tricked into opening
a specially crafted document, AbiWord, or other applications using Link
Grammar, could be made to crash.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- liblink-grammar4-4.2.2-4ubuntu0.7.10.1 (Ubuntu 7.10)
- liblink-grammar4-dev-4.2.2-4ubuntu0.7.10.1 (Ubuntu 7.10)
- link-grammar-4.2.2-4ubuntu0.7.10.1 (Ubuntu 7.10)
- link-grammar-dictionaries-en-4.2.2-4ubuntu0.7.10.1 (Ubuntu 7.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:C/I:C/A:C');
script_end_attributes();

script_cve_id("CVE-2007-5395");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.10", pkgname: "liblink-grammar4", pkgver: "4.2.2-4ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblink-grammar4-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to liblink-grammar4-4.2.2-4ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "liblink-grammar4-dev", pkgver: "4.2.2-4ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package liblink-grammar4-dev-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to liblink-grammar4-dev-4.2.2-4ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "link-grammar", pkgver: "4.2.2-4ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package link-grammar-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to link-grammar-4.2.2-4ubuntu0.7.10.1
');
}
found = ubuntu_check(osver: "7.10", pkgname: "link-grammar-dictionaries-en", pkgver: "4.2.2-4ubuntu0.7.10.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package link-grammar-dictionaries-en-',found,' is vulnerable in Ubuntu 7.10
Upgrade it to link-grammar-dictionaries-en-4.2.2-4ubuntu0.7.10.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
