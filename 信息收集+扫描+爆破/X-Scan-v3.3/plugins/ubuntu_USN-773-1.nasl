# This script was automatically generated from the 773-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(38716);
script_version("$Revision: 1.2 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "773-1");
script_summary(english:"pango1.0 vulnerability");
script_name(english:"USN773-1 : pango1.0 vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libpango1.0-0 
- libpango1.0-0-dbg 
- libpango1.0-common 
- libpango1.0-dev 
- libpango1.0-doc 
');
script_set_attribute(attribute:'description', value: 'Will Drewry discovered that Pango incorrectly handled rendering text with
long glyphstrings. If a user were tricked into displaying specially crafted
data with applications linked against Pango, such as Firefox, an attacker
could cause a denial of service or execute arbitrary code with privileges
of the user invoking the program.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libpango1.0-0-1.22.2-0ubuntu1.1 (Ubuntu 8.10)
- libpango1.0-0-dbg-1.22.2-0ubuntu1.1 (Ubuntu 8.10)
- libpango1.0-common-1.22.2-0ubuntu1.1 (Ubuntu 8.10)
- libpango1.0-dev-1.22.2-0ubuntu1.1 (Ubuntu 8.10)
- libpango1.0-doc-1.22.2-0ubuntu1.1 (Ubuntu 8.10)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:M/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2009-1194");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "8.10", pkgname: "libpango1.0-0", pkgver: "1.22.2-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpango1.0-0-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpango1.0-0-1.22.2-0ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpango1.0-0-dbg", pkgver: "1.22.2-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpango1.0-0-dbg-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpango1.0-0-dbg-1.22.2-0ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpango1.0-common", pkgver: "1.22.2-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpango1.0-common-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpango1.0-common-1.22.2-0ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpango1.0-dev", pkgver: "1.22.2-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpango1.0-dev-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpango1.0-dev-1.22.2-0ubuntu1.1
');
}
found = ubuntu_check(osver: "8.10", pkgname: "libpango1.0-doc", pkgver: "1.22.2-0ubuntu1.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libpango1.0-doc-',found,' is vulnerable in Ubuntu 8.10
Upgrade it to libpango1.0-doc-1.22.2-0ubuntu1.1
');
}

if (w) { security_warning(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
