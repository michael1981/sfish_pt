# This script was automatically generated from the 515-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(28120);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "515-1");
script_summary(english:"t1lib vulnerability");
script_name(english:"USN515-1 : t1lib vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libt1-5 
- libt1-dev 
- libt1-doc 
- t1lib-bin 
');
script_set_attribute(attribute:'description', value: 'It was discovered that t1lib does not properly perform bounds checking
which can result in a buffer overflow vulnerability.  An attacker could
send specially crafted input to applications linked against t1lib which
could result in a DoS or arbitrary code execution.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libt1-5-5.1.0-2ubuntu0.7.04.1 (Ubuntu 7.04)
- libt1-dev-5.1.0-2ubuntu0.7.04.1 (Ubuntu 7.04)
- libt1-doc-5.1.0-2ubuntu0.7.04.1 (Ubuntu 7.04)
- t1lib-bin-5.1.0-2ubuntu0.7.04.1 (Ubuntu 7.04)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2007-4033");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "7.04", pkgname: "libt1-5", pkgver: "5.1.0-2ubuntu0.7.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libt1-5-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libt1-5-5.1.0-2ubuntu0.7.04.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libt1-dev", pkgver: "5.1.0-2ubuntu0.7.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libt1-dev-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libt1-dev-5.1.0-2ubuntu0.7.04.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "libt1-doc", pkgver: "5.1.0-2ubuntu0.7.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libt1-doc-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to libt1-doc-5.1.0-2ubuntu0.7.04.1
');
}
found = ubuntu_check(osver: "7.04", pkgname: "t1lib-bin", pkgver: "5.1.0-2ubuntu0.7.04.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package t1lib-bin-',found,' is vulnerable in Ubuntu 7.04
Upgrade it to t1lib-bin-5.1.0-2ubuntu0.7.04.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
