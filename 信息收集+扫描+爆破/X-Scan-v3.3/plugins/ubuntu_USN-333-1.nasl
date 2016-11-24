# This script was automatically generated from the 333-1 Ubuntu Security Notice
# It is released under the Nessus Script Licence.
# Ubuntu Security Notices are (C) 2005 Canonical, Inc.
# USN2nasl Convertor is (C) 2005 Tenable Network Security, Inc.
# See http://www.ubuntulinux.org/usn/
# Ubuntu(R) is a registered trademark of Canonical, Inc.

if (! defined_func("bn_random")) exit(0);
include('compat.inc');

if (description) {
script_id(27912);
script_version("$Revision: 1.3 $");
script_copyright("Ubuntu Security Notice (C) 2009 Canonical, Inc. / NASL script (C) 2009 Tenable Network Security, Inc.");
script_category(ACT_GATHER_INFO);
script_family(english: "Ubuntu Local Security Checks");
script_dependencies("ssh_get_info.nasl");
script_require_keys("Host/Ubuntu", "Host/Ubuntu/release", "Host/Debian/dpkg-l");

script_xref(name: "USN", value: "333-1");
script_summary(english:"libwmf vulnerability");
script_name(english:"USN333-1 : libwmf vulnerability");
script_set_attribute(attribute:'synopsis', value: 'These remote packages are missing security patches :
- libwmf-bin 
- libwmf-dev 
- libwmf-doc 
- libwmf0.2-7 
');
script_set_attribute(attribute:'description', value: 'An integer overflow was found in the handling of the MaxRecordSize
field in the WMF header parser. By tricking a user into opening a
specially crafted WMF image file with an application that uses this
library, an attacker could exploit this to execute arbitrary code with
the user\'s privileges.');
script_set_attribute(attribute:'solution', value: 'Upgrade to : 
- libwmf-bin-0.2.8.3-3.1ubuntu0.1 (Ubuntu 6.06)
- libwmf-dev-0.2.8.3-3.1ubuntu0.1 (Ubuntu 6.06)
- libwmf-doc-0.2.8.3-3.1ubuntu0.1 (Ubuntu 6.06)
- libwmf0.2-7-0.2.8.3-3.1ubuntu0.1 (Ubuntu 6.06)
');
script_set_attribute(attribute: 'cvss_vector', value: 'CVSS2#AV:N/AC:L/Au:N/C:P/I:P/A:P');
script_end_attributes();

script_cve_id("CVE-2006-3376");
exit(0);
}

include('ubuntu.inc');

if ( ! get_kb_item('Host/Ubuntu/release') ) exit(1, 'Could not gather the list of packages');

extrarep = NULL;

found = ubuntu_check(osver: "6.06", pkgname: "libwmf-bin", pkgver: "0.2.8.3-3.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwmf-bin-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libwmf-bin-0.2.8.3-3.1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libwmf-dev", pkgver: "0.2.8.3-3.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwmf-dev-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libwmf-dev-0.2.8.3-3.1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libwmf-doc", pkgver: "0.2.8.3-3.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwmf-doc-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libwmf-doc-0.2.8.3-3.1ubuntu0.1
');
}
found = ubuntu_check(osver: "6.06", pkgname: "libwmf0.2-7", pkgver: "0.2.8.3-3.1ubuntu0.1");
if (! isnull(found)) {
w++;
extrarep = strcat(extrarep, '
The package libwmf0.2-7-',found,' is vulnerable in Ubuntu 6.06
Upgrade it to libwmf0.2-7-0.2.8.3-3.1ubuntu0.1
');
}

if (w) { security_hole(port: 0, extra: extrarep); }
else exit(0, "Host is not vulnerable");
